package main

import (
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

const maxBody = 1 << 20 // 1 MiB cap on request bodies

// RebuildEncryptedCache builds a snapshot, encrypts it (AES-GCM, key sealed
// with the recovery public key) and writes it + a monotonic version manifest
// atomically.
func RebuildEncryptedCache(cfg *Config, ca *CA, st *Store) error {
	pub, err := RecoveryPublicFromBase64(cfg.RecoveryPublicKey)
	if err != nil {
		return err
	}
	snap, err := st.BuildSnapshot(ca)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	ec, err := EncryptCache(raw, pub)
	if err != nil {
		return err
	}
	b, err := json.Marshal(ec)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(cfg.cachePath(), b, 0o600); err != nil {
		return err
	}
	return writeFileAtomic(cfg.cacheVersionPath(),
		[]byte(fmt.Sprintf("%d", snap.Version)), 0o644)
}

// ensureServerCert makes sure a dedicated SERVER leaf exists (issued by the CA)
// so the TLS listeners never use the Root CA key directly.
func ensureServerCert(cfg *Config, ca *CA) error {
	if _, err := os.Stat(cfg.serverCertPath()); err == nil {
		if _, e := tls.LoadX509KeyPair(cfg.serverCertPath(), cfg.serverKeyPath()); e == nil {
			return nil
		}
	}
	chainPEM, keyPEM, err := ca.IssueServerCert([]string{host(cfg.MasterAddress), "localhost"})
	if err != nil {
		return err
	}
	if err := writeFileAtomic(cfg.serverCertPath(), chainPEM, 0o644); err != nil {
		return err
	}
	return writeFileAtomic(cfg.serverKeyPath(), keyPEM, 0o600)
}

func RunBootstrap(cfg *Config) error {
	if _, err := os.Stat(cfg.caCertPath()); err == nil {
		return fmt.Errorf("Root CA already exists at %s — refusing to overwrite", cfg.caCertPath())
	}
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return err
	}
	ca, err := BootstrapCA()
	if err != nil {
		return err
	}
	if err := ca.SaveToFiles(cfg.caCertPath(), cfg.caKeyPath()); err != nil {
		return err
	}
	if err := ensureServerCert(cfg, ca); err != nil {
		return err
	}
	rk, mnemonic, err := GenerateRecovery()
	if err != nil {
		return err
	}
	cfg.Mode = "master"
	cfg.RecoveryPublicKey = rk.PublicBase64()
	if err := cfg.Save(); err != nil {
		return err
	}
	st, err := OpenStore(cfg.dbPath())
	if err != nil {
		return err
	}
	defer st.Close()
	for _, c := range cfg.Clients {
		st.AddClient(c)
	}
	if err := RebuildEncryptedCache(cfg, ca, st); err != nil {
		return err
	}

	fmt.Println("============================================================")
	fmt.Println(" NATSSL Root CA initialized (valid 10 years).")
	fmt.Println(" SHA-256 fingerprint (copy to clients as master_fingerprint):")
	fmt.Println("   " + ca.Fingerprint())
	fmt.Println("------------------------------------------------------------")
	fmt.Println(" DISASTER RECOVERY SEED PHRASE (24 words) — SHOWN ONCE.")
	fmt.Println(" Write it down OFFLINE. It is NOT stored on disk.")
	fmt.Println("------------------------------------------------------------")
	fmt.Println(" " + mnemonic)
	fmt.Println("============================================================")
	return nil
}

func enforceLoopbackOnly(csr *x509.CertificateRequest, localhost bool) error {
	if !localhost {
		return fmt.Errorf("clients may only request localhost certificates " +
			"(use --localhost); domain/IP issuance is reserved for the administrator on the master")
	}
	for _, d := range csr.DNSNames {
		if d != "localhost" {
			return fmt.Errorf("clients may only request 'localhost', got DNS SAN %q", d)
		}
	}
	for _, ip := range csr.IPAddresses {
		if !ip.IsLoopback() {
			return fmt.Errorf("clients may only request loopback IPs (127.0.0.1/::1), got %s", ip)
		}
	}
	if len(csr.DNSNames) == 0 && len(csr.IPAddresses) == 0 {
		return fmt.Errorf("CSR has no loopback SAN")
	}
	return nil
}

// checkEnrollment validates the shared enrollment token in constant time.
// LoadConfig guarantees the token is non-empty whenever registration is on.
func checkEnrollment(cfg *Config, r *http.Request) bool {
	got := r.Header.Get("X-Enrollment-Token")
	return subtle.ConstantTimeCompare([]byte(got), []byte(cfg.EnrollmentToken)) == 1
}

// methodGuard enforces the HTTP method and caps the request body.
func methodGuard(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method != method {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	return true
}

func RunMaster(cfg *Config) error {
	ca, err := LoadCA(cfg.caCertPath(), cfg.caKeyPath())
	if err != nil {
		return fmt.Errorf("no Root CA (run --bootstrap): %w", err)
	}
	if err := ensureServerCert(cfg, ca); err != nil {
		return fmt.Errorf("server cert: %w", err)
	}
	st, err := OpenStore(cfg.dbPath())
	if err != nil {
		return err
	}
	defer st.Close()
	for _, c := range cfg.Clients {
		st.AddClient(c)
	}

	log.Printf("master online | fingerprint %s", ca.Fingerprint())
	if len(cfg.ClientNetworks) > 0 {
		log.Printf("auto-registration enabled for: %s (enrollment token REQUIRED)",
			strings.Join(cfg.ClientNetworks, ", "))
	} else {
		log.Printf("WARNING: client_networks is empty — clients cannot self-register")
	}

	caPool := x509.NewCertPool()
	caPool.AddCert(ca.Cert)

	// ── :443 bootstrap API (no client cert yet; clients pin this) ──────────
	acme := http.NewServeMux()
	acme.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	acme.HandleFunc("/ca", func(w http.ResponseWriter, r *http.Request) {
		if !methodGuard(w, r, http.MethodGet) {
			return
		}
		http.ServeFile(w, r, cfg.caCertPath())
	})

	// Enrollment: token + CIDR gates, then (if a CSR is supplied) issue the
	// client's mTLS identity certificate.
	acme.HandleFunc("/acme/register", func(w http.ResponseWriter, r *http.Request) {
		if !methodGuard(w, r, http.MethodPost) {
			return
		}
		ip := host(r.RemoteAddr)
		if !checkEnrollment(cfg, r) {
			log.Printf("AUDIT DENIED registration from %s (invalid/missing enrollment token)", ip)
			http.Error(w, "invalid or missing enrollment token", http.StatusForbidden)
			return
		}
		if !cfg.ClientAllowed(ip) {
			log.Printf("AUDIT DENIED registration from %s (not in client_networks)", ip)
			http.Error(w, "your IP is not in any allowed client network", http.StatusForbidden)
			return
		}
		var req struct {
			CSR string `json:"csr"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)

		newly := st.AddClient(ip)
		resp := map[string]any{"status": "ok", "ip": ip, "new": newly}

		if strings.TrimSpace(req.CSR) != "" {
			block, _ := pem.Decode([]byte(req.CSR))
			if block == nil {
				http.Error(w, "bad CSR PEM", http.StatusBadRequest)
				return
			}
			csr, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			clientCertPEM, err := ca.IssueClientCert(csr, "client:"+ip)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			resp["client_certificate"] = clientCertPEM
			log.Printf("AUDIT client %s enrolled (issued mTLS identity)", ip)
		} else if newly {
			log.Printf("AUDIT client registered: %s", ip)
		}
		json.NewEncoder(w).Encode(resp)
	})

	go func() {
		srv := &http.Server{
			Addr:              cfg.Listen.ACME,
			Handler:           acme,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
		}
		log.Printf("bootstrap API on %s (server leaf, NOT the CA key)", cfg.Listen.ACME)
		log.Fatal(srv.ListenAndServeTLS(cfg.serverCertPath(), cfg.serverKeyPath()))
	}()

	// ── :8443 mTLS control plane (RequireAndVerifyClientCert) ──────────────
	mgmt := http.NewServeMux()
	mgmt.HandleFunc("/sync/health", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })

	mgmt.HandleFunc("/sync/clients", func(w http.ResponseWriter, r *http.Request) {
		if !methodGuard(w, r, http.MethodGet) {
			return
		}
		cls, _ := st.ListClients()
		json.NewEncoder(w).Encode(cls)
	})

	mgmt.HandleFunc("/sync/cache", func(w http.ResponseWriter, r *http.Request) {
		if !methodGuard(w, r, http.MethodGet) {
			return
		}
		if v, err := os.ReadFile(cfg.cacheVersionPath()); err == nil {
			w.Header().Set("X-Cache-Version", strings.TrimSpace(string(v)))
		}
		http.ServeFile(w, r, cfg.cachePath())
	})

	mgmt.HandleFunc("/sync/crl", func(w http.ResponseWriter, r *http.Request) {
		if !methodGuard(w, r, http.MethodGet) {
			return
		}
		revoked, _ := st.ListRevoked()
		if revoked == nil {
			revoked = []string{}
		}
		json.NewEncoder(w).Encode(map[string]any{
			"revoked":   revoked,
			"issued_at": time.Now().UTC(),
		})
	})

	// CSR signing over mTLS — the caller identity is authenticated.
	mgmt.HandleFunc("/acme/sign-csr", func(w http.ResponseWriter, r *http.Request) {
		if !methodGuard(w, r, http.MethodPost) {
			return
		}
		peer := "unknown"
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			peer = r.TLS.PeerCertificates[0].Subject.CommonName
		}
		var req struct {
			CSR       string `json:"csr"`
			ClientPub string `json:"client_pub"`
			Localhost bool   `json:"localhost"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		block, _ := pem.Decode([]byte(req.CSR))
		if block == nil {
			http.Error(w, "bad CSR PEM", http.StatusBadRequest)
			return
		}
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := enforceLoopbackOnly(csr, req.Localhost); err != nil {
			log.Printf("AUDIT DENIED CSR from %q: %v", peer, err)
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		res, err := ca.SignCSR(csr, req.Localhost)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		rec := CertRecord{
			ID:        res.Cert.SerialNumber.Text(16),
			Subject:   csr.Subject.CommonName,
			SANs:      strings.Join(append(res.Cert.DNSNames, ipsToStr(res.Cert.IPAddresses)...), ","),
			NotBefore: res.Cert.NotBefore,
			NotAfter:  res.Cert.NotAfter,
			ClientPub: req.ClientPub,
			SerialHex: res.Cert.SerialNumber.Text(16),
			CertPEM:   res.CertPEM,
		}
		if err := st.AddCert(rec); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if err := RebuildEncryptedCache(cfg, ca, st); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("AUDIT signed loopback CSR for %q by mTLS peer %q (serial %s)",
			rec.Subject, peer, rec.SerialHex)
		json.NewEncoder(w).Encode(map[string]string{"certificate": res.CertPEM})
	})

	mgmtSrv := &http.Server{
		Addr:              cfg.Listen.Mgmt,
		Handler:           mgmt,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		TLSConfig: &tls.Config{
			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs:  caPool,
			MinVersion: tls.VersionTLS12,
		},
	}
	log.Printf("mTLS control plane on %s (pull-only, no push)", cfg.Listen.Mgmt)
	return mgmtSrv.ListenAndServeTLS(cfg.serverCertPath(), cfg.serverKeyPath())
}
