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

// RebuildEncryptedCache builds a snapshot, encrypts it with AES-GCM, and seals
// the symmetric key with the recovery public key.
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
	return ec.WriteFile(cfg.cachePath())
}

// RunBootstrap initializes a brand-new Root CA (valid 10 years) and prints the
// 24-word recovery seed exactly once.
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
	for _, c := range cfg.Clients { // optional static seed list
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

// enforceLoopbackOnly is the HARD authorization rule for client-submitted CSRs:
// clients may ONLY obtain loopback certificates (localhost / 127.0.0.1 / ::1).
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

// checkEnrollment validates the shared enrollment token (constant-time). If no
// token is configured on the master, it logs a warning and allows the request
// to fall through to the network (CIDR) gate only.
func checkEnrollment(cfg *Config, r *http.Request) bool {
	if cfg.EnrollmentToken == "" {
		return true // no token configured -> rely on CIDR only (logged at startup)
	}
	got := r.Header.Get("X-Enrollment-Token")
	return subtle.ConstantTimeCompare([]byte(got), []byte(cfg.EnrollmentToken)) == 1
}

// RunMaster starts the master: ACME API on :443 and mTLS management on :8443.
func RunMaster(cfg *Config) error {
	ca, err := LoadCA(cfg.caCertPath(), cfg.caKeyPath())
	if err != nil {
		return fmt.Errorf("no Root CA (run --bootstrap): %w", err)
	}
	st, err := OpenStore(cfg.dbPath())
	if err != nil {
		return err
	}
	defer st.Close()

	// Merge any static clients from config into the DB on startup.
	for _, c := range cfg.Clients {
		st.AddClient(c)
	}

	log.Printf("master online | fingerprint %s", ca.Fingerprint())
	if len(cfg.ClientNetworks) > 0 {
		log.Printf("auto-registration enabled for networks: %s", strings.Join(cfg.ClientNetworks, ", "))
	} else {
		log.Printf("WARNING: client_networks is empty — clients cannot self-register")
	}
	if cfg.EnrollmentToken == "" {
		log.Printf("WARNING: enrollment_token not set — registration relies on source IP only (spoofable on flat L2)")
	} else {
		log.Printf("enrollment token required for registration (anti-spoofing enabled)")
	}

	// Port 443 — ACME-compatible issuance API.
	acmeMux := http.NewServeMux()
	acmeMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	acmeMux.HandleFunc("/ca", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, cfg.caCertPath())
	})
	acmeMux.HandleFunc("/cache", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, cfg.cachePath())
	})

	// Client self-registration. Authorization = enrollment token (anti-spoofing)
	// AND source-IP CIDR. Both must pass.
	acmeMux.HandleFunc("/acme/register", func(w http.ResponseWriter, r *http.Request) {
		ip := host(r.RemoteAddr)

		// 1. Enrollment token — defeats IP spoofing on flat L2 segments.
		if !checkEnrollment(cfg, r) {
			log.Printf("DENIED registration from %s (invalid/missing enrollment token)", ip)
			http.Error(w, "invalid or missing enrollment token", 403)
			return
		}
		// 2. Network gate.
		if !cfg.ClientAllowed(ip) {
			log.Printf("DENIED registration from %s (not in client_networks)", ip)
			http.Error(w, "your IP is not in any allowed client network", 403)
			return
		}
		newly := st.AddClient(ip)
		if newly {
			log.Printf("client registered: %s", ip)
		}
		json.NewEncoder(w).Encode(map[string]any{"status": "ok", "ip": ip, "new": newly})
	})

	// Issuance where the master generates the key (admin-style; returns key).
	acmeMux.HandleFunc("/acme/new-order", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Subject   string   `json:"subject"`
			SANs      []string `json:"sans"`
			ClientPub string   `json:"client_pub"`
			Localhost bool     `json:"localhost"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		res, err := ca.Issue(req.Subject, req.SANs, req.Localhost)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		rec := CertRecord{
			ID: res.Cert.SerialNumber.Text(16), Subject: req.Subject,
			SANs: strings.Join(req.SANs, ","), NotBefore: res.Cert.NotBefore,
			NotAfter: res.Cert.NotAfter, ClientPub: req.ClientPub,
			SerialHex: res.Cert.SerialNumber.Text(16), CertPEM: res.CertPEM,
		}
		st.AddCert(rec)
		RebuildEncryptedCache(cfg, ca, st)
		json.NewEncoder(w).Encode(map[string]string{
			"certificate": res.CertPEM, "private_key": res.KeyPEM,
		})
	})

	// CSR signing for clients. The leaf private key NEVER reaches the master.
	// HARD RULE: clients get loopback-only certificates.
	acmeMux.HandleFunc("/acme/sign-csr", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			CSR       string `json:"csr"`
			ClientPub string `json:"client_pub"`
			Localhost bool   `json:"localhost"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		block, _ := pem.Decode([]byte(req.CSR))
		if block == nil {
			http.Error(w, "bad CSR PEM", 400)
			return
		}
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		// ── HARD AUTHORIZATION: clients = loopback only ────────────────
		if err := enforceLoopbackOnly(csr, req.Localhost); err != nil {
			log.Printf("DENIED CSR from %s: %v", r.RemoteAddr, err)
			http.Error(w, err.Error(), 403)
			return
		}
		// ───────────────────────────────────────────────────────────────

		res, err := ca.SignCSR(csr, req.Localhost)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		subject := csr.Subject.CommonName
		rec := CertRecord{
			ID: res.Cert.SerialNumber.Text(16), Subject: subject,
			SANs:      strings.Join(append(res.Cert.DNSNames, ipsToStr(res.Cert.IPAddresses)...), ","),
			NotBefore: res.Cert.NotBefore, NotAfter: res.Cert.NotAfter,
			ClientPub: req.ClientPub, SerialHex: res.Cert.SerialNumber.Text(16),
			CertPEM: res.CertPEM,
		}
		st.AddCert(rec)
		RebuildEncryptedCache(cfg, ca, st)
		log.Printf("signed loopback CSR for %q (serial %s)", subject, rec.SerialHex)
		json.NewEncoder(w).Encode(map[string]string{"certificate": res.CertPEM})
	})

	// Periodic cache fan-out to all registered clients.
	go func() {
		t := time.NewTicker(cfg.PullInterval)
		defer t.Stop()
		for range t.C {
			pushCacheToClients(cfg, st)
		}
	}()

	go func() {
		srv := &http.Server{Addr: cfg.Listen.ACME, Handler: acmeMux}
		log.Printf("ACME API on %s", cfg.Listen.ACME)
		log.Fatal(srv.ListenAndServeTLS(cfg.caCertPath(), cfg.caKeyPath()))
	}()

	// Port 8443 — internal management/sync (mTLS).
	mgmtMux := http.NewServeMux()
	mgmtMux.HandleFunc("/sync/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	mgmtMux.HandleFunc("/sync/clients", func(w http.ResponseWriter, r *http.Request) {
		cls, _ := st.ListClients()
		json.NewEncoder(w).Encode(cls)
	})

	caPool := x509.NewCertPool()
	caPool.AddCert(ca.Cert)
	mgmtSrv := &http.Server{
		Addr:    cfg.Listen.Mgmt,
		Handler: mgmtMux,
		TLSConfig: &tls.Config{
			ClientAuth: tls.RequireAndVerifyClientCert, // mTLS
			ClientCAs:  caPool,
			MinVersion: tls.VersionTLS12,
		},
	}
	log.Printf("mTLS management on %s", cfg.Listen.Mgmt)
	return mgmtSrv.ListenAndServeTLS(cfg.caCertPath(), cfg.caKeyPath())
}

func pushCacheToClients(cfg *Config, st *Store) {
	cls, _ := st.ListClients()
	data, err := os.ReadFile(cfg.cachePath())
	if err != nil {
		return
	}
	// master -> client receiver uses an ephemeral self-signed cert; the payload
	// is already AES-GCM encrypted + sealed, so this direction is intentionally
	// not pinned in the OSS edition.
	client := insecureMasterClient()
	for _, c := range cls {
		url := fmt.Sprintf("https://%s:8443/cache/push", host(c))
		req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(string(data)))
		req.Header.Set("Content-Type", "application/octet-stream")
		if resp, err := client.Do(req); err == nil {
			resp.Body.Close()
			log.Printf("cache pushed to %s", c)
		}
	}
}
