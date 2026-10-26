package main

import (
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

func RebuildEncryptedCache(cfg *Config, ca *CA, st *Store) error {
	unlock, err := lockFile(cfg.cachePath() + ".lock")
	if err != nil {
		return err
	}
	defer unlock()
	pub, err := RecoveryPublicFromBase64(cfg.RecoveryPublicKey)
	if err != nil {
		return err
	}
	snap, err := st.BuildSnapshot(ca)
	if err != nil {
		return err
	}
	if previous, err := ReadEncryptedCache(cfg.cachePath()); err == nil && previous.Verify(ca.Cert) == nil {
		if _, err := st.db.Exec(`UPDATE state SET value=MAX(value,?) WHERE key='cache_sequence'`, previous.Sequence); err != nil {
			return err
		}
	}
	seq, err := st.nextCacheSequence()
	if err != nil {
		return err
	}
	snap.Sequence = seq
	snap.EnrollmentToken = cfg.EnrollmentToken
	snap.ClientNetworks = cfg.ClientNetworks
	raw, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	ec, err := EncryptCache(raw, pub)
	if err != nil {
		return err
	}
	ec.Sequence = seq
	if err := ec.Sign(ca); err != nil {
		return err
	}
	return ec.WriteFile(cfg.cachePath())
}

// RunBootstrap initializes a brand-new Root CA (valid 10 years) and prints the
// 24-word recovery seed exactly once.
func RunBootstrap(cfg *Config) error {
	if clientOnly {
		return fmt.Errorf("client-only build: bootstrap is disabled")
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return err
	}
	unlock, err := lockFile(cfg.caKeyPath() + ".bootstrap.lock")
	if err != nil {
		return err
	}
	defer unlock()
	if _, err := os.Stat(cfg.caKeyPath()); err == nil {
		return fmt.Errorf("Root CA key already exists — refusing to overwrite")
	} else if !os.IsNotExist(err) {
		return err
	}
	if _, err := os.Stat(cfg.caCertPath()); err == nil {
		return fmt.Errorf("Root CA already exists at %s — refusing to overwrite", cfg.caCertPath())
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
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
	for _, c := range cfg.Clients {
		st.AddClient(c)
	}
	if err := WriteCRL(cfg, ca, st); err != nil {
		return err
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
	fmt.Println("   " + mnemonic)
	fmt.Println("============================================================")
	return nil
}

// enforceLoopbackOnly is the HARD authorization rule for client-submitted CSRs.
func enforceLoopbackOnly(csr *x509.CertificateRequest, localhost bool) error {
	if csr.Subject.CommonName != "" && !isLoopbackTarget(csr.Subject.CommonName) {
		return fmt.Errorf("only loopback common names are allowed")
	}
	if len(csr.EmailAddresses) > 0 || len(csr.URIs) > 0 {
		return fmt.Errorf("only loopback DNS/IP SANs are allowed")
	}
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

func checkEnrollment(cfg *Config, r *http.Request) bool {
	return cfg.EnrollmentToken != "REPLACE_ME" && cfg.EnrollmentToken != "" && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Enrollment-Token")), []byte(cfg.EnrollmentToken)) == 1
}

func requireMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method != method {
		w.Header().Set("Allow", method)
		http.Error(w, "method not allowed", 405)
		return false
	}
	return true
}

func decodeRequest(w http.ResponseWriter, r *http.Request, out any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	dec := json.NewDecoder(r.Body)
	err := dec.Decode(out)
	if err == nil {
		var extra any
		if e := dec.Decode(&extra); e != io.EOF {
			err = fmt.Errorf("expected a single JSON object")
		}
	}
	if err != nil {
		status := http.StatusBadRequest
		if _, ok := err.(*http.MaxBytesError); ok {
			status = http.StatusRequestEntityTooLarge
		}
		http.Error(w, err.Error(), status)
		return false
	}
	return true
}

func certRecord(cert *x509.Certificate, certPEM string) CertRecord {
	serial := cert.SerialNumber.Text(16)
	return CertRecord{ID: serial, SerialHex: serial, Subject: cert.Subject.CommonName, SANs: strings.Join(append(cert.DNSNames, ipsToStr(cert.IPAddresses)...), ","), NotBefore: cert.NotBefore, NotAfter: cert.NotAfter, CertPEM: certPEM}
}

// Separate routers prevent public issuance or unauthenticated snapshot access.
func masterHandlers(cfg *Config, ca *CA, st *Store) (http.Handler, http.Handler) {
	bootstrap, control := http.NewServeMux(), http.NewServeMux()
	bootstrap.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if requireMethod(w, r, "GET") {
			io.WriteString(w, "ok")
		}
	})
	bootstrap.HandleFunc("/ca", func(w http.ResponseWriter, r *http.Request) {
		if requireMethod(w, r, "GET") {
			w.Header().Set("Content-Type", "application/x-pem-file")
			w.Write(ca.certPEMBytes())
		}
	})
	bootstrap.HandleFunc("/acme/register", func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, "POST") {
			return
		}
		ip := host(r.RemoteAddr)
		blocked, err := st.IsBlocked(ip)
		if err != nil {
			http.Error(w, "database unavailable", 500)
			return
		}
		if blocked || !checkEnrollment(cfg, r) || !cfg.ClientAllowed(ip) {
			log.Printf("AUDIT enrollment denied ip=%s", ip)
			http.Error(w, "enrollment denied: token, network or blacklist", 403)
			return
		}
		var req struct {
			CSR string `json:"csr"`
		}
		if !decodeRequest(w, r, &req) {
			return
		}
		var certPEM string
		if req.CSR != "" {
			b, _ := pem.Decode([]byte(req.CSR))
			if b == nil || b.Type != "CERTIFICATE REQUEST" {
				http.Error(w, "bad CSR PEM", 400)
				return
			}
			csr, err := x509.ParseCertificateRequest(b.Bytes)
			if err != nil || csr.CheckSignature() != nil {
				http.Error(w, "invalid CSR", 400)
				return
			}
			certPEM, err = ca.IssueClientCert(csr, identityPrefix+ip)
			if err != nil {
				http.Error(w, "cannot issue client identity", 500)
				return
			}
			b, _ = pem.Decode([]byte(certPEM))
			cert, err := x509.ParseCertificate(b.Bytes)
			if err != nil {
				http.Error(w, "invalid identity", 500)
				return
			}
			if err := st.AddCert(certRecord(cert, certPEM)); err != nil {
				http.Error(w, "cannot save identity", 500)
				return
			}
		}
		if _, err := st.registerClient(ip); err != nil {
			http.Error(w, "cannot register client", 500)
			return
		}
		if err := RebuildEncryptedCache(cfg, ca, st); err != nil {
			http.Error(w, "cannot rebuild cache", 500)
			return
		}
		log.Printf("AUDIT client %s enrolled", ip)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "ip": ip, "certificate": certPEM})
	})
	control.HandleFunc("/sync/health", func(w http.ResponseWriter, r *http.Request) {
		if requireMethod(w, r, "GET") {
			io.WriteString(w, "ok")
		}
	})
	control.HandleFunc("/sync/cache", func(w http.ResponseWriter, r *http.Request) {
		if requireMethod(w, r, "GET") {
			w.Header().Set("Content-Type", "application/json")
			http.ServeFile(w, r, cfg.cachePath())
		}
	})
	control.HandleFunc("/sync/crl", func(w http.ResponseWriter, r *http.Request) {
		if requireMethod(w, r, "GET") {
			if err := refreshCRL(cfg, ca, st); err != nil {
				http.Error(w, "cannot refresh CRL", 500)
				return
			}
			w.Header().Set("Content-Type", "application/pkix-crl")
			http.ServeFile(w, r, cfg.crlPath())
		}
	})
	control.HandleFunc("/acme/sign-csr", func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, "POST") {
			return
		}
		var req struct {
			CSR       string `json:"csr"`
			Localhost bool   `json:"localhost"`
		}
		if !decodeRequest(w, r, &req) {
			return
		}
		b, _ := pem.Decode([]byte(req.CSR))
		if b == nil || b.Type != "CERTIFICATE REQUEST" {
			http.Error(w, "bad CSR PEM", 400)
			return
		}
		csr, err := x509.ParseCertificateRequest(b.Bytes)
		if err != nil || csr.CheckSignature() != nil {
			http.Error(w, "invalid CSR", 400)
			return
		}
		if err := enforceLoopbackOnly(csr, req.Localhost); err != nil {
			log.Printf("AUDIT CSR denied ip=%s", host(r.RemoteAddr))
			http.Error(w, err.Error(), 403)
			return
		}
		res, err := ca.SignCSR(csr, true)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if err := st.AddCert(certRecord(res.Cert, res.CertPEM)); err != nil {
			http.Error(w, "cannot save certificate", 500)
			return
		}
		if err := RebuildEncryptedCache(cfg, ca, st); err != nil {
			http.Error(w, "cannot rebuild cache", 500)
			return
		}
		log.Printf("AUDIT signed loopback CSR ip=%s serial=%s", host(r.RemoteAddr), res.Cert.SerialNumber.Text(16))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"certificate": res.CertPEM})
	})
	return bootstrap, authorizeClient(st, control)
}

func authorizeClient(st *Store, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "client identity required", 403)
			return
		}
		cert := r.TLS.PeerCertificates[0]
		ip := strings.TrimPrefix(cert.Subject.CommonName, identityPrefix)
		if ip == cert.Subject.CommonName || net.ParseIP(ip) == nil {
			http.Error(w, "enrollment identity required", 403)
			return
		}
		blocked, err := st.IsBlocked(ip)
		if err != nil {
			http.Error(w, "database unavailable", 500)
			return
		}
		revoked, err := st.IsRevoked(cert.SerialNumber.Text(16))
		if err != nil {
			http.Error(w, "database unavailable", 500)
			return
		}
		rec, found, err := st.CertBySerial(cert.SerialNumber.Text(16))
		if err != nil {
			http.Error(w, "database unavailable", 500)
			return
		}
		registered, err := st.hasClient(ip)
		if err != nil {
			http.Error(w, "database unavailable", 500)
			return
		}
		if blocked || revoked || !registered || !found || rec.Subject != cert.Subject.CommonName || rec.CertPEM != string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})) {
			http.Error(w, "client is blocked, revoked or not registered", 403)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func newHTTPServer(addr string, handler http.Handler, tlsCfg *tls.Config) *http.Server {
	return &http.Server{Addr: addr, Handler: handler, TLSConfig: tlsCfg, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32 << 10}
}

func RunMaster(cfg *Config) error {
	if clientOnly {
		return fmt.Errorf("client-only build: master mode is disabled")
	}
	if len(cfg.ClientNetworks) > 0 && (cfg.EnrollmentToken == "" || cfg.EnrollmentToken == "REPLACE_ME") {
		return fmt.Errorf("enrollment_token is required when client_networks is set")
	}
	ca, err := LoadCA(cfg.caCertPath(), cfg.caKeyPath())
	if err != nil {
		return fmt.Errorf("no Root CA (run --bootstrap): %w", err)
	}
	st, err := OpenStore(cfg.dbPath())
	if err != nil {
		return err
	}
	defer st.Close()
	if err := WriteCRL(cfg, ca, st); err != nil {
		return err
	}
	if err := RebuildEncryptedCache(cfg, ca, st); err != nil {
		return err
	}
	hosts := append([]string{"localhost", host(cfg.Listen.ACME), host(cfg.Listen.Mgmt)}, cfg.ServerNames...)
	if name, err := os.Hostname(); err == nil {
		hosts = append(hosts, name)
	}
	if ips, err := localIPv4s(); err == nil {
		hosts = append(hosts, ips...)
	}
	chain, key, err := ca.IssueServerCert(hosts)
	if err != nil {
		return err
	}
	pair, err := tls.X509KeyPair(chain, key)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	public, control := masterHandlers(cfg, ca, st)
	api := newHTTPServer(cfg.Listen.ACME, public, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}})
	mgmt := newHTTPServer(cfg.Listen.Mgmt, control, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots})
	a, err := net.Listen("tcp", api.Addr)
	if err != nil {
		return err
	}
	defer a.Close()
	m, err := net.Listen("tcp", mgmt.Addr)
	if err != nil {
		return err
	}
	defer m.Close()
	defer api.Close()
	defer mgmt.Close()
	errs := make(chan error, 2)
	go func() { errs <- api.Serve(tls.NewListener(a, api.TLSConfig)) }()
	go func() { errs <- mgmt.Serve(tls.NewListener(m, mgmt.TLSConfig)) }()
	log.Printf("master online | API %s | mTLS %s | fingerprint %s", api.Addr, mgmt.Addr, ca.Fingerprint())
	return <-errs
}
