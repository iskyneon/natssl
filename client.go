package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// RunClient boots the client: install the Root CA (pinned), enroll for an mTLS
// identity, accept signed migration packets on :8443, and pull the encrypted
// cache over mTLS. There is NO inbound cache-push surface.
func RunClient(cfg *Config) error {
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return err
	}
	if cfg.MasterAddress == "" {
		return fmt.Errorf("master_address is required in client mode")
	}
	if cfg.EnrollmentToken == "" {
		return fmt.Errorf("enrollment_token is required in client mode")
	}
	if cfg.MasterFingerprint == "" {
		log.Printf("WARNING: master_fingerprint not set — the bootstrap /ca fetch cannot be " +
			"pinned to a known root; set it from the master bootstrap output")
	}

	log.Printf("client starting | master=%s", cfg.MasterAddress)

	if err := fetchAndInstallRootCA(cfg); err != nil {
		log.Printf("WARNING: could not install Root CA yet: %v (will retry on pull)", err)
	}
	if err := ensureClientIdentity(cfg); err != nil {
		log.Printf("WARNING: enrollment incomplete: %v (will retry)", err)
	}

	StartRegistrationLoop(cfg) // periodic liveness re-announce
	go runMigrationReceiver(cfg)
	go runPullLoop(cfg)

	select {}
}

func fetchAndInstallRootCA(cfg *Config) error {
	url := fmt.Sprintf("https://%s:443/ca", host(cfg.MasterAddress))
	resp, err := pinnedMasterClient(cfg).Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("master returned %d for /ca", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return err
	}
	if err := writeFileAtomic(cfg.caCertPath(), data, 0o644); err != nil {
		return err
	}
	if err := InstallRootCAIntoOS(cfg.caCertPath()); err != nil {
		log.Printf("OS trust store: %v", err)
	}
	if err := InstallRootCAIntoFirefox(cfg.caCertPath()); err != nil {
		log.Printf("Firefox trust store: %v", err)
	}
	log.Printf("Root CA installed from master (%d bytes)", len(data))
	return nil
}

// ensureClientIdentity enrolls (token + CIDR on master) and stores the returned
// client-auth certificate, giving this client an mTLS identity. Idempotent.
func ensureClientIdentity(cfg *Config) error {
	if _, err := os.Stat(cfg.clientCertPath()); err == nil {
		if _, e := os.Stat(cfg.clientKeyPath()); e == nil {
			return nil
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "natssl-client"}}, key)
	if err != nil {
		return err
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	body, _ := json.Marshal(map[string]string{"csr": string(csrPEM)})
	req, err := buildRegisterRequest(cfg, body)
	if err != nil {
		return err
	}
	resp, err := pinnedMasterClient(cfg).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if resp.StatusCode != 200 {
		return fmt.Errorf("enroll rejected (%d): %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out struct {
		ClientCertificate string `json:"client_certificate"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return err
	}
	if out.ClientCertificate == "" {
		return fmt.Errorf("master returned no client certificate")
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := writeFileAtomic(cfg.clientKeyPath(), keyPEM, 0o600); err != nil {
		return err
	}
	if err := writeFileAtomic(cfg.clientCertPath(), []byte(out.ClientCertificate), 0o644); err != nil {
		return err
	}
	log.Printf("client mTLS identity stored")
	return nil
}

// runMigrationReceiver serves :8443 to accept signed disaster-recovery
// migration packets. The payload is verified against the Root CA public key.
func runMigrationReceiver(cfg *Config) {
	cert, err := ephemeralSelfSigned()
	if err != nil {
		log.Fatalf("migration receiver: cannot create ephemeral cert: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/cache/health", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("/migrate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		var pkt MigrationPacket
		if err := json.NewDecoder(r.Body).Decode(&pkt); err != nil {
			http.Error(w, "bad packet", http.StatusBadRequest)
			return
		}
		if err := verifyMigrationSig(cfg, &pkt); err != nil {
			log.Printf("AUDIT DENIED migration packet: %v", err)
			http.Error(w, "invalid signature", http.StatusForbidden)
			return
		}
		newIP := host(pkt.NewMasterIP)
		if newIP == "" {
			http.Error(w, "empty new master IP", http.StatusBadRequest)
			return
		}
		cfg.MasterAddress = newIP
		if err := cfg.Save(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("AUDIT migration accepted: new master = %s", newIP)
		w.Write([]byte("ok"))
	})

	srv := &http.Server{
		Addr:              cfg.Listen.Mgmt,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
	}
	log.Printf("migration receiver on %s", cfg.Listen.Mgmt)
	if err := srv.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("migration receiver failed: %v", err)
	}
}

// runPullLoop pulls the encrypted cache + CRL over mTLS, rejecting stale or
// replayed versions via the monotonic X-Cache-Version header.
func runPullLoop(cfg *Config) {
	pull := func() {
		if _, err := os.Stat(cfg.caCertPath()); err != nil {
			if e := fetchAndInstallRootCA(cfg); e != nil {
				log.Printf("pull: Root CA refresh failed: %v", e)
			}
		}
		if _, err := os.Stat(cfg.clientCertPath()); err != nil {
			if e := ensureClientIdentity(cfg); e != nil {
				log.Printf("pull: no mTLS identity yet: %v", e)
				return
			}
		}
		client, err := mtlsClient(cfg)
		if err != nil {
			log.Printf("pull: %v", err)
			return
		}
		url := fmt.Sprintf("https://%s:8443/sync/cache", host(cfg.MasterAddress))
		resp, err := client.Get(url)
		if err != nil {
			log.Printf("pull: master unreachable (READ-ONLY): %v", err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			log.Printf("pull: master returned %d", resp.StatusCode)
			return
		}
		newVer, _ := strconv.ParseInt(strings.TrimSpace(resp.Header.Get("X-Cache-Version")), 10, 64)
		if cur := readLocalCacheVersion(cfg); newVer != 0 && newVer < cur {
			log.Printf("pull: rejecting stale cache v%d (have v%d)", newVer, cur)
			return
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		if err != nil {
			return
		}
		if err := writeFileAtomic(cfg.cachePath(), data, 0o600); err != nil {
			log.Printf("pull: cannot write cache: %v", err)
			return
		}
		if newVer != 0 {
			writeFileAtomic(cfg.cacheVersionPath(), []byte(strconv.FormatInt(newVer, 10)), 0o644)
		}
		log.Printf("cache pulled (v%d, %d bytes)", newVer, len(data))
		fetchCRL(cfg, client)
	}
	pull()
	t := time.NewTicker(cfg.PullInterval)
	defer t.Stop()
	for range t.C {
		pull()
	}
}

func fetchCRL(cfg *Config, client *http.Client) {
	url := fmt.Sprintf("https://%s:8443/sync/crl", host(cfg.MasterAddress))
	resp, err := client.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return
	}
	if err := writeFileAtomic(cfg.crlPath(), data, 0o644); err == nil {
		log.Printf("revocation list updated")
	}
}

func readLocalCacheVersion(cfg *Config) int64 {
	b, err := os.ReadFile(cfg.cacheVersionPath())
	if err != nil {
		return 0
	}
	v, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	return v
}

// ephemeralSelfSigned creates a short-lived self-signed cert for the :8443
// migration receiver. It is not part of the PKI trust chain.
func ephemeralSelfSigned() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "natssl-client-receiver"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}
