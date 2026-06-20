package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"
)

// RunClient boots the client: refresh + install the Root CA, self-register with
// the master, accept replicated cache + CRL pushes on :8443, and periodically
// pull the cache. New certificate issuance is handled separately
// (RunClientIssue) and is loopback-only.
func RunClient(cfg *Config) error {
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return err
	}
	if cfg.MasterAddress == "" {
		return fmt.Errorf("master_address is required in client mode")
	}
	if cfg.MasterFingerprint == "" {
		log.Printf("WARNING: master_fingerprint not set — the first /ca fetch cannot be pinned; " +
			"set it from the master bootstrap output for full protection")
	}

	log.Printf("client starting | master=%s", cfg.MasterAddress)

	if err := fetchAndInstallRootCA(cfg); err != nil {
		log.Printf("WARNING: could not install Root CA yet: %v (will retry on pull)", err)
	}

	StartRegistrationLoop(cfg)
	go runCacheReceiver(cfg)
	go runPullLoop(cfg)

	select {}
}

// fetchAndInstallRootCA downloads the Root CA from the master over a pinned
// connection and installs it into the OS + Firefox trust stores.
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
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if err := os.WriteFile(cfg.caCertPath(), data, 0o644); err != nil {
		return err
	}

	// InstallRootCA writes the OS anchor, runs update-ca-certificates /
	// update-ca-trust, AND installs into every Firefox profile via certutil.
	if err := InstallRootCA(data); err != nil {
		log.Printf("trust store: %v", err)
	}
	log.Printf("Root CA installed from master (%d bytes)", len(data))
	return nil
}

// runCacheReceiver serves :8443 to accept replicated cache + CRL pushes.
func runCacheReceiver(cfg *Config) {
	cert, err := ephemeralSelfSigned()
	if err != nil {
		log.Fatalf("cache receiver: cannot create ephemeral cert: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/cache/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/cache/push", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		data, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if err := os.WriteFile(cfg.cachePath(), data, 0o600); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		log.Printf("cache received from master (%d bytes)", len(data))
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/crl/push", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		data, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if err := os.WriteFile(cfg.crlPath(), data, 0o644); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		log.Printf("CRL received from master (%d bytes)", len(data))
		w.Write([]byte("ok"))
	})

	srv := &http.Server{
		Addr:    cfg.Listen.Mgmt, // :8443
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
	}
	log.Printf("cache receiver on %s", cfg.Listen.Mgmt)
	if err := srv.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("cache receiver failed: %v", err)
	}
}

// runPullLoop periodically pulls the encrypted cache + CRL from the master
// (pinned) and refreshes the Root CA.
func runPullLoop(cfg *Config) {
	pull := func() {
		if _, err := os.Stat(cfg.caCertPath()); err != nil {
			if e := fetchAndInstallRootCA(cfg); e != nil {
				log.Printf("pull: Root CA refresh failed: %v", e)
			}
		}
		url := fmt.Sprintf("https://%s:443/cache", host(cfg.MasterAddress))
		resp, err := pinnedMasterClient(cfg).Get(url)
		if err != nil {
			log.Printf("pull: master unreachable (READ-ONLY): %v", err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			log.Printf("pull: master returned %d", resp.StatusCode)
			return
		}
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			return
		}
		if err := os.WriteFile(cfg.cachePath(), data, 0o600); err != nil {
			log.Printf("pull: cannot write cache: %v", err)
			return
		}
		log.Printf("cache pulled from master (%d bytes)", len(data))

		// Best-effort CRL refresh (non-fatal).
		crlURL := fmt.Sprintf("https://%s:443/crl", host(cfg.MasterAddress))
		if cresp, cerr := pinnedMasterClient(cfg).Get(crlURL); cerr == nil {
			defer cresp.Body.Close()
			if cresp.StatusCode == 200 {
				if b, rerr := io.ReadAll(cresp.Body); rerr == nil && len(b) > 0 {
					if werr := os.WriteFile(cfg.crlPath(), b, 0o644); werr == nil {
						log.Printf("CRL pulled from master (%d bytes)", len(b))
					}
				}
			}
		}
	}

	pull()
	t := time.NewTicker(cfg.PullInterval)
	defer t.Stop()
	for range t.C {
		pull()
	}
}

// ephemeralSelfSigned creates a short-lived self-signed cert for the :8443
// receiver. It is not part of the PKI trust chain.
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

