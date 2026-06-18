package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// RebuildEncryptedCache: формирует снапшот, шифрует AES-GCM, ключ запечатывает recovery-pub.
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
	for _, c := range cfg.Clients {
		st.AddClient(c)
	}
	if err := RebuildEncryptedCache(cfg, ca, st); err != nil {
		return err
	}

	fmt.Println("============================================================")
	fmt.Println(" NATSSL Root CA initialized (valid 10 years).")
	fmt.Println(" SHA-256 fingerprint:")
	fmt.Println("   " + ca.Fingerprint())
	fmt.Println("------------------------------------------------------------")
	fmt.Println(" DISASTER RECOVERY SEED PHRASE (24 words) — SHOWN ONCE.")
	fmt.Println(" Write it down OFFLINE. It is NOT stored on disk.")
	fmt.Println("------------------------------------------------------------")
	fmt.Println(" " + mnemonic)
	fmt.Println("============================================================")
	return nil
}

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

	log.Printf("master online | fingerprint %s", ca.Fingerprint())

	// Порт 443 — ACME-совместимый REST API выдачи.
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

	// Push-генератор кэша: веерная рассылка раз в pull_interval.
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

	// Порт 8443 — внутреннее управление/синхронизация (mTLS).
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
	client := insecureMasterClient() // клиент доверяет нашему Root CA
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
