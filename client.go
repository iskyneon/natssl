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
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

type migrationRequest struct {
	packet MigrationPacket
	result chan error
}

// Only signed migration announcements need an inbound listener. Cache and CRL
// are fetched exclusively over the master's authenticated mTLS control plane.
func RunClient(cfg *Config) error {
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return err
	}
	if cfg.MasterAddress == "" {
		return fmt.Errorf("master_address is required")
	}
	if cfg.MasterFingerprint == "" {
		if _, err := os.Stat(cfg.caCertPath()); err != nil {
			return fmt.Errorf("master_fingerprint or local Root CA is required")
		}
	}
	changes := make(chan migrationRequest, 8)
	receiverConfig := *cfg // immutable; the event loop owns changes to cfg
	cert, err := ephemeralSelfSigned()
	if err != nil {
		return err
	}
	srv := newHTTPServer(cfg.Listen.Mgmt, migrationHandler(&receiverConfig, changes), &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}})
	listener, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return err
	}
	defer srv.Close()
	errs := make(chan error, 1)
	go func() { errs <- srv.Serve(tls.NewListener(listener, srv.TLSConfig)) }()
	register := func() {
		if _, err := os.Stat(cfg.caCertPath()); err != nil {
			if err := fetchAndInstallRootCA(cfg); err != nil {
				log.Printf("Root CA bootstrap: %v", err)
				return
			}
		}
		if err := RegisterWithMaster(cfg); err != nil {
			log.Printf("self-registration (READ-ONLY): %v", err)
		}
	}
	pull := func() {
		if err := pullOnce(cfg); err != nil {
			log.Printf("pull (READ-ONLY): %v", err)
		}
	}
	// Retry failed trust-store installation on subsequent registration ticks.
	installOS, installFirefox := true, true
	installTrust := func() {
		if !cfg.InstallTrust {
			return
		}
		data, err := os.ReadFile(cfg.caCertPath())
		if err != nil {
			return
		}
		root, err := parseRootCA(data)
		if err != nil {
			log.Printf("local Root CA: %v", err)
			return
		}
		if want := normalizeFingerprint(cfg.MasterFingerprint); want != "" && certFingerprint(root.Raw) != want {
			log.Printf("local Root CA fingerprint mismatch")
			return
		}
		if installOS {
			if err := InstallRootCAIntoOS(cfg.caCertPath()); err != nil {
				log.Printf("OS trust store: %v", err)
			} else {
				installOS = false
			}
		}
		if installFirefox {
			if err := InstallRootCAIntoFirefox(cfg.caCertPath()); err != nil {
				log.Printf("Firefox trust store: %v", err)
			} else {
				installFirefox = false
			}
		}
	}
	register()
	installTrust()
	pull()
	ping := time.NewTicker(cfg.PingInterval)
	defer ping.Stop()
	sync := time.NewTicker(cfg.PullInterval)
	defer sync.Stop()
	for {
		select {
		case <-ping.C:
			register()
			installTrust()
		case <-sync.C:
			pull()
		case req := <-changes:
			err := applyMigration(cfg, &req.packet)
			req.result <- err
			if err == nil {
				register()
				pull()
			}
		case err := <-errs:
			return err
		}
	}
}

func fetchAndInstallRootCA(cfg *Config) error {
	client := pinnedMasterClient(cfg)
	defer client.CloseIdleConnections()
	resp, err := client.Get(cfg.masterURL(false, "/ca"))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("master returned %d for /ca", resp.StatusCode)
	}
	data, err := readBounded(resp.Body)
	if err != nil {
		return err
	}
	root, err := parseRootCA(data)
	if err != nil {
		return err
	}
	if want := normalizeFingerprint(cfg.MasterFingerprint); want != "" && certFingerprint(root.Raw) != want {
		return fmt.Errorf("downloaded Root CA fingerprint mismatch")
	}
	// With a local trust anchor, a server cannot silently replace that anchor.
	if previous, err := os.ReadFile(cfg.caCertPath()); err == nil {
		old, err := parseRootCA(previous)
		if err != nil {
			return err
		}
		if !old.Equal(root) {
			return fmt.Errorf("downloaded Root CA differs from local Root CA")
		}
	}
	if err := atomicWriteFile(cfg.caCertPath(), data, 0o644); err != nil {
		return err
	}

	return nil
}

func pullOnce(cfg *Config) error {
	client, err := mtlsClient(cfg)
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	fetch := func(path string) ([]byte, error) {
		resp, err := client.Get(cfg.masterURL(true, path))
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("%s returned %d", path, resp.StatusCode)
		}
		return readBounded(resp.Body)
	}
	data, err := fetch("/sync/cache")
	if err != nil {
		return err
	}
	if err := acceptCache(cfg, data); err != nil {
		return err
	}
	crl, err := fetch("/sync/crl")
	if err != nil {
		return err
	}
	if err := acceptCRL(cfg, crl); err != nil {
		return err
	}
	log.Printf("cache and signed CRL pulled from master")
	return nil
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
