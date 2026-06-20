package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// host strips an optional :port (and brackets) from an address.
func host(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return addr
	}
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return strings.Trim(addr, "[]")
}

// NOTE: ipsToStr lives in ca.go (single definition). It was previously also
// declared here, which broke the build with "ipsToStr redeclared".

// tcpHealthy reports whether any of the given TCP ports on host accept a
// connection within timeout.
func tcpHealthy(h string, timeout time.Duration, ports ...int) bool {
	for _, p := range ports {
		addr := net.JoinHostPort(h, fmt.Sprintf("%d", p))
		if c, err := net.DialTimeout("tcp", addr, timeout); err == nil {
			c.Close()
			return true
		}
	}
	return false
}

// insecureMasterClient is used ONLY for master->client cache/CRL push, where
// the payload is already AES-GCM encrypted+sealed (cache) or publicly signed
// (CRL), and the client receiver uses an ephemeral self-signed cert.
func insecureMasterClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12,
			},
		},
	}
}

// pinnedMasterClient authenticates the MASTER via Root CA pinning (client->master
// path: /ca, /cache, /crl, /acme/*).
func pinnedMasterClient(cfg *Config) *http.Client {
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // hostname check disabled; pin enforced below
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyMasterPin(cfg, rawCerts)
		},
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}
}

// verifyMasterPin enforces Root CA pinning for the master connection.
func verifyMasterPin(cfg *Config, rawCerts [][]byte) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("master presented no certificate")
	}

	if want := normalizeFingerprint(cfg.MasterFingerprint); want != "" {
		for _, der := range rawCerts {
			if certFingerprint(der) == want {
				return nil
			}
		}
		return fmt.Errorf("master certificate fingerprint mismatch (expected %s…)", shorten(want))
	}

	if caPEM, err := os.ReadFile(cfg.caCertPath()); err == nil {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return fmt.Errorf("local Root CA file is not valid PEM")
		}
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("parse master certificate: %w", err)
		}
		inter := x509.NewCertPool()
		for _, der := range rawCerts[1:] {
			if c, e := x509.ParseCertificate(der); e == nil {
				inter.AddCert(c)
			}
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter}); err != nil {
			return fmt.Errorf("master certificate does not chain to local Root CA: %w", err)
		}
		return nil
	}

	return fmt.Errorf("cannot verify master: set master_fingerprint in config " +
		"or install the Root CA locally first")
}

// certFingerprint returns the lowercase, colon-free hex SHA-256 of a DER cert.
func certFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// normalizeFingerprint lowercases and strips ':' and spaces.
func normalizeFingerprint(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, ":", "")
	s = strings.ReplaceAll(s, " ", "")
	return s
}

func shorten(s string) string {
	if len(s) > 16 {
		return s[:16]
	}
	return s
}

