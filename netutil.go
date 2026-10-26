package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
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

// insecureMasterClient is used only to deliver Root-CA-signed migration packets.
// The receiver authenticates their signature and rejects stale announcements.
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
// path: bootstrap, enrollment and mTLS control plane).
func pinnedMasterClient(cfg *Config) *http.Client {
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // normal verification is replaced with pin + chain + hostname checks below
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyMasterPin(cfg, rawCerts)
		},
	}
	return &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     &http.Transport{TLSClientConfig: tlsCfg},
	}
}

// verifyMasterPin verifies the complete server chain against exactly the pinned
// Root CA. Merely appending that CA to an unrelated TLS chain is insufficient.
func verifyMasterPin(cfg *Config, rawCerts [][]byte) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("master presented no certificate")
	}
	certs := make([]*x509.Certificate, 0, len(rawCerts))
	for _, der := range rawCerts {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("parse master certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	if certs[0].Subject.CommonName != "natssl-master-api" {
		return fmt.Errorf("master must present its dedicated server identity")
	}
	if certs[0].IsCA {
		return fmt.Errorf("master must serve a dedicated server leaf, not the Root CA")
	}
	var root *x509.Certificate
	want := normalizeFingerprint(cfg.MasterFingerprint)
	if want != "" {
		if len(want) != 64 {
			return fmt.Errorf("invalid master_fingerprint")
		}
		if _, err := hex.DecodeString(want); err != nil {
			return fmt.Errorf("invalid master_fingerprint")
		}
		for _, cert := range certs {
			if cert.IsCA && certFingerprint(cert.Raw) == want {
				root = cert
			}
		}
	}
	if data, err := os.ReadFile(cfg.caCertPath()); err == nil {
		if cert, err := parseRootCA(data); err == nil && (want == "" || certFingerprint(cert.Raw) == want) {
			root = cert
		}
	}
	if root == nil {
		return fmt.Errorf("cannot verify master: set master_fingerprint or install the pinned Root CA")
	}
	roots, inter := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)
	for _, cert := range certs[1:] {
		inter.AddCert(cert)
	}
	if _, err := certs[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, DNSName: host(cfg.MasterAddress), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return fmt.Errorf("master certificate does not chain to pinned Root CA: %w", err)
	}
	return nil
}

func parseRootCA(data []byte) (*x509.Certificate, error) {
	b, _ := pem.Decode(data)
	if b == nil || b.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("Root CA is not valid PEM")
	}
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return nil, err
	}
	if !cert.IsCA || cert.CheckSignatureFrom(cert) != nil {
		return nil, fmt.Errorf("not a self-signed Root CA")
	}
	return cert, nil
}

func mtlsClient(cfg *Config) (*http.Client, error) {
	cert, err := tls.LoadX509KeyPair(cfg.identityCertPath(), cfg.identityKeyPath())
	if err != nil {
		return nil, err
	}
	client := pinnedMasterClient(cfg)
	client.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{cert}
	return client, nil
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
