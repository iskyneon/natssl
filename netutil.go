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
	"path/filepath"
	"strings"
	"time"
)

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

func ipsToStr(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

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

// insecureMasterClient is used ONLY for the signed migration broadcast
// (master -> client :8443 /migrate). The packet body is ECDSA-signed by the
// Root CA and verified by the receiver, so transport verification is not
// required on this single, authenticated-by-payload path.
func insecureMasterClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
		},
	}
}

func rootCAPool(cfg *Config) *x509.CertPool {
	b, err := os.ReadFile(cfg.caCertPath())
	if err != nil {
		return nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil
	}
	return pool
}

// pinnedMasterClient authenticates the master over the BOOTSTRAP path (:443,
// /ca and /acme/register) where the client has no identity cert yet.
func pinnedMasterClient(cfg *Config) *http.Client {
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // default hostname check off; pin enforced below
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyMasterPin(cfg, rawCerts)
		},
	}
	return &http.Client{Timeout: 30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg}}
}

// mtlsClient authenticates BOTH directions for the control plane (:8443): it
// presents the client identity cert AND verifies the master leaf chains to the
// pinned Root CA. Used after enrollment.
func mtlsClient(cfg *Config) (*http.Client, error) {
	cert, err := tls.LoadX509KeyPair(cfg.clientCertPath(), cfg.clientKeyPath())
	if err != nil {
		return nil, fmt.Errorf("client identity not available (enroll first): %w", err)
	}
	pool := rootCAPool(cfg)
	if pool == nil {
		return nil, fmt.Errorf("local Root CA missing")
	}
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		Certificates:       []tls.Certificate{cert},
		RootCAs:            pool,
		InsecureSkipVerify: true, // hostname check off; pin enforced below
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyMasterPin(cfg, rawCerts)
		},
	}
	return &http.Client{Timeout: 30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg}}, nil
}

// verifyMasterPin pins to the ROOT CA (not an arbitrary presented leaf) and
// requires a valid ServerAuth chain. Order:
//  1. master_fingerprint set -> a CA cert with that SHA-256 must be present in
//     the chain, and the leaf must chain to it.
//  2. else -> the leaf must chain to the locally installed Root CA.
//  3. else -> fail closed.
func verifyMasterPin(cfg *Config, rawCerts [][]byte) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("master presented no certificate")
	}
	certs := make([]*x509.Certificate, 0, len(rawCerts))
	for _, der := range rawCerts {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("parse presented cert: %w", err)
		}
		certs = append(certs, c)
	}
	leaf := certs[0]

	roots := x509.NewCertPool()
	if want := normalizeFingerprint(cfg.MasterFingerprint); want != "" {
		var pinned *x509.Certificate
		for _, c := range certs {
			if normalizeFingerprint(certFingerprint(c.Raw)) == want {
				pinned = c
				break
			}
		}
		if pinned == nil {
			return fmt.Errorf("no certificate in chain matches pinned root fingerprint %s…", shorten(want))
		}
		if !pinned.IsCA {
			return fmt.Errorf("pinned certificate is not a CA — refusing")
		}
		roots.AddCert(pinned)
	} else if p := rootCAPool(cfg); p != nil {
		roots = p
	} else {
		return fmt.Errorf("cannot verify master: set master_fingerprint or install the Root CA first")
	}

	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return fmt.Errorf("master leaf does not chain to pinned Root CA: %w", err)
	}
	return nil
}

func certFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func normalizeFingerprint(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, ":", "")
	return strings.ReplaceAll(s, " ", "")
}

func shorten(s string) string {
	if len(s) > 16 {
		return s[:16]
	}
	return s
}

// writeFileAtomic writes via a temp file + rename (durable, no torn files).
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".natssl-tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
