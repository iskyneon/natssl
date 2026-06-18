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

// host strips an optional :port (and brackets) from an address, returning the
// bare host or IP. "1.2.3.4:443" -> "1.2.3.4", "[::1]:8443" -> "::1".
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

// ipsToStr converts a slice of net.IP to their string forms.
func ipsToStr(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

// tcpHealthy reports whether any of the given TCP ports on host accept a
// connection within timeout. Used by the promote-to-master safety checks.
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

// insecureMasterClient is used ONLY for the master->client cache push, where
// the payload is already AES-GCM encrypted and sealed with the recovery public
// key (useless without the seed phrase). The client receiver uses an ephemeral
// self-signed cert, so verification is skipped on this direction only.
func insecureMasterClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // master -> ephemeral client cert only
				MinVersion:         tls.VersionTLS12,
			},
		},
	}
}

// pinnedMasterClient authenticates the MASTER via Root CA pinning. It replaces
// InsecureSkipVerify on the client->master path (/ca, /cache, /acme/*).
//
// Pinning order:
//  1. If master_fingerprint is set, the master's presented certificate must
//     match that SHA-256 fingerprint exactly. This works even before the local
//     Root CA file exists, solving the bootstrap chicken-and-egg.
//  2. Otherwise, if the local Root CA file exists, the presented certificate
//     must chain to it.
//  3. Otherwise (no pin, no local CA), the connection is refused (fail closed).
//
// InsecureSkipVerify is set only to disable the default hostname check (the
// Root CA cert carries no SAN for the master's IP); the pin is enforced in
// VerifyPeerCertificate. This is the standard certificate-pinning pattern.
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

	// 1) Explicit fingerprint pin (preferred; survives before CA is on disk).
	if want := normalizeFingerprint(cfg.MasterFingerprint); want != "" {
		for _, der := range rawCerts {
			if certFingerprint(der) == want {
				return nil
			}
		}
		return fmt.Errorf("master certificate fingerprint mismatch (expected %s…)",
			shorten(want))
	}

	// 2) Chain to the locally installed Root CA.
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

	// 3) Nothing to pin against -> refuse.
	return fmt.Errorf("cannot verify master: set master_fingerprint in config " +
		"or install the Root CA locally first")
}

// certFingerprint returns the lowercase, colon-free hex SHA-256 of a DER cert.
func certFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// normalizeFingerprint lowercases and strips ':' and spaces so that
// "AB:CD:.." and "abcd.." compare equal.
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
