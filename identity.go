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
	"net"
	"os"
	"strings"
	"time"
)

const identityPrefix = "natssl-client:"

// The enrollment private key is generated locally and is never sent to master.
func ensureClientIdentity(cfg *Config) error {
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return err
	}
	unlock, err := lockFile(cfg.identityKeyPath() + ".lock")
	if err != nil {
		return err
	}
	defer unlock()
	if pair, err := tls.LoadX509KeyPair(cfg.identityCertPath(), cfg.identityKeyPath()); err == nil {
		if cert, err := x509.ParseCertificate(pair.Certificate[0]); err == nil && time.Until(cert.NotAfter) > 24*time.Hour {
			if err := verifyClientIdentity(cfg, cert); err == nil {
				return nil
			}
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "natssl-client"}}, key)
	if err != nil {
		return err
	}
	body, err := json.Marshal(map[string]string{"csr": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))})
	if err != nil {
		return err
	}
	req, err := buildRegisterRequest(cfg, body)
	if err != nil {
		return err
	}
	client := pinnedMasterClient(cfg)
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := readBounded(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("enrollment rejected (%d): %s", resp.StatusCode, data)
	}
	var out struct {
		Certificate string `json:"certificate"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}
	kd, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	kp := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd})
	pair, err := tls.X509KeyPair([]byte(out.Certificate), kp)
	if err != nil {
		return fmt.Errorf("invalid enrollment certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return err
	}
	if err := verifyClientIdentity(cfg, cert); err != nil {
		return err
	}
	if err := atomicWriteFile(cfg.identityKeyPath(), kp, 0o600); err != nil {
		return err
	}
	return atomicWriteFile(cfg.identityCertPath(), []byte(out.Certificate), 0o644)
}

func verifyClientIdentity(cfg *Config, cert *x509.Certificate) error {
	if cert.IsCA || !strings.HasPrefix(cert.Subject.CommonName, identityPrefix) || net.ParseIP(strings.TrimPrefix(cert.Subject.CommonName, identityPrefix)) == nil {
		return fmt.Errorf("not an enrollment identity")
	}
	data, err := os.ReadFile(cfg.caCertPath())
	if err != nil {
		return err
	}
	ca, err := parseRootCA(data)
	if err != nil {
		return err
	}
	if want := normalizeFingerprint(cfg.MasterFingerprint); want != "" && certFingerprint(ca.Raw) != want {
		return fmt.Errorf("local Root CA fingerprint mismatch")
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	_, err = cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	return err
}
