package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

const maxMasters = 1 // бесплатная версия: кластеризация/Raft отключены.

type CA struct {
	Cert    *x509.Certificate
	CertDER []byte
	Key     *ecdsa.PrivateKey
}

func newSerial() *big.Int {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	n, _ := rand.Int(rand.Reader, max)
	return n
}

// BootstrapCA генерирует Root CA сроком на 10 лет.
func BootstrapCA() (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: newSerial(),
		Subject: pkix.Name{
			CommonName:   "NATSSL Private Root CA",
			Organization: []string{"NATSSL"},
		},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().AddDate(10, 0, 0), // 10 лет
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, CertDER: der, Key: key}, nil
}

func LoadCA(certPath, keyPath string) (*CA, error) {
	cb, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	kb, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	cblock, _ := pem.Decode(cb)
	kblock, _ := pem.Decode(kb)
	if cblock == nil || kblock == nil {
		return nil, errors.New("invalid CA PEM material")
	}
	cert, err := x509.ParseCertificate(cblock.Bytes)
	if err != nil {
		return nil, err
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(kblock.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := keyAny.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("CA key is not ECDSA")
	}
	return &CA{Cert: cert, CertDER: cblock.Bytes, Key: key}, nil
}

func (ca *CA) SaveToFiles(certPath, keyPath string) error {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.CertDER})
	keyDER, err := x509.MarshalPKCS8PrivateKey(ca.Key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return err
	}
	return os.WriteFile(keyPath, keyPEM, 0o600)
}

func (ca *CA) Fingerprint() string {
	sum := sha256.Sum256(ca.CertDER)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

func (ca *CA) KeyPKCS8() ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(ca.Key)
}

// IssueResult — результат выдачи.
type IssueResult struct {
	CertPEM string
	KeyPEM  string // присутствует для localhost-режима (генерим ключ сами)
	Cert    *x509.Certificate
}

// Issue выпускает leaf-сертификат на домены/IP.
//   localhostMode=true  -> срок 1 год, флаг "Same PC only", генерируем ключ.
//   localhostMode=false -> срок 90 дней (ACME-стиль), публичный домен/IP.
func (ca *CA) Issue(subject string, sans []string, localhostMode bool) (*IssueResult, error) {
	dnsNames, ips := splitSANs(append([]string{subject}, sans...))
	if !localhostMode && !validIssuanceTarget(dnsNames, ips) {
		return nil, fmt.Errorf("target not allowed for issuance: %v %v", dnsNames, ips)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	notAfter := time.Now().AddDate(0, 0, 90)
	cn := subject
	if localhostMode {
		notAfter = time.Now().AddDate(1, 0, 0) // 1 год для локальной разработки
		cn = "localhost (Same PC only)"
		if !containsIP(ips, net.ParseIP("127.0.0.1")) {
			ips = append(ips, net.ParseIP("127.0.0.1"), net.ParseIP("::1"))
		}
		if !contains(dnsNames, "localhost") {
			dnsNames = append(dnsNames, "localhost")
		}
	}

	tmpl := &x509.Certificate{
		SerialNumber: newSerial(),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-5 * time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &leafKey.PublicKey, ca.Key)
	if err != nil {
		return nil, err
	}
	cert, _ := x509.ParseCertificate(der)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyDER, _ := x509.MarshalPKCS8PrivateKey(leafKey)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))

	return &IssueResult{CertPEM: certPEM, KeyPEM: keyPEM, Cert: cert}, nil
}

func splitSANs(items []string) (dns []string, ips []net.IP) {
	seenD, seenI := map[string]bool{}, map[string]bool{}
	for _, it := range items {
		it = strings.TrimSpace(it)
		if it == "" {
			continue
		}
		if ip := net.ParseIP(it); ip != nil {
			if !seenI[ip.String()] {
				ips = append(ips, ip)
				seenI[ip.String()] = true
			}
			continue
		}
		if !seenD[it] {
			dns = append(dns, it)
			seenD[it] = true
		}
	}
	return
}

// validIssuanceTarget: *.local, *.internal, любые приватные/публичные IP.
func validIssuanceTarget(dns []string, ips []net.IP) bool {
	for _, d := range dns {
		if strings.HasSuffix(d, ".local") || strings.HasSuffix(d, ".internal") ||
			strings.Contains(d, ".") {
			return true
		}
	}
	return len(ips) > 0
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
func containsIP(s []net.IP, v net.IP) bool {
	for _, x := range s {
		if x.Equal(v) {
			return true
		}
	}
	return false
}

func RunIssueCLI(cfg *Config, target string, localhost bool) error {
	ca, err := LoadCA(cfg.caCertPath(), cfg.caKeyPath())
	if err != nil {
		return fmt.Errorf("no Root CA found (run --bootstrap first): %w", err)
	}
	st, err := OpenStore(cfg.dbPath())
	if err != nil {
		return err
	}
	defer st.Close()

	res, err := ca.Issue(target, nil, localhost)
	if err != nil {
		return err
	}
	rec := CertRecord{
		ID:        res.Cert.SerialNumber.Text(16),
		Subject:   target,
		SANs:      strings.Join(append(res.Cert.DNSNames, ipsToStr(res.Cert.IPAddresses)...), ","),
		NotBefore: res.Cert.NotBefore,
		NotAfter:  res.Cert.NotAfter,
		SerialHex: res.Cert.SerialNumber.Text(16),
		CertPEM:   res.CertPEM,
	}
	if err := st.AddCert(rec); err != nil {
		return err
	}
	if err := RebuildEncryptedCache(cfg, ca, st); err != nil {
		return err
	}

	os.MkdirAll(cfg.issuedDir(), 0o755)
	base := strings.NewReplacer("*", "_", "/", "_", ":", "_").Replace(target)
	os.WriteFile(cfg.issuedDir()+"/"+base+".crt", []byte(res.CertPEM), 0o644)
	os.WriteFile(cfg.issuedDir()+"/"+base+".key", []byte(res.KeyPEM), 0o600)

	fmt.Printf("Issued certificate for %q (serial %s, valid until %s)\n",
		target, rec.SerialHex, rec.NotAfter.Format(time.RFC3339))
	fmt.Printf("Files: %s/%s.crt , %s/%s.key\n", cfg.issuedDir(), base, cfg.issuedDir(), base)
	return nil
}

func ipsToStr(ips []net.IP) []string {
	out := make([]string, len(ips))
	for i, ip := range ips {
		out[i] = ip.String()
	}
	return out
}
