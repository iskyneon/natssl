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

const maxMasters = 1 // OSS edition: clustering/Raft disabled.

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

// BootstrapCA generates a Root CA valid for 10 years.
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
		NotAfter:              time.Now().AddDate(10, 0, 0),
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
	if !cert.IsCA || cert.CheckSignatureFrom(cert) != nil || !key.PublicKey.Equal(cert.PublicKey) {
		return nil, fmt.Errorf("invalid or mismatched Root CA key pair")
	}
	return &CA{Cert: cert, CertDER: cblock.Bytes, Key: key}, nil
}

// LoadCAFromPEM rebuilds a CA from in-memory PEM (used by promote/recovery).
func LoadCAFromPEM(certPEM, keyPEM string) (*CA, error) {
	cblock, _ := pem.Decode([]byte(certPEM))
	kblock, _ := pem.Decode([]byte(keyPEM))
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
	if !cert.IsCA || cert.CheckSignatureFrom(cert) != nil || !key.PublicKey.Equal(cert.PublicKey) {
		return nil, fmt.Errorf("invalid or mismatched Root CA key pair")
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
	if err := atomicWriteFile(certPath, certPEM, 0o644); err != nil {
		return err
	}
	return atomicWriteFile(keyPath, keyPEM, 0o600) // CA key: strict perms
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

func (ca *CA) certPEMBytes() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.CertDER})
}

// IssueResult — issuance result.
type IssueResult struct {
	CertPEM string
	KeyPEM  string // present only when WE generate the key (master --issue / localhost)
	Cert    *x509.Certificate
}

// Issue creates a leaf cert AND its key (master generates both). CLI-only path.
func (ca *CA) Issue(subject string, sans []string, localhostMode bool) (*IssueResult, error) {
	dnsNames, ips := splitSANs(append([]string{subject}, sans...))
	if !localhostMode && !validIssuanceTarget(dnsNames, ips) {
		return nil, fmt.Errorf("target not allowed for issuance: %v %v", dnsNames, ips)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	notAfter := time.Now().Add(90 * 24 * time.Hour)
	cn := subject
	if localhostMode {
		dnsNames, ips = loopbackSANs("localhost")
		notAfter = time.Now().AddDate(1, 0, 0)
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
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
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

// SignCSR signs a client CSR. The leaf private key is unknown to the master.
func (ca *CA) SignCSR(csr *x509.CertificateRequest, localhostMode bool) (*IssueResult, error) {
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("invalid CSR signature: %w", err)
	}
	dnsNames := csr.DNSNames
	ips := csr.IPAddresses
	notAfter := time.Now().Add(90 * 24 * time.Hour)

	if localhostMode {
		if err := enforceLoopbackOnly(csr, true); err != nil {
			return nil, err
		}
		for _, d := range dnsNames {
			if d != "localhost" {
				return nil, fmt.Errorf("localhost mode: only 'localhost' allowed, got %q", d)
			}
		}
		for _, ip := range ips {
			if !ip.IsLoopback() {
				return nil, fmt.Errorf("localhost mode: only loopback IPs allowed, got %s", ip)
			}
		}
		notAfter = time.Now().AddDate(1, 0, 0)
	} else if !validIssuanceTarget(dnsNames, ips) {
		return nil, fmt.Errorf("CSR target not allowed for issuance: %v %v", dnsNames, ips)
	}

	tmpl := &x509.Certificate{
		SerialNumber: newSerial(),
		Subject:      csr.Subject,
		NotBefore:    time.Now().Add(-5 * time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, csr.PublicKey, ca.Key)
	if err != nil {
		return nil, err
	}
	cert, _ := x509.ParseCertificate(der)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return &IssueResult{CertPEM: certPEM, Cert: cert}, nil
}

// IssueServerCert issues a SERVER-auth leaf for the master's TLS listeners and
// returns a chain [leaf || root] so pinning clients can verify it during
// bootstrap (before they have the Root CA on disk). This is what the master
// serves TLS with — NOT the Root CA key (which only ever signs).
func (ca *CA) IssueServerCert(hosts []string) (certChainPEM, keyPEM []byte, err error) {
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	var dns []string
	var ips []net.IP
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			ips = append(ips, ip)
		} else {
			dns = append(dns, h)
		}
	}
	ips = append(ips, net.ParseIP("127.0.0.1"), net.ParseIP("::1"))

	tmpl := &x509.Certificate{
		SerialNumber: newSerial(),
		Subject:      pkix.Name{CommonName: "natssl-master-api"},
		NotBefore:    time.Now().Add(-5 * time.Minute),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dns,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &leafKey.PublicKey, ca.Key)
	if err != nil {
		return nil, nil, err
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	certChainPEM = append(leafPEM, ca.certPEMBytes()...) // leaf THEN root
	kd, _ := x509.MarshalPKCS8PrivateKey(leafKey)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd})
	return certChainPEM, keyPEM, nil
}

// IssueClientCert signs a CLIENT-auth leaf from a client CSR. Used to give each
// registered client an mTLS identity for the control plane.
func (ca *CA) IssueClientCert(csr *x509.CertificateRequest, cn string) (string, error) {
	if err := csr.CheckSignature(); err != nil {
		return "", fmt.Errorf("invalid CSR signature: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: newSerial(),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-5 * time.Minute),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, csr.PublicKey, ca.Key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
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

// validIssuanceTarget: *.local, *.internal, any dotted DNS name, or any IP.
func validIssuanceTarget(dns []string, ips []net.IP) bool {
	if len(dns)+len(ips) == 0 {
		return false
	}
	for _, ip := range ips {
		if ip == nil {
			return false
		}
	}
	for _, name := range dns {
		if !strings.Contains(name, ".") {
			return false
		}
		name = strings.TrimPrefix(name, "*.")
		if len(name) > 253 {
			return false
		}
		for _, label := range strings.Split(name, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return false
			}
			for _, r := range label {
				if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
					return false
				}
			}
		}
	}
	return true
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

// RunIssueCLI is the CLI-only admin issuance path (any target). It never goes
// over HTTP. /acme/new-order was removed precisely so this is the only way to
// mint non-loopback certificates.
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

	target = canonicalTarget(target)
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

	unlock, err := lockIssuance(cfg, target)
	if err != nil {
		return err
	}
	defer unlock()
	if err := writeIssuedFiles(cfg, target, res); err != nil {
		return err
	}
	base := sanitizeName(target)

	if err := st.AddCert(rec); err != nil {
		return err
	}
	if err := RebuildEncryptedCache(cfg, ca, st); err != nil {
		return err
	}

	fmt.Printf("Issued certificate for %q (serial %s, valid until %s)\n",
		target, rec.SerialHex, rec.NotAfter.Format(time.RFC3339))
	fmt.Printf("Files: %s/%s.crt , %s/%s.key\n", cfg.issuedDir(), base, cfg.issuedDir(), base)
	return nil
}

// RunRevoke marks a certificate (by serial hex) as revoked and rebuilds the
// encrypted cache so the revocation propagates to clients.
func RunRevoke(cfg *Config, serial string) error { return RunRevokeCert(cfg, serial) }

func ipsToStr(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

func canonicalTarget(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	return s
}

func lockIssuance(cfg *Config, target string) (func(), error) {
	if err := os.MkdirAll(cfg.issuedDir(), 0o700); err != nil {
		return nil, err
	}
	return lockFile(cfg.issuedDir() + "/" + sanitizeName(target) + ".issue.lock")
}

func writeIssuedFiles(cfg *Config, target string, res *IssueResult) error {
	base := cfg.issuedDir() + "/" + sanitizeName(target)
	previous, readErr := os.ReadFile(base + ".key")
	if readErr != nil && !os.IsNotExist(readErr) {
		return readErr
	}
	if err := atomicWriteFile(base+".key", []byte(res.KeyPEM), 0o600); err != nil {
		return err
	}
	if err := atomicWriteFile(base+".crt", []byte(res.CertPEM), 0o644); err != nil {
		var rollback error
		if readErr == nil {
			rollback = atomicWriteFile(base+".key", previous, 0o600)
		} else {
			rollback = os.Remove(base + ".key")
		}
		return errors.Join(err, rollback)
	}
	return nil
}
