package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/scrypt"
	"golang.org/x/term"
)

// scrypt parameters for encrypting the leaf private key at rest.
const (
	scryptN      = 1 << 15 // 32768
	scryptR      = 8
	scryptP      = 1
	scryptKeyLen = 32 // AES-256
	saltLen      = 16
)

// isLoopbackTarget reports whether the requested subject is strictly loopback.
// This is the CLIENT-SIDE half of the loopback-only rule; the master enforces
// the same rule again in enforceLoopbackOnly (defense in depth).
func isLoopbackTarget(subject string) bool {
	s := strings.TrimSpace(strings.ToLower(subject))
	switch s {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// loopbackSANs returns the DNS and IP SANs for a given loopback subject.
func loopbackSANs(subject string) (dns []string, ips []net.IP) {
	s := strings.TrimSpace(strings.ToLower(subject))
	if ip := net.ParseIP(s); ip != nil {
		return nil, []net.IP{ip}
	}
	// subject == "localhost"
	return []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
}

// RunClientIssue issues a LOOPBACK-ONLY certificate for this machine using the
// CSR-flow: the private key is generated locally and never leaves the machine.
// The master signs the CSR (and independently re-enforces the loopback rule).
//
//	natssl --mode=client --issue "localhost" [--localhost]
func RunClientIssue(cfg *Config, subject string, localhost bool) error {
	if cfg.MasterAddress == "" {
		return fmt.Errorf("master_address is required to issue certificates")
	}

	// ── CLIENT-SIDE HARD RULE: loopback only ──────────────────────────────
	if !isLoopbackTarget(subject) {
		return fmt.Errorf(
			"clients may only issue certificates for localhost / 127.0.0.1 / ::1.\n"+
				"  %q is not a loopback target.\n"+
				"  Domain/IP certificates must be issued by the administrator on the master:\n"+
				"      natssl --mode=master --issue %q", subject, subject)
	}
	// The flag is implied for loopback subjects; normalize it for the master.
	localhost = true

	// ── ReadOnly guard: refuse to issue if the master is unreachable ───────
	if !tcpHealthy(host(cfg.MasterAddress), 3*time.Second, 443) {
		return fmt.Errorf("issue failed: master is OFFLINE (READ-ONLY mode). " +
			"Existing certificates keep working; new issuance requires the master")
	}

	// 1. Generate the leaf keypair LOCALLY.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	// 2. Build a CSR with loopback SANs only.
	dns, ips := loopbackSANs(subject)
	csrTmpl := &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: subject},
		DNSNames:    dns,
		IPAddresses: ips,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, key)
	if err != nil {
		return fmt.Errorf("create CSR: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	// Public key (for the master's audit record).
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	// 3. Ask the master to sign it (pinned transport).
	certPEM, err := requestCSRSign(cfg, string(csrPEM), string(pubPEM), localhost)
	if err != nil {
		return err
	}

	// 4. Prompt for a password and encrypt the private key at rest.
	password, err := promptPassword("Set a password to encrypt the private key: ")
	if err != nil {
		return err
	}
	confirm, err := promptPassword("Confirm password: ")
	if err != nil {
		return err
	}
	if password != confirm {
		return fmt.Errorf("passwords do not match")
	}
	if len(password) == 0 {
		return fmt.Errorf("empty password is not allowed")
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}
	encKey, err := encryptKey(keyDER, password)
	if err != nil {
		return fmt.Errorf("encrypt private key: %w", err)
	}

	// 5. Persist cert (plaintext) + key (encrypted) under issued/.
	if err := os.MkdirAll(cfg.issuedDir(), 0o755); err != nil {
		return err
	}
	base := sanitizeName(subject)
	certPath := filepath.Join(cfg.issuedDir(), base+".crt")
	keyPath := filepath.Join(cfg.issuedDir(), base+".key.enc")

	if err := os.WriteFile(certPath, []byte(certPEM), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, encKey, 0o600); err != nil {
		return err
	}

	fmt.Println("============================================================")
	fmt.Printf(" ✔ Loopback certificate issued for %q\n", subject)
	fmt.Println("   cert:", certPath)
	fmt.Println("   key :", keyPath, " (encrypted, this PC only)")
	fmt.Println("------------------------------------------------------------")
	fmt.Println(" Decrypt the key for use with:")
	fmt.Printf("   natssl --mode=client --decrypt-key=%s > key.pem\n", keyPath)
	fmt.Println("============================================================")
	return nil
}

// requestCSRSign POSTs the CSR to the master and returns the signed cert PEM.
// Uses the pinned client so a rogue master / MITM is rejected.
func requestCSRSign(cfg *Config, csrPEM, pubPEM string, localhost bool) (string, error) {
	url := fmt.Sprintf("https://%s:443/acme/sign-csr", host(cfg.MasterAddress))
	body, _ := json.Marshal(map[string]any{
		"csr":        csrPEM,
		"client_pub": pubPEM,
		"localhost":  localhost,
	})

	resp, err := pinnedMasterClient(cfg).Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("contact master: %w", err)
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("master rejected request (%d): %s",
			resp.StatusCode, strings.TrimSpace(string(data)))
	}

	var out struct {
		Certificate string `json:"certificate"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", fmt.Errorf("parse master response: %w", err)
	}
	if out.Certificate == "" {
		return "", fmt.Errorf("master returned an empty certificate")
	}
	return out.Certificate, nil
}

// RunDecryptKey decrypts a .key.enc file and writes the PEM private key to
// stdout, so it can be redirected to a file:
//
//	natssl --mode=client --decrypt-key=localhost.key.enc > key.pem
func RunDecryptKey(cfg *Config, path string) error {
	enc, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	password, err := promptPassword("Password to decrypt the private key: ")
	if err != nil {
		return err
	}
	keyDER, err := decryptKey(enc, password)
	if err != nil {
		return fmt.Errorf("decrypt failed (wrong password?): %w", err)
	}
	// Re-encode as PKCS#8 PEM for portability.
	if _, err := x509.ParsePKCS8PrivateKey(keyDER); err != nil {
		return fmt.Errorf("decrypted data is not a valid private key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	_, err = os.Stdout.Write(pemBytes)
	return err
}

// --- key-at-rest encryption (scrypt KDF + AES-256-GCM) --------------------
//
// On-disk layout:  [ salt(16) | nonce(12) | ciphertext+tag ]

func encryptKey(plaintext []byte, password string) ([]byte, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	dk, err := scrypt.Key([]byte(password), salt, scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)

	out := make([]byte, 0, len(salt)+len(nonce)+len(ct))
	out = append(out, salt...)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

func decryptKey(blob []byte, password string) ([]byte, error) {
	if len(blob) < saltLen+12+16 {
		return nil, fmt.Errorf("ciphertext too short / corrupted")
	}
	salt := blob[:saltLen]
	rest := blob[saltLen:]

	dk, err := scrypt.Key([]byte(password), salt, scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(rest) < ns {
		return nil, fmt.Errorf("ciphertext too short / corrupted")
	}
	nonce := rest[:ns]
	ct := rest[ns:]
	return gcm.Open(nil, nonce, ct, nil)
}

// --- helpers --------------------------------------------------------------

// promptPassword reads a password from the terminal without echoing it.
func promptPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	b, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// sanitizeName turns a subject into a safe filename base.
func sanitizeName(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	repl := strings.NewReplacer("/", "_", "\\", "_", ":", "_", "*", "_",
		"?", "_", "\"", "_", "<", "_", ">", "_", "|", "_", " ", "_")
	s = repl.Replace(s)
	if s == "" {
		s = "cert"
	}
	return s
}
