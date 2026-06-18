package main

import (
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
	"strings"
	"time"

	"golang.org/x/crypto/scrypt"
	"golang.org/x/term"
)

// isLoopbackTarget reports whether a client is allowed to request `target`.
// Clients may ONLY issue loopback certificates: localhost / 127.0.0.1 / ::1.
func isLoopbackTarget(target string, localhost bool) bool {
	t := strings.TrimSpace(strings.ToLower(target))
	if t == "localhost" {
		return true
	}
	if ip := net.ParseIP(t); ip != nil && ip.IsLoopback() {
		return true // 127.0.0.1, ::1, 127.x.x.x
	}
	if t == "" && localhost {
		return true
	}
	return false
}

// RunClientIssue lets a client issue a loopback certificate FOR ITSELF via the
// CSR-flow. The private key is generated locally and NEVER leaves the machine.
func RunClientIssue(cfg *Config, target string, localhost bool) error {
	// ── HARD RULE: clients may only issue loopback certificates ─────────
	if !isLoopbackTarget(target, localhost) {
		return fmt.Errorf("clients may only issue certificates for localhost / 127.0.0.1 / ::1.\n"+
			"  Requested %q is not allowed.\n"+
			"  Tip: use  natssl --mode=client --issue \"localhost\" --localhost\n"+
			"  Domain/IP certificates must be issued by the administrator on the master.", target)
	}
	localhost = true // loopback targets are always issued in localhost mode
	// ────────────────────────────────────────────────────────────────────

	// 1. Issuance requires a LIVE master: in ReadOnly mode new issuance is blocked.
	if !tcpHealthy(host(cfg.MasterAddress), 5*time.Second, 443) {
		return fmt.Errorf("master %s is OFFLINE — new issuance blocked (READ-ONLY mode)", cfg.MasterAddress)
	}

	// 2. Generate the leaf private key locally.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	// 3. Build the CSR with loopback SANs only.
	dnsNames := []string{"localhost"}
	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{
			Subject:     pkix.Name{CommonName: "localhost (Same PC only)"},
			DNSNames:    dnsNames,
			IPAddresses: ips,
		}, leafKey)
	if err != nil {
		return err
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))

	// 4. Send the CSR to the master for signing.
	body, _ := json.Marshal(map[string]any{"csr": csrPEM, "localhost": true})
	resp, err := insecureMasterClient().Post(
		fmt.Sprintf("https://%s:443/acme/sign-csr", host(cfg.MasterAddress)),
		"application/json", strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("master request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("master rejected request: %s", strings.TrimSpace(string(msg)))
	}
	var out struct {
		Certificate string `json:"certificate"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return err
	}

	// 5. Encrypt the private key with the user's LOCAL password (scrypt + AES-GCM).
	keyDER, _ := x509.MarshalPKCS8PrivateKey(leafKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	fmt.Print("Set a password to encrypt the private key (Same-PC only): ")
	pw1, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return err
	}
	fmt.Print("\nConfirm password: ")
	pw2, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return err
	}
	fmt.Println()
	if string(pw1) != string(pw2) {
		return fmt.Errorf("passwords do not match")
	}
	if len(pw1) == 0 {
		return fmt.Errorf("empty password is not allowed")
	}
	encKey, err := encryptKeyWithPassword(keyPEM, pw1)
	if err != nil {
		return err
	}

	// 6. Persist artifacts.
	dir := cfg.issuedDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	base := strings.NewReplacer("*", "_", "/", "_", ":", "_").Replace(target)
	if base == "" {
		base = "localhost"
	}
	crtPath := dir + "/" + base + ".crt"
	keyPath := dir + "/" + base + ".key.enc"
	if err := os.WriteFile(crtPath, []byte(out.Certificate), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, encKey, 0o600); err != nil {
		return err
	}

	fmt.Printf("\n\u2714 Loopback certificate issued for %q\n", target)
	fmt.Printf("  cert: %s\n", crtPath)
	fmt.Printf("  key : %s  (encrypted, this PC only)\n", keyPath)
	fmt.Printf("\nDecrypt the key when needed:\n")
	fmt.Printf("  natssl --mode=client --decrypt-key=%s > /tmp/%s.key\n", keyPath, base)
	return nil
}

// RunDecryptKey decrypts a .key.enc file (prompting for the password) to stdout.
func RunDecryptKey(path string) error {
	blob, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	fmt.Fprint(os.Stderr, "Password: ")
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return err
	}
	plain, err := DecryptKeyWithPassword(blob, pw)
	if err != nil {
		return fmt.Errorf("wrong password or corrupted key file")
	}
	_, err = os.Stdout.Write(plain)
	return err
}

// --- scrypt + AES-GCM ----------------------------------------------------

func encryptKeyWithPassword(plaintext, password []byte) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	dk, err := scrypt.Key(password, salt, 1<<15, 8, 1, 32)
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
	return json.Marshal(map[string][]byte{"salt": salt, "nonce": nonce, "ct": ct})
}

func DecryptKeyWithPassword(blob, password []byte) ([]byte, error) {
	var m map[string][]byte
	if err := json.Unmarshal(blob, &m); err != nil {
		return nil, err
	}
	dk, err := scrypt.Key(password, m["salt"], 1<<15, 8, 1, 32)
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
	return gcm.Open(nil, m["nonce"], m["ct"], nil)
}
