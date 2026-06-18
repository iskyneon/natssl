package main

import (
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go driver, friendly to cross-compilation
)

// CertRecord is one issued (or signed) certificate as persisted in SQLite and
// replicated inside the encrypted snapshot.
type CertRecord struct {
	ID        string    `json:"id"`
	Subject   string    `json:"subject"`
	SANs      string    `json:"sans"` // comma-separated
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	ClientPub string    `json:"client_pub"`
	SerialHex string    `json:"serial_hex"`
	CertPEM   string    `json:"cert_pem"`
}

// Snapshot is the full, recoverable state of the CA. It is JSON-encoded, then
// AES-GCM encrypted, then the symmetric key is sealed with the recovery public
// key. A promoted master restores the Root CA byte-for-byte from here.
type Snapshot struct {
	Version     int          `json:"version"`
	CreatedAt   time.Time    `json:"created_at"`
	Fingerprint string       `json:"fingerprint"`
	CACertPEM   string       `json:"ca_cert_pem"`
	CAKeyPEM    string       `json:"ca_key_pem"`
	Clients     []string     `json:"clients"`
	Certs       []CertRecord `json:"certs"`
}

// Store wraps the SQLite database.
type Store struct {
	db *sql.DB
}

// OpenStore opens (creating if needed) the SQLite database and ensures schema.
func OpenStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite: serialize writes
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS clients (
    ip         TEXT PRIMARY KEY,
    added_at   DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS certs (
    id          TEXT PRIMARY KEY,
    subject     TEXT,
    sans        TEXT,
    not_before  DATETIME,
    not_after   DATETIME,
    client_pub  TEXT,
    serial_hex  TEXT,
    cert_pem    TEXT
);`)
	return err
}

// Close releases the database handle.
func (s *Store) Close() error { return s.db.Close() }

// AddClient inserts a client IP if absent. Returns true if it was newly added.
func (s *Store) AddClient(ip string) bool {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return false
	}
	res, err := s.db.Exec(`INSERT OR IGNORE INTO clients(ip) VALUES(?)`, ip)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n > 0
}

// RemoveClient deletes a client IP (used for housekeeping / manual eviction).
func (s *Store) RemoveClient(ip string) error {
	_, err := s.db.Exec(`DELETE FROM clients WHERE ip = ?`, strings.TrimSpace(ip))
	return err
}

// ListClients returns all registered client IPs.
func (s *Store) ListClients() ([]string, error) {
	rows, err := s.db.Query(`SELECT ip FROM clients ORDER BY ip`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		out = append(out, ip)
	}
	return out, rows.Err()
}

// AddCert upserts an issued certificate record.
func (s *Store) AddCert(rec CertRecord) error {
	_, err := s.db.Exec(`
INSERT INTO certs(id, subject, sans, not_before, not_after, client_pub, serial_hex, cert_pem)
VALUES(?,?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET
    subject=excluded.subject, sans=excluded.sans,
    not_before=excluded.not_before, not_after=excluded.not_after,
    client_pub=excluded.client_pub, serial_hex=excluded.serial_hex,
    cert_pem=excluded.cert_pem`,
		rec.ID, rec.Subject, rec.SANs, rec.NotBefore, rec.NotAfter,
		rec.ClientPub, rec.SerialHex, rec.CertPEM)
	return err
}

// ListCerts returns all certificate records.
func (s *Store) ListCerts() ([]CertRecord, error) {
	rows, err := s.db.Query(`
SELECT id, subject, sans, not_before, not_after, client_pub, serial_hex, cert_pem
FROM certs ORDER BY not_before`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CertRecord
	for rows.Next() {
		var r CertRecord
		if err := rows.Scan(&r.ID, &r.Subject, &r.SANs, &r.NotBefore, &r.NotAfter,
			&r.ClientPub, &r.SerialHex, &r.CertPEM); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// BuildSnapshot assembles the full recoverable state for the encrypted cache.
func (s *Store) BuildSnapshot(ca *CA) (*Snapshot, error) {
	clients, err := s.ListClients()
	if err != nil {
		return nil, err
	}
	certs, err := s.ListCerts()
	if err != nil {
		return nil, err
	}
	certPEM, keyPEM, err := caPEM(ca)
	if err != nil {
		return nil, err
	}
	return &Snapshot{
		Version:     1,
		CreatedAt:   time.Now().UTC(),
		Fingerprint: ca.Fingerprint(),
		CACertPEM:   certPEM,
		CAKeyPEM:    keyPEM,
		Clients:     clients,
		Certs:       certs,
	}, nil
}

// caPEM extracts the Root CA cert + key as PEM strings.
func caPEM(ca *CA) (certPEM, keyPEM string, err error) {
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw})
	keyDER, err := x509.MarshalPKCS8PrivateKey(ca.Key)
	if err != nil {
		return "", "", fmt.Errorf("marshal CA key: %w", err)
	}
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return string(cert), string(key), nil
}
