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

// CertRecord is one issued (or signed) certificate.
type CertRecord struct {
	ID        string    `json:"id"`
	Subject   string    `json:"subject"`
	SANs      string    `json:"sans"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	ClientPub string    `json:"client_pub"`
	SerialHex string    `json:"serial_hex"`
	CertPEM   string    `json:"cert_pem"`
	Revoked   bool      `json:"revoked"`
}

// Snapshot is the full, recoverable state of the CA. Version is monotonic.
type Snapshot struct {
	Version     int64        `json:"version"`
	CreatedAt   time.Time    `json:"created_at"`
	Fingerprint string       `json:"fingerprint"`
	CACertPEM   string       `json:"ca_cert_pem"`
	CAKeyPEM    string       `json:"ca_key_pem"`
	Clients     []string     `json:"clients"`
	Certs       []CertRecord `json:"certs"`
	Revoked     []string     `json:"revoked"` // revoked serials (flat CRL view)
}

type Store struct {
	db *sql.DB
}

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
	if _, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS meta (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS clients (
  ip TEXT PRIMARY KEY,
  added_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS certs (
  id TEXT PRIMARY KEY,
  subject TEXT,
  sans TEXT,
  not_before DATETIME,
  not_after DATETIME,
  client_pub TEXT,
  serial_hex TEXT,
  cert_pem TEXT,
  revoked INTEGER DEFAULT 0
);`); err != nil {
		return err
	}
	// Best-effort upgrade for old databases.
	_, _ = s.db.Exec(`ALTER TABLE certs ADD COLUMN revoked INTEGER DEFAULT 0`)
	return nil
}

func (s *Store) Close() error { return s.db.Close() }

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

func (s *Store) RemoveClient(ip string) error {
	_, err := s.db.Exec(`DELETE FROM clients WHERE ip = ?`, strings.TrimSpace(ip))
	return err
}

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

func (s *Store) AddCert(rec CertRecord) error {
	_, err := s.db.Exec(`
INSERT INTO certs(id, subject, sans, not_before, not_after, client_pub, serial_hex, cert_pem, revoked)
VALUES(?,?,?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET
  subject=excluded.subject, sans=excluded.sans,
  not_before=excluded.not_before, not_after=excluded.not_after,
  client_pub=excluded.client_pub, serial_hex=excluded.serial_hex,
  cert_pem=excluded.cert_pem`, // NB: revoked is intentionally NOT reset here
		rec.ID, rec.Subject, rec.SANs, rec.NotBefore, rec.NotAfter,
		rec.ClientPub, rec.SerialHex, rec.CertPEM, boolToInt(rec.Revoked))
	return err
}

func (s *Store) RevokeCert(serialHex string) error {
	serialHex = strings.TrimSpace(serialHex)
	res, err := s.db.Exec(`UPDATE certs SET revoked=1 WHERE serial_hex=? OR id=?`, serialHex, serialHex)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("no certificate found with serial %q", serialHex)
	}
	return nil
}

func (s *Store) ListCerts() ([]CertRecord, error) {
	rows, err := s.db.Query(`
SELECT id, subject, sans, not_before, not_after, client_pub, serial_hex, cert_pem, revoked
FROM certs ORDER BY not_before`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CertRecord
	for rows.Next() {
		var r CertRecord
		var rev int
		if err := rows.Scan(&r.ID, &r.Subject, &r.SANs, &r.NotBefore, &r.NotAfter,
			&r.ClientPub, &r.SerialHex, &r.CertPEM, &rev); err != nil {
			return nil, err
		}
		r.Revoked = rev != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) ListRevoked() ([]string, error) {
	rows, err := s.db.Query(`SELECT serial_hex FROM certs WHERE revoked=1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var sx string
		if err := rows.Scan(&sx); err != nil {
			return nil, err
		}
		out = append(out, sx)
	}
	return out, rows.Err()
}

// nextVersion atomically increments and returns the monotonic snapshot version.
func (s *Store) nextVersion() (int64, error) {
	var sv string
	_ = s.db.QueryRow(`SELECT v FROM meta WHERE k='snapshot_version'`).Scan(&sv)
	var v int64
	fmt.Sscanf(sv, "%d", &v)
	v++
	_, err := s.db.Exec(
		`INSERT INTO meta(k,v) VALUES('snapshot_version', ?)
		 ON CONFLICT(k) DO UPDATE SET v=excluded.v`, fmt.Sprintf("%d", v))
	return v, err
}

func (s *Store) BuildSnapshot(ca *CA) (*Snapshot, error) {
	ver, err := s.nextVersion()
	if err != nil {
		return nil, err
	}
	clients, err := s.ListClients()
	if err != nil {
		return nil, err
	}
	certs, err := s.ListCerts()
	if err != nil {
		return nil, err
	}
	revoked, err := s.ListRevoked()
	if err != nil {
		return nil, err
	}
	certPEM, keyPEM, err := caPEM(ca)
	if err != nil {
		return nil, err
	}
	return &Snapshot{
		Version:     ver,
		CreatedAt:   time.Now().UTC(),
		Fingerprint: ca.Fingerprint(),
		CACertPEM:   certPEM,
		CAKeyPEM:    keyPEM,
		Clients:     clients,
		Certs:       certs,
		Revoked:     revoked,
	}, nil
}

// RestoreSnapshot transactionally replaces local clients + certs from a
// decrypted snapshot (used by promote-to-master). Atomic: BEGIN/COMMIT.
func (s *Store) RestoreSnapshot(snap *Snapshot) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM clients`); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM certs`); err != nil {
		return err
	}
	for _, ip := range snap.Clients {
		if _, err := tx.Exec(`INSERT OR IGNORE INTO clients(ip) VALUES(?)`, ip); err != nil {
			return err
		}
	}
	for _, r := range snap.Certs {
		if _, err := tx.Exec(`
INSERT INTO certs(id, subject, sans, not_before, not_after, client_pub, serial_hex, cert_pem, revoked)
VALUES(?,?,?,?,?,?,?,?,?)`,
			r.ID, r.Subject, r.SANs, r.NotBefore, r.NotAfter,
			r.ClientPub, r.SerialHex, r.CertPEM, boolToInt(r.Revoked)); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(
		`INSERT INTO meta(k,v) VALUES('snapshot_version', ?)
		 ON CONFLICT(k) DO UPDATE SET v=excluded.v`, fmt.Sprintf("%d", snap.Version)); err != nil {
		return err
	}
	return tx.Commit()
}

func caPEM(ca *CA) (certPEM, keyPEM string, err error) {
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw})
	keyDER, err := x509.MarshalPKCS8PrivateKey(ca.Key)
	if err != nil {
		return "", "", fmt.Errorf("marshal CA key: %w", err)
	}
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return string(cert), string(key), nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
