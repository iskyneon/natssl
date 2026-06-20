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

// RevokedRecord is one revoked certificate (drives the CRL).
type RevokedRecord struct {
	SerialHex string    `json:"serial_hex"`
	Subject   string    `json:"subject"`
	Reason    int       `json:"reason"` // RFC 5280 CRLReason code
	RevokedAt time.Time `json:"revoked_at"`
}

// BlockRecord is one blacklisted client IP.
type BlockRecord struct {
	IP      string    `json:"ip"`
	Reason  string    `json:"reason"`
	AddedAt time.Time `json:"added_at"`
}

// ClientInfo is a registered client together with its registration timestamp.
type ClientInfo struct {
	IP      string    `json:"ip"`
	AddedAt time.Time `json:"added_at"`
}

// Snapshot is the full, recoverable state of the CA. It is JSON-encoded, then
// AES-GCM encrypted, then the symmetric key is sealed with the recovery public
// key. A promoted master restores the Root CA byte-for-byte from here.
//
// CACertPEM / CAKeyPEM are PEM strings — matches promote.go's restore path.
type Snapshot struct {
	Version     int             `json:"version"`
	CreatedAt   time.Time       `json:"created_at"`
	Fingerprint string          `json:"fingerprint"`
	CACertPEM   string          `json:"ca_cert_pem"`
	CAKeyPEM    string          `json:"ca_key_pem"`
	Clients     []string        `json:"clients"`
	Certs       []CertRecord    `json:"certs"`
	Revoked     []RevokedRecord `json:"revoked"`   // replicated so a promoted master keeps revocations
	Blacklist   []BlockRecord   `json:"blacklist"` // replicated so a promoted master keeps blocks
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
    cert_pem TEXT
);
CREATE TABLE IF NOT EXISTS revoked (
    serial_hex TEXT PRIMARY KEY,
    subject    TEXT,
    reason     INTEGER DEFAULT 0,
    revoked_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS blacklist (
    ip       TEXT PRIMARY KEY,
    reason   TEXT,
    added_at DATETIME DEFAULT CURRENT_TIMESTAMP
);`)
	return err
}

// Close releases the database handle.
func (s *Store) Close() error { return s.db.Close() }

// --- clients -------------------------------------------------------------

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

// RemoveClient deletes a client IP.
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

// ListClientsInfo returns all registered clients with their added_at time.
func (s *Store) ListClientsInfo() ([]ClientInfo, error) {
	rows, err := s.db.Query(`SELECT ip, added_at FROM clients ORDER BY ip`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ClientInfo
	for rows.Next() {
		var ci ClientInfo
		if err := rows.Scan(&ci.IP, &ci.AddedAt); err != nil {
			return nil, err
		}
		out = append(out, ci)
	}
	return out, rows.Err()
}

// --- certs ---------------------------------------------------------------

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

// CertBySerial returns a single cert record by its hex serial.
func (s *Store) CertBySerial(serial string) (*CertRecord, bool, error) {
	row := s.db.QueryRow(`
SELECT id, subject, sans, not_before, not_after, client_pub, serial_hex, cert_pem
FROM certs WHERE serial_hex = ?`, serial)
	var r CertRecord
	err := row.Scan(&r.ID, &r.Subject, &r.SANs, &r.NotBefore, &r.NotAfter,
		&r.ClientPub, &r.SerialHex, &r.CertPEM)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return &r, true, nil
}

// CertsBySubject returns all (issued) cert records whose subject matches.
func (s *Store) CertsBySubject(subject string) ([]CertRecord, error) {
	rows, err := s.db.Query(`
SELECT id, subject, sans, not_before, not_after, client_pub, serial_hex, cert_pem
FROM certs WHERE subject = ? ORDER BY not_before`, subject)
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

// --- revocation ----------------------------------------------------------

// RevokeCert records a certificate serial as revoked (idempotent on serial).
func (s *Store) RevokeCert(serialHex, subject string, reason int) error {
	_, err := s.db.Exec(`
INSERT INTO revoked(serial_hex, subject, reason) VALUES(?,?,?)
ON CONFLICT(serial_hex) DO UPDATE SET subject=excluded.subject, reason=excluded.reason`,
		serialHex, subject, reason)
	return err
}

// IsRevoked reports whether a serial is in the revoked set.
func (s *Store) IsRevoked(serial string) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(1) FROM revoked WHERE serial_hex = ?`, serial).Scan(&n)
	return n > 0, err
}

// ListRevoked returns all revoked certificate records.
func (s *Store) ListRevoked() ([]RevokedRecord, error) {
	rows, err := s.db.Query(`SELECT serial_hex, subject, reason, revoked_at FROM revoked ORDER BY revoked_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RevokedRecord
	for rows.Next() {
		var r RevokedRecord
		if err := rows.Scan(&r.SerialHex, &r.Subject, &r.Reason, &r.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RevokedSet returns revoked serials as a lookup map.
func (s *Store) RevokedSet() (map[string]bool, error) {
	recs, err := s.ListRevoked()
	if err != nil {
		return nil, err
	}
	m := make(map[string]bool, len(recs))
	for _, r := range recs {
		m[r.SerialHex] = true
	}
	return m, nil
}

// --- blacklist -----------------------------------------------------------

// BlockIP adds an IP to the blacklist (idempotent).
func (s *Store) BlockIP(ip, reason string) error {
	_, err := s.db.Exec(`
INSERT INTO blacklist(ip, reason) VALUES(?,?)
ON CONFLICT(ip) DO UPDATE SET reason=excluded.reason`,
		strings.TrimSpace(ip), reason)
	return err
}

// UnblockIP removes an IP from the blacklist.
func (s *Store) UnblockIP(ip string) error {
	_, err := s.db.Exec(`DELETE FROM blacklist WHERE ip = ?`, strings.TrimSpace(ip))
	return err
}

// IsBlocked reports whether an IP is blacklisted.
func (s *Store) IsBlocked(ip string) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(1) FROM blacklist WHERE ip = ?`, strings.TrimSpace(ip)).Scan(&n)
	return n > 0, err
}

// ListBlocked returns all blacklisted IPs.
func (s *Store) ListBlocked() ([]BlockRecord, error) {
	rows, err := s.db.Query(`SELECT ip, reason, added_at FROM blacklist ORDER BY ip`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BlockRecord
	for rows.Next() {
		var b BlockRecord
		if err := rows.Scan(&b.IP, &b.Reason, &b.AddedAt); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// --- snapshot ------------------------------------------------------------

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
	revoked, err := s.ListRevoked()
	if err != nil {
		return nil, err
	}
	blacklist, err := s.ListBlocked()
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
		Revoked:     revoked,
		Blacklist:   blacklist,
	}, nil
}

// RestoreSnapshot rewrites the local DB from a decrypted snapshot. Used by the
// disaster-recovery promotion so a former client becomes a fully-functional
// master that knows the LAST replicated state: clients, issued certs, revoked
// serials AND the blacklist. Idempotent (clears then repopulates each table).
func (s *Store) RestoreSnapshot(snap *Snapshot) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() // no-op after a successful Commit

	if _, err := tx.Exec(`DELETE FROM clients`); err != nil {
		return err
	}
	for _, ip := range snap.Clients {
		if _, err := tx.Exec(`INSERT OR IGNORE INTO clients(ip) VALUES(?)`, strings.TrimSpace(ip)); err != nil {
			return err
		}
	}

	if _, err := tx.Exec(`DELETE FROM certs`); err != nil {
		return err
	}
	for _, c := range snap.Certs {
		if _, err := tx.Exec(`
INSERT OR REPLACE INTO certs(id, subject, sans, not_before, not_after, client_pub, serial_hex, cert_pem)
VALUES(?,?,?,?,?,?,?,?)`,
			c.ID, c.Subject, c.SANs, c.NotBefore, c.NotAfter,
			c.ClientPub, c.SerialHex, c.CertPEM); err != nil {
			return err
		}
	}

	if _, err := tx.Exec(`DELETE FROM revoked`); err != nil {
		return err
	}
	for _, r := range snap.Revoked {
		ra := r.RevokedAt
		if ra.IsZero() {
			ra = time.Now().UTC()
		}
		if _, err := tx.Exec(`
INSERT OR REPLACE INTO revoked(serial_hex, subject, reason, revoked_at)
VALUES(?,?,?,?)`, r.SerialHex, r.Subject, r.Reason, ra); err != nil {
			return err
		}
	}

	if _, err := tx.Exec(`DELETE FROM blacklist`); err != nil {
		return err
	}
	for _, b := range snap.Blacklist {
		ba := b.AddedAt
		if ba.IsZero() {
			ba = time.Now().UTC()
		}
		if _, err := tx.Exec(`
INSERT OR REPLACE INTO blacklist(ip, reason, added_at)
VALUES(?,?,?)`, strings.TrimSpace(b.IP), b.Reason, ba); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// caPEM extracts the Root CA cert + key as PEM strings.
func caPEM(ca *CA) (certPEM, keyPEM string, err error) {
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.CertDER})
	keyDER, err := x509.MarshalPKCS8PrivateKey(ca.Key)
	if err != nil {
		return "", "", fmt.Errorf("marshal CA key: %w", err)
	}
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return string(cert), string(key), nil
}

