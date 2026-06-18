package main

import (
	"database/sql"
	"encoding/json"
	"time"

	_ "modernc.org/sqlite"
)

type CertRecord struct {
	ID        string    `json:"id"`
	Subject   string    `json:"subject"`
	SANs      string    `json:"sans"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	ClientPub string    `json:"client_pub"`
	SerialHex string    `json:"serial_hex"`
	CertPEM   string    `json:"cert_pem"`
}

type Store struct{ db *sql.DB }

func OpenStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	schema := `
	CREATE TABLE IF NOT EXISTS certificates (
		id TEXT PRIMARY KEY, subject TEXT, sans TEXT,
		not_before TEXT, not_after TEXT, client_pub TEXT,
		serial_hex TEXT, cert_pem TEXT
	);
	CREATE TABLE IF NOT EXISTS clients (addr TEXT PRIMARY KEY);
	CREATE TABLE IF NOT EXISTS changelog (
		seq INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, op TEXT, payload TEXT
	);`
	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) AddCert(r CertRecord) error {
	_, err := s.db.Exec(`INSERT OR REPLACE INTO certificates
		(id,subject,sans,not_before,not_after,client_pub,serial_hex,cert_pem)
		VALUES (?,?,?,?,?,?,?,?)`,
		r.ID, r.Subject, r.SANs, r.NotBefore.Format(time.RFC3339),
		r.NotAfter.Format(time.RFC3339), r.ClientPub, r.SerialHex, r.CertPEM)
	if err != nil {
		return err
	}
	pl, _ := json.Marshal(r)
	_, err = s.db.Exec(`INSERT INTO changelog (ts,op,payload) VALUES (?,?,?)`,
		time.Now().Format(time.RFC3339), "issue", string(pl))
	return err
}

func (s *Store) AddClient(addr string) error {
	_, err := s.db.Exec(`INSERT OR IGNORE INTO clients(addr) VALUES (?)`, addr)
	return err
}

func (s *Store) ListClients() ([]string, error) {
	rows, err := s.db.Query(`SELECT addr FROM clients`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var a string
		rows.Scan(&a)
		out = append(out, a)
	}
	return out, nil
}

func (s *Store) ListCerts() ([]CertRecord, error) {
	rows, err := s.db.Query(`SELECT id,subject,sans,not_before,not_after,client_pub,serial_hex,cert_pem FROM certificates`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CertRecord
	for rows.Next() {
		var r CertRecord
		var nb, na string
		rows.Scan(&r.ID, &r.Subject, &r.SANs, &nb, &na, &r.ClientPub, &r.SerialHex, &r.CertPEM)
		r.NotBefore, _ = time.Parse(time.RFC3339, nb)
		r.NotAfter, _ = time.Parse(time.RFC3339, na)
		out = append(out, r)
	}
	return out, nil
}

// Snapshot — содержимое recovery-кэша (DR-payload).
type Snapshot struct {
	CACertDER    []byte       `json:"ca_cert_der"`
	CAKeyPKCS8   []byte       `json:"ca_key_pkcs8"`
	Certificates []CertRecord `json:"certificates"`
	Clients      []string     `json:"clients"`
	CreatedAt    time.Time    `json:"created_at"`
}

func (s *Store) BuildSnapshot(ca *CA) (*Snapshot, error) {
	certs, err := s.ListCerts()
	if err != nil {
		return nil, err
	}
	clients, err := s.ListClients()
	if err != nil {
		return nil, err
	}
	keyPKCS8, err := ca.KeyPKCS8()
	if err != nil {
		return nil, err
	}
	return &Snapshot{
		CACertDER:    ca.CertDER,
		CAKeyPKCS8:   keyPKCS8,
		Certificates: certs,
		Clients:      clients,
		CreatedAt:    time.Now(),
	}, nil
}

func (s *Store) RestoreSnapshot(snap *Snapshot) error {
	for _, c := range snap.Certificates {
		if err := s.AddCert(c); err != nil {
			return err
		}
	}
	for _, cl := range snap.Clients {
		if err := s.AddClient(cl); err != nil {
			return err
		}
	}
	return nil
}
