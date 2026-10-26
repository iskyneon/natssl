package main

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

// RFC 5280 CRLReason codes we use.
const (
	crlReasonUnspecified = 0
	crlReasonSuperseded  = 4
)

// BuildCRLDER builds a DER-encoded X.509 CRL signed by the Root CA, listing
// every serial currently in the revoked table. An empty revoked set yields a
// valid CRL with no entries.
func BuildCRLDER(ca *CA, st *Store) ([]byte, error) {
	revoked, err := st.ListRevoked()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	number, err := st.nextCRLNumber(now.UnixNano())
	if err != nil {
		return nil, err
	}
	tmpl := &x509.RevocationList{
		Number:     big.NewInt(number),
		ThisUpdate: now.Add(-5 * time.Minute),
		NextUpdate: now.AddDate(0, 0, 7),
	}

	for _, r := range revoked {
		serial := new(big.Int)
		if _, ok := serial.SetString(r.SerialHex, 16); !ok {
			continue // skip a malformed serial rather than failing the whole CRL
		}
		rt := r.RevokedAt
		if rt.IsZero() {
			rt = now
		}
		tmpl.RevokedCertificateEntries = append(tmpl.RevokedCertificateEntries,
			x509.RevocationListEntry{
				SerialNumber:   serial,
				RevocationTime: rt,
				ReasonCode:     r.Reason,
			})
	}

	// ca.Key (*ecdsa.PrivateKey) satisfies crypto.Signer; ca.Cert carries
	// KeyUsageCRLSign (set in BootstrapCA), so it is a valid CRL issuer.
	return x509.CreateRevocationList(rand.Reader, tmpl, ca.Cert, ca.Key)
}

// WriteCRL generates the CRL and writes it as PEM to cfg.crlPath() (0644).
func WriteCRL(cfg *Config, ca *CA, st *Store) error {
	unlock, err := lockFile(cfg.crlPath() + ".lock")
	if err != nil {
		return err
	}
	defer unlock()
	der, err := BuildCRLDER(ca, st)
	if err != nil {
		return fmt.Errorf("build CRL: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
	if err := atomicWriteFile(cfg.crlPath(), pemBytes, 0o644); err != nil {
		return fmt.Errorf("write CRL: %w", err)
	}
	return nil
}

func acceptCRL(cfg *Config, data []byte) error {
	rootData, err := os.ReadFile(cfg.caCertPath())
	if err != nil {
		return err
	}
	root, err := parseRootCA(rootData)
	if err != nil {
		return err
	}
	parse := func(data []byte) (*x509.RevocationList, error) {
		b, _ := pem.Decode(data)
		if b == nil || b.Type != "X509 CRL" {
			return nil, fmt.Errorf("invalid CRL PEM")
		}
		return x509.ParseRevocationList(b.Bytes)
	}
	crl, err := parse(data)
	if err != nil {
		return err
	}
	if err := crl.CheckSignatureFrom(root); err != nil {
		return err
	}
	now := time.Now()
	if crl.Number == nil || crl.ThisUpdate.After(now.Add(time.Minute)) || !crl.NextUpdate.After(now) {
		return fmt.Errorf("expired or invalid CRL")
	}
	unlock, err := lockFile(cfg.crlPath() + ".lock")
	if err != nil {
		return err
	}
	defer unlock()
	previous, err := os.ReadFile(cfg.crlPath())
	if err == nil {
		old, err := parse(previous)
		if err != nil {
			return err
		}
		if err := old.CheckSignatureFrom(root); err != nil {
			return err
		}
		if old.Number == nil || crl.Number.Cmp(old.Number) < 0 {
			return fmt.Errorf("stale CRL")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return atomicWriteFile(cfg.crlPath(), data, 0o644)
}

func refreshCRL(cfg *Config, ca *CA, st *Store) error {
	data, err := os.ReadFile(cfg.crlPath())
	if err == nil {
		if b, _ := pem.Decode(data); b != nil {
			if crl, err := x509.ParseRevocationList(b.Bytes); err == nil && time.Until(crl.NextUpdate) > 24*time.Hour {
				return nil
			}
		}
	}
	return WriteCRL(cfg, ca, st)
}
