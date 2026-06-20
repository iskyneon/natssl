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
	tmpl := &x509.RevocationList{
		Number:     big.NewInt(now.UnixNano()), // strictly increasing across regenerations
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
	der, err := BuildCRLDER(ca, st)
	if err != nil {
		return fmt.Errorf("build CRL: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
	if err := os.WriteFile(cfg.crlPath(), pemBytes, 0o644); err != nil {
		return fmt.Errorf("write CRL: %w", err)
	}
	return nil
}

