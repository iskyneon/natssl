package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

// MigrationPacket announces a new master IP after a disaster-recovery
// promotion. It is signed by the Root CA so clients can trust it regardless of
// the (untrusted) transport used to deliver it.
type MigrationPacket struct {
	NewMasterIP string    `json:"new_master_ip"`
	IssuedAt    time.Time `json:"issued_at"`
	Signature   []byte    `json:"signature"`
}

// migrationDigest is the canonical message digest signed/verified for a packet
// (computed WITHOUT the signature field).
func migrationDigest(pkt *MigrationPacket) [32]byte {
	msg := fmt.Sprintf("natssl-migrate|%s|%d", pkt.NewMasterIP, pkt.IssuedAt.UnixNano())
	return sha256.Sum256([]byte(msg))
}

// randReader returns the crypto/rand source (used for ECDSA signing).
func randReader() io.Reader { return rand.Reader }

// verifyMigrationSig validates a migration packet's ECDSA signature against the
// locally installed Root CA public key.
func verifyMigrationSig(cfg *Config, pkt *MigrationPacket) error {
	caPEM, err := os.ReadFile(cfg.caCertPath())
	if err != nil {
		return fmt.Errorf("no local Root CA: %w", err)
	}
	block, _ := pem.Decode(caPEM)
	if block == nil {
		return fmt.Errorf("local Root CA is not valid PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("Root CA key is not ECDSA")
	}
	d := migrationDigest(pkt)
	if !ecdsa.VerifyASN1(pub, d[:], pkt.Signature) {
		return fmt.Errorf("signature does not verify against the Root CA")
	}
	return nil
}

func migrationHandler(cfg *Config, changes chan<- migrationRequest) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/migrate", func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, "POST") {
			return
		}
		var packet MigrationPacket
		if !decodeRequest(w, r, &packet) {
			return
		}
		if err := verifyMigrationSig(cfg, &packet); err != nil {
			http.Error(w, err.Error(), 403)
			return
		}
		req := migrationRequest{packet: packet, result: make(chan error, 1)}
		select {
		case changes <- req:
		case <-r.Context().Done():
			return
		}
		select {
		case err := <-req.result:
			if err != nil {
				http.Error(w, err.Error(), 403)
			} else {
				io.WriteString(w, "ok")
			}
		case <-r.Context().Done():
			return
		}
	})
	return mux
}

func applyMigration(cfg *Config, pkt *MigrationPacket) error {
	if err := verifyMigrationSig(cfg, pkt); err != nil {
		return err
	}
	ip := net.ParseIP(pkt.NewMasterIP)
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
		return fmt.Errorf("invalid migration address")
	}
	now := time.Now()
	if pkt.IssuedAt.Before(now.Add(-5*time.Minute)) || pkt.IssuedAt.After(now.Add(time.Minute)) || !pkt.IssuedAt.After(cfg.LastMigration) {
		return fmt.Errorf("stale or replayed migration")
	}
	previous := *cfg
	cfg.MasterAddress = ip.String()
	cfg.MasterMgmtAddress = ""
	cfg.LastMigration = pkt.IssuedAt
	if err := cfg.Save(); err != nil {
		*cfg = previous
		return err
	}
	return nil
}
