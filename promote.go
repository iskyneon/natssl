package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// RunPromote performs a disaster-recovery promotion of this client into a new
// master. It refuses to run unless the old master is provably dead (anti
// split-brain), then restores the Root CA byte-for-byte and the LAST replicated
// state (clients, issued certs, revoked serials, blacklist) from the locally
// stored encrypted cache.
func RunPromote(cfg *Config, mnemonic string) error {
	log.Printf("=== DISASTER RECOVERY PROMOTION START ===")

	oldIP := host(cfg.MasterAddress)
	if oldIP == "" {
		return fmt.Errorf("no old master address in config")
	}

	// CHECK 1: old CA liveness (TCP 443/8443).
	log.Printf("check 1/3: TCP health of old master %s", oldIP)
	if tcpHealthy(oldIP, 3*time.Second, 443) || tcpHealthy(oldIP, 3*time.Second, 8443) {
		return fmt.Errorf("OLD MASTER IS ALIVE (443/8443 responds) — promotion aborted to prevent split-brain")
	}

	// CHECK 2: L2/L3 — ICMP ping + ARP table.
	log.Printf("check 2/3: ICMP/ARP reachability of %s", oldIP)
	if icmpAlive(oldIP) || arpKnown(oldIP) {
		return fmt.Errorf("old master IP %s answers at network layer (ICMP/ARP) — promotion blocked", oldIP)
	}

	// CHECK 3: own IP conflict.
	log.Printf("check 3/3: local IP conflict check")
	myIPs, err := localIPv4s()
	if err != nil {
		return err
	}
	for _, ip := range myIPs {
		if ip == oldIP {
			return fmt.Errorf("local IP %s equals old master IP — address conflict, promotion blocked", oldIP)
		}
	}
	log.Printf("all safety checks passed")

	// Reconstruct the recovery key from the seed phrase.
	rk, err := RecoveryFromMnemonic(strings.TrimSpace(mnemonic))
	if err != nil {
		return err
	}
	cfgPub, err := RecoveryPublicFromBase64(cfg.RecoveryPublicKey)
	if err != nil {
		return fmt.Errorf("config has no recovery public key: %w", err)
	}
	if rk.Public != *cfgPub {
		return fmt.Errorf("seed phrase does not match the network's recovery public key")
	}
	log.Printf("recovery key reconstructed and verified against pinned public key")

	// Decrypt the locally stored cache and parse the snapshot.
	ec, err := ReadEncryptedCache(cfg.cachePath())
	if err != nil {
		return fmt.Errorf("no local network cache to recover from: %w", err)
	}
	plain, err := DecryptCache(ec, rk)
	if err != nil {
		return err
	}
	var snap Snapshot
	if err := json.Unmarshal(plain, &snap); err != nil {
		return err
	}
	log.Printf("cache decrypted (created %s): %d certs, %d clients, %d revoked, %d blacklisted",
		snap.CreatedAt.Format(time.RFC3339),
		len(snap.Certs), len(snap.Clients), len(snap.Revoked), len(snap.Blacklist))

	// Restore the Root CA BYTE-FOR-BYTE (identical serial and SHA-256).
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return err
	}
	caCertBlock, _ := pem.Decode([]byte(snap.CACertPEM))
	if caCertBlock == nil {
		return fmt.Errorf("snapshot Root CA certificate is not valid PEM")
	}
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse Root CA certificate: %w", err)
	}
	caKeyBlock, _ := pem.Decode([]byte(snap.CAKeyPEM))
	if caKeyBlock == nil {
		return fmt.Errorf("snapshot Root CA key is not valid PEM")
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse Root CA key: %w", err)
	}
	caKey, ok := keyAny.(*ecdsa.PrivateKey)
	if !ok {
		return fmt.Errorf("restored Root CA key is not ECDSA")
	}
	ca := &CA{Cert: caCert, CertDER: caCertBlock.Bytes, Key: caKey}
	if err := ca.SaveToFiles(cfg.caCertPath(), cfg.caKeyPath()); err != nil {
		return err
	}
	log.Printf("Root CA restored | identical fingerprint: %s", ca.Fingerprint())
	if snap.Fingerprint != "" && snap.Fingerprint != ca.Fingerprint() {
		log.Printf("WARNING: restored fingerprint differs from snapshot's recorded fingerprint!")
	}

	// Restore the database (clients, certs, revoked, blacklist).
	st, err := OpenStore(cfg.dbPath())
	if err != nil {
		return err
	}
	if err := st.RestoreSnapshot(&snap); err != nil {
		st.Close()
		return fmt.Errorf("restore snapshot into DB: %w", err)
	}
	log.Printf("state restored: clients, issued certs, revocations and blacklist are now active")

	// Regenerate the signed CRL from the restored revoked set.
	if err := WriteCRL(cfg, ca, st); err != nil {
		log.Printf("WARNING: could not regenerate CRL after promotion: %v", err)
	}

	// Switch config to master mode on the NEW IP.
	newIP := myIPs[0]
	cfg.Mode = "master"
	cfg.MasterAddress = newIP
	cfg.Clients = snap.Clients
	if err := cfg.Save(); err != nil {
		st.Close()
		return err
	}
	if err := RebuildEncryptedCache(cfg, ca, st); err != nil {
		st.Close()
		return fmt.Errorf("rebuild cache after promotion: %w", err)
	}

	// Broadcast the Root-CA-signed migration packet to all clients.
	log.Printf("broadcasting signed migration packet (new master = %s) to %d clients",
		newIP, len(snap.Clients))
	broadcastMigration(ca, newIP, snap.Clients)

	st.Close()
	log.Printf("=== PROMOTION COMPLETE — starting master role ===")
	return RunMaster(cfg)
}

func broadcastMigration(ca *CA, newIP string, clients []string) {
	pkt := &MigrationPacket{NewMasterIP: newIP, IssuedAt: time.Now().UTC()}
	d := migrationDigest(pkt)
	sig, err := ecdsa.SignASN1(randReader(), ca.Key, d[:])
	if err != nil {
		log.Printf("ERROR signing migration packet: %v", err)
		return
	}
	pkt.Signature = sig
	body, _ := json.Marshal(pkt)

	cl := insecureMasterClient()
	for _, c := range clients {
		if host(c) == newIP {
			continue
		}
		url := fmt.Sprintf("https://%s:8443/migrate", host(c))
		req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		if resp, err := cl.Do(req); err == nil {
			resp.Body.Close()
			log.Printf("migration packet delivered to %s", c)
		} else {
			log.Printf("migration delivery to %s failed: %v", c, err)
		}
	}
}

