package main

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

func RunPromote(cfg *Config, mnemonic string) error {
	log.Printf("=== DISASTER RECOVERY PROMOTION START ===")

	oldIP := host(cfg.MasterAddress)
	if oldIP == "" {
		return fmt.Errorf("no old master address in config")
	}

	// CHECK 1: liveness of the old master (TCP 443/8443).
	log.Printf("check 1/3: TCP health of old master %s", oldIP)
	if tcpHealthy(oldIP, 3*time.Second, 443) || tcpHealthy(oldIP, 3*time.Second, 8443) {
		return fmt.Errorf("OLD MASTER IS ALIVE (443/8443 responds) — promotion aborted to prevent split-brain")
	}

	// CHECK 2: L2/L3 — ICMP ping + ARP table.
	log.Printf("check 2/3: ICMP/ARP reachability of %s", oldIP)
	if icmpAlive(oldIP) || arpKnown(oldIP) {
		return fmt.Errorf("old master IP %s answers at the network layer (ICMP/ARP) — promotion blocked", oldIP)
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

	// Reconstruct the recovery key and verify against the pinned public key.
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
	log.Printf("recovery key reconstructed and verified against the pinned public key")

	// Decrypt the local cache and parse the snapshot.
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
	log.Printf("cache decrypted: snapshot v%d, %d certificates, %d clients",
		snap.Version, len(snap.Certs), len(snap.Clients))

	// Restore the Root CA byte-for-byte (identical serial & SHA-256).
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return err
	}
	ca, err := LoadCAFromPEM(snap.CACertPEM, snap.CAKeyPEM)
	if err != nil {
		return fmt.Errorf("rebuild CA from snapshot: %w", err)
	}

	// Integrity gate: restored fingerprint MUST equal the pinned one.
	if want := normalizeFingerprint(cfg.MasterFingerprint); want != "" {
		if normalizeFingerprint(ca.Fingerprint()) != want {
			return fmt.Errorf("restored CA fingerprint mismatch — refusing to promote")
		}
	}
	if err := ca.SaveToFiles(cfg.caCertPath(), cfg.caKeyPath()); err != nil {
		return err
	}
	if err := ensureServerCert(cfg, ca); err != nil {
		return err
	}
	log.Printf("Root CA restored | identical fingerprint: %s", ca.Fingerprint())

	// Transactionally restore the database.
	st, err := OpenStore(cfg.dbPath())
	if err != nil {
		return err
	}
	if err := st.RestoreSnapshot(&snap); err != nil {
		st.Close()
		return fmt.Errorf("restore snapshot: %w", err)
	}

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
		return err
	}

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
