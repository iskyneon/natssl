package main

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// RunPromote performs a disaster-recovery promotion of this client into a new
// master. It refuses promotion when liveness probes find the old master; the
// operator must also fence it to prevent split-brain. It restores the Root CA byte-for-byte and the LAST replicated
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
	for _, control := range []bool{false, true} {
		addr := strings.TrimPrefix(cfg.masterURL(control, ""), "https://")
		if c, err := net.DialTimeout("tcp", addr, 3*time.Second); err == nil {
			c.Close()
			return fmt.Errorf("OLD MASTER IS ALIVE (%s responds) — promotion aborted", addr)
		}
	}
	oldIPs, err := net.LookupIP(oldIP)
	if err != nil || len(oldIPs) == 0 {
		return fmt.Errorf("cannot resolve old master for safety checks")
	}
	log.Printf("check 2/3: ICMP/ARP reachability of %s", oldIP)
	for _, ip := range oldIPs {
		alive, err := probeICMP(ip.String())
		if err != nil {
			return err
		}
		if alive || arpKnown(ip.String()) {
			return fmt.Errorf("old master %s is reachable — promotion blocked", ip)
		}
	}
	log.Printf("check 3/3: local IP conflict check")
	myIPs, err := localIPv4s()
	if err != nil {
		return err
	}
	for _, old := range oldIPs {
		if old.IsLoopback() {
			return fmt.Errorf("old master resolves to loopback — promotion blocked")
		}
		for _, ip := range myIPs {
			if old.Equal(net.ParseIP(ip)) {
				return fmt.Errorf("local IP conflicts with old master — promotion blocked")
			}
		}
	}
	if len(myIPs) == 0 {
		return fmt.Errorf("no non-loopback IPv4 address available for the new master")
	}

	log.Printf("all safety checks passed")

	ca, clients, err := restoreMasterState(cfg, mnemonic, myIPs[0])
	if err != nil {
		return err
	}
	newIP := myIPs[0]

	// Broadcast the Root-CA-signed migration packet to all clients.
	log.Printf("broadcasting signed migration packet (new master = %s) to %d clients",
		newIP, len(clients))
	go broadcastMigration(ca, newIP, clients)
	log.Printf("=== PROMOTION COMPLETE — starting master role ===")
	return RunMaster(cfg)
}

func broadcastMigration(ca *CA, newIP string, clients []string) {
	pkt := &MigrationPacket{NewMasterIP: newIP, IssuedAt: time.Now().UTC()}

	cl := insecureMasterClient()
	defer cl.CloseIdleConnections()
	for _, c := range clients {
		if host(c) == newIP {
			continue
		}
		url := fmt.Sprintf("https://%s/migrate", net.JoinHostPort(host(c), "8443"))
		pkt.IssuedAt = time.Now().UTC()
		d := migrationDigest(pkt)
		sig, err := ecdsa.SignASN1(randReader(), ca.Key, d[:])
		if err != nil {
			log.Printf("sign migration: %v", err)
			return
		}
		pkt.Signature = sig
		body, err := json.Marshal(pkt)
		if err != nil {
			log.Printf("encode migration: %v", err)
			return
		}
		req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		if resp, err := cl.Do(req); err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				log.Printf("migration packet delivered to %s", c)
			} else {
				log.Printf("migration rejected by %s: HTTP %d", c, resp.StatusCode)
			}
		} else {
			log.Printf("migration delivery to %s failed: %v", c, err)
		}
	}
}

// restoreMasterState verifies the seed, signed snapshot and pinned CA before
// writing recovery state. Liveness checks remain mandatory in RunPromote.
func restoreMasterState(cfg *Config, mnemonic, newIP string) (*CA, []string, error) {
	unlock, err := lockFile(cfg.caKeyPath() + ".promotion.lock")
	if err != nil {
		return nil, nil, err
	}
	defer unlock()
	// Reconstruct the recovery key from the seed phrase.
	rk, err := RecoveryFromMnemonic(strings.TrimSpace(mnemonic))
	if err != nil {
		return nil, nil, err
	}
	cfgPub, err := RecoveryPublicFromBase64(cfg.RecoveryPublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("config has no recovery public key: %w", err)
	}
	if rk.Public != *cfgPub {
		return nil, nil, fmt.Errorf("seed phrase does not match the network's recovery public key")
	}
	log.Printf("recovery key reconstructed and verified against pinned public key")

	// Decrypt the locally stored cache and parse the snapshot.
	ec, err := ReadEncryptedCache(cfg.cachePath())
	if err != nil {
		return nil, nil, fmt.Errorf("no local network cache to recover from: %w", err)
	}
	rootData, err := os.ReadFile(cfg.caCertPath())
	if err != nil {
		return nil, nil, err
	}
	root, err := parseRootCA(rootData)
	if err != nil {
		return nil, nil, err
	}
	if want := normalizeFingerprint(cfg.MasterFingerprint); want != "" && certFingerprint(root.Raw) != want {
		return nil, nil, fmt.Errorf("local Root CA does not match configured pin")
	}
	if err := ec.Verify(root); err != nil {
		return nil, nil, fmt.Errorf("cannot recover unauthenticated cache: %w", err)
	}
	plain, err := DecryptCache(ec, rk)
	if err != nil {
		return nil, nil, err
	}
	var snap Snapshot
	if err := json.Unmarshal(plain, &snap); err != nil {
		return nil, nil, err
	}
	log.Printf("cache decrypted (created %s): %d certs, %d clients, %d revoked, %d blacklisted",
		snap.CreatedAt.Format(time.RFC3339),
		len(snap.Certs), len(snap.Clients), len(snap.Revoked), len(snap.Blacklist))

	// Restore the Root CA BYTE-FOR-BYTE (identical serial and SHA-256).
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return nil, nil, err
	}
	ca, err := LoadCAFromPEM(snap.CACertPEM, snap.CAKeyPEM)
	if err != nil {
		return nil, nil, err
	}
	if snap.Version != 1 || snap.Sequence != ec.Sequence || snap.Fingerprint != ca.Fingerprint() || !ca.Cert.Equal(root) {
		return nil, nil, fmt.Errorf("snapshot Root CA, fingerprint or sequence mismatch")
	}
	if _, err := os.Stat(cfg.caKeyPath()); err == nil {
		return nil, nil, fmt.Errorf("local CA key already exists; refusing to overwrite")
	} else if !os.IsNotExist(err) {
		return nil, nil, err
	}
	if err := ca.SaveToFiles(cfg.caCertPath(), cfg.caKeyPath()); err != nil {
		return nil, nil, err
	}
	log.Printf("Root CA restored | identical fingerprint: %s", ca.Fingerprint())

	// Restore the database (clients, certs, revoked, blacklist).
	st, err := OpenStore(cfg.dbPath())
	if err != nil {
		return nil, nil, err
	}
	if err := st.RestoreSnapshot(&snap); err != nil {
		st.Close()
		return nil, nil, fmt.Errorf("restore snapshot into DB: %w", err)
	}
	log.Printf("state restored: clients, issued certs, revocations and blacklist are now active")

	// Regenerate the signed CRL from the restored revoked set.
	if err := WriteCRL(cfg, ca, st); err != nil {
		st.Close()
		return nil, nil, fmt.Errorf("regenerate CRL after promotion: %w", err)
	}

	// Switch config to master mode on the NEW IP.

	cfg.Mode = "master"
	cfg.MasterAddress = newIP
	cfg.Clients = nil
	cfg.MasterMgmtAddress = ""
	if snap.EnrollmentToken != "" {
		cfg.EnrollmentToken = snap.EnrollmentToken
	}
	cfg.ClientNetworks = snap.ClientNetworks
	if err := cfg.Save(); err != nil {
		st.Close()
		return nil, nil, err
	}
	if err := RebuildEncryptedCache(cfg, ca, st); err != nil {
		st.Close()
		return nil, nil, fmt.Errorf("rebuild cache after promotion: %w", err)
	}

	st.Close()
	return ca, snap.Clients, nil
}
