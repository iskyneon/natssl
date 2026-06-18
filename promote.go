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

func RunPromote(cfg *Config, mnemonic string) error {
	log.Printf("=== DISASTER RECOVERY PROMOTION START ===")

	oldIP := host(cfg.MasterAddress)
	if oldIP == "" {
		return fmt.Errorf("no old master address in config")
	}

	// --- ПРОВЕРКА 1: живучесть старого УЦ (TCP 443/8443). ---
	log.Printf("check 1/3: TCP health of old master %s", oldIP)
	if tcpHealthy(oldIP, 3*time.Second, 443) || tcpHealthy(oldIP, 3*time.Second, 8443) {
		return fmt.Errorf("OLD MASTER IS ALIVE (443/8443 responds) — promotion aborted to prevent split-brain")
	}

	// --- ПРОВЕРКА 2: L2/L3 — ICMP ping + ARP-таблица. ---
	log.Printf("check 2/3: ICMP/ARP reachability of %s", oldIP)
	if icmpAlive(oldIP) || arpKnown(oldIP) {
		return fmt.Errorf("old master IP %s answers at network layer (ICMP/ARP) — promotion blocked", oldIP)
	}

	// --- ПРОВЕРКА 3: конфликт собственного IP. ---
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

	// --- Восстановление recovery-ключа из сид-фразы. ---
	rk, err := RecoveryFromMnemonic(strings.TrimSpace(mnemonic))
	if err != nil {
		return err
	}
	// Сверка с локально вшитым публичным ключом.
	cfgPub, err := RecoveryPublicFromBase64(cfg.RecoveryPublicKey)
	if err != nil {
		return fmt.Errorf("config has no recovery public key: %w", err)
	}
	if rk.Public != *cfgPub {
		return fmt.Errorf("seed phrase does not match the network's recovery public key")
	}
	log.Printf("recovery key reconstructed and verified against pinned public key")

	// --- Расшифровка локального кэша и восстановление БД. ---
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
	log.Printf("cache decrypted: %d certificates, %d clients", len(snap.Certificates), len(snap.Clients))

	// --- Восстановление Root CA БАЙТ-В-БАЙТ (идентичный serial и SHA-256). ---
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return err
	}
	caCert, _ := x509.ParseCertificate(snap.CACertDER)
	keyAny, _ := x509.ParsePKCS8PrivateKey(snap.CAKeyPKCS8)
	ca := &CA{Cert: caCert, CertDER: snap.CACertDER, Key: keyAny.(*ecdsa.PrivateKey)}
	if err := ca.SaveToFiles(cfg.caCertPath(), cfg.caKeyPath()); err != nil {
		return err
	}
	log.Printf("Root CA restored | identical fingerprint: %s", ca.Fingerprint())

	st, err := OpenStore(cfg.dbPath())
	if err != nil {
		return err
	}
	if err := st.RestoreSnapshot(&snap); err != nil {
		st.Close()
		return err
	}

	// --- Переключение конфигурации в режим master на НОВОМ IP. ---
	newIP := myIPs[0]
	cfg.Mode = "master"
	cfg.MasterAddress = newIP
	cfg.Clients = snap.Clients
	if err := cfg.Save(); err != nil {
		st.Close()
		return err
	}
	RebuildEncryptedCache(cfg, ca, st)

	// --- Веерная P2P-рассылка пакета миграции, подписанного Root CA. ---
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

// удобный re-export для подписи
func pemDecodeFirst(b []byte) *pem.Block { blk, _ := pem.Decode(b); return blk }
