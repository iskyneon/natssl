package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

var masterAvailable atomic.Bool

func RunClient(cfg *Config) error {
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return err
	}

	// 1. Скачать и установить Root CA в ОС и Firefox (нужны права root).
	if err := fetchAndInstallRootCA(cfg); err != nil {
		log.Printf("WARN: root CA install: %v", err)
	}

	// 2. HTTP-сервер 8443: приём зашифрованного кэша и пакетов миграции.
	mux := http.NewServeMux()
	mux.HandleFunc("/cache/push", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		// Критично: клиент НЕ может расшифровать — просто сохраняет «мёртвым грузом».
		os.WriteFile(cfg.cachePath(), body, 0o600)
		w.Write([]byte("stored"))
		log.Printf("encrypted network cache stored (%d bytes, undecryptable on client)", len(body))
	})
	mux.HandleFunc("/migrate", func(w http.ResponseWriter, r *http.Request) {
		var pkt MigrationPacket
		if err := json.NewDecoder(r.Body).Decode(&pkt); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if err := applyMigration(cfg, &pkt); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		w.Write([]byte("master updated"))
	})
	go func() {
		srv := &http.Server{
			Addr:      ":8443",
			Handler:   mux,
			TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		}
		// Самоподписанный серверный сертификат клиента (для приёма push).
		certFile, keyFile := ensureClientServerCert(cfg)
		log.Printf("client sync listener on :8443")
		if err := srv.ListenAndServeTLS(certFile, keyFile); err != nil {
			log.Printf("client listener stopped: %v", err)
		}
	}()

	// 3. Ping мастера каждые ping_interval; ReadOnly при недоступности.
	t := time.NewTicker(cfg.PingInterval)
	defer t.Stop()
	pingMaster(cfg)
	for range t.C {
		pingMaster(cfg)
		// Pull-модель: забираем кэш раз в час (упрощённо — при доступности).
		if masterAvailable.Load() {
			pullCache(cfg)
		}
	}
	return nil
}

func pingMaster(cfg *Config) {
	ok := tcpHealthy(cfg.MasterAddress, 5*time.Second, 443) ||
		tcpHealthy(cfg.MasterAddress, 5*time.Second, 8443)
	prev := masterAvailable.Swap(ok)
	if ok && !prev {
		log.Printf("master %s ONLINE — full operation restored", cfg.MasterAddress)
	}
	if !ok && prev {
		// ВАЖНО: Root CA не удаляется. Старые сертификаты остаются доверенными.
		log.Printf("master %s DOWN — entering READ-ONLY mode "+
			"(existing certs still trusted, new issuance blocked)", cfg.MasterAddress)
	}
}

func fetchAndInstallRootCA(cfg *Config) error {
	client := insecureBootstrapClient() // первый контакт: CA ещё не в системе
	resp, err := client.Get(fmt.Sprintf("https://%s:443/ca", host(cfg.MasterAddress)))
	if err != nil {
		// возможно, CA уже стоит локально — не критично
		return err
	}
	defer resp.Body.Close()
	pemBytes, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(pemBytes), "BEGIN CERTIFICATE") {
		return fmt.Errorf("master did not return a valid CA certificate")
	}
	return InstallRootCA(pemBytes)
}

func pullCache(cfg *Config) {
	client := insecureMasterClient()
	resp, err := client.Get(fmt.Sprintf("https://%s:443/cache", host(cfg.MasterAddress)))
	if err != nil {
		return
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if len(data) > 0 {
		os.WriteFile(cfg.cachePath(), data, 0o600)
	}
}

// ---- Приём пакета миграции при аварийном промоушене нового мастера ----

type MigrationPacket struct {
	NewMasterIP string    `json:"new_master_ip"`
	IssuedAt    time.Time `json:"issued_at"`
	Signature   []byte    `json:"signature"` // ECDSA(SHA-256(payload)) ключом Root CA
}

func migrationDigest(p *MigrationPacket) [32]byte {
	return sha256.Sum256([]byte(p.NewMasterIP + "|" + p.IssuedAt.UTC().Format(time.RFC3339)))
}

func applyMigration(cfg *Config, pkt *MigrationPacket) error {
	// Верификация подписи тем Root CA, который уже стоит в ОС клиента.
	caCert, err := LoadInstalledRootCA()
	if err != nil {
		return fmt.Errorf("cannot load installed Root CA: %w", err)
	}
	pub, ok := caCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("Root CA key is not ECDSA")
	}
	d := migrationDigest(pkt)
	if !ecdsa.VerifyASN1(pub, d[:], pkt.Signature) {
		return fmt.Errorf("migration packet signature INVALID — rejected")
	}
	// Подпись валидна — перезаписываем IP мастера в конфиге.
	cfg.MasterAddress = pkt.NewMasterIP
	if err := cfg.Save(); err != nil {
		return err
	}
	log.Printf("MIGRATION ACCEPTED: master IP updated to %s", pkt.NewMasterIP)
	return nil
}

func ensureClientServerCert(cfg *Config) (string, string) {
	cp := cfg.DataDir + "/client-server.crt"
	kp := cfg.DataDir + "/client-server.key"
	if _, err := os.Stat(cp); err == nil {
		return cp, kp
	}
	// Самоподписанный, только для транспортного приёма push.
	tmp, _ := BootstrapCA()
	tmp.SaveToFiles(cp, kp)
	return cp, kp
}
