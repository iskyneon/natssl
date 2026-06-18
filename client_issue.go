package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/scrypt"
	"golang.org/x/term"
)

// RunClientIssue: клиент выписывает СЕБЕ сертификат через CSR-flow.
// Приватный ключ генерируется локально и НИКОГДА не покидает машину.
func RunClientIssue(cfg *Config, target string, localhost bool) error {
	// 1. Issuance требует ЖИВОГО мастера: в ReadOnly новые сертификаты блокируются.
	if !tcpHealthy(host(cfg.MasterAddress), 5*time.Second, 443) {
		return fmt.Errorf("master %s is OFFLINE — new issuance blocked (READ-ONLY mode)", cfg.MasterAddress)
	}

	// 2. Локальная генерация приватного ключа.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	// 3. Формирование CSR.
	var dnsNames []string
	var ips []net.IP
	cn := target
	if localhost {
		dnsNames = []string
