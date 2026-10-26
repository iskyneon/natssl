package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

type EncryptedCache struct {
	Version    int    `json:"v"`
	Sequence   uint64 `json:"sequence"`
	Signature  []byte `json:"signature"`
	SealedKey  []byte `json:"sealed_key"` // AES-256-ключ, запечатанный recovery-pub
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"` // AES-GCM(snapshot JSON)
}

// EncryptCache: симметричный AES-GCM-256, ключ запечатан публичным recovery-ключом.
func EncryptCache(plaintext []byte, recoveryPub *[32]byte) (*EncryptedCache, error) {
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return nil, err
	}
	defer clear(aesKey)
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)

	sealed, err := SealKeyToRecovery(aesKey, recoveryPub)
	if err != nil {
		return nil, err
	}
	// Симметричный ключ больше нигде не хранится.
	for i := range aesKey {
		aesKey[i] = 0
	}
	return &EncryptedCache{Version: 1, SealedKey: sealed, Nonce: nonce, Ciphertext: ct}, nil
}

// DecryptCache доступен ТОЛЬКО владельцу recovery-приватного ключа.
func DecryptCache(ec *EncryptedCache, rk *RecoveryKey) ([]byte, error) {
	if ec.Version != 1 {
		return nil, fmt.Errorf("unsupported cache version")
	}
	aesKey, err := OpenKeyWithRecovery(ec.SealedKey, rk)
	if err != nil {
		return nil, err
	}
	defer clear(aesKey)
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ec.Nonce) != gcm.NonceSize() {
		return nil, errors.New("bad nonce")
	}
	return gcm.Open(nil, ec.Nonce, ec.Ciphertext, nil)
}

func (ec *EncryptedCache) WriteFile(path string) error {
	b, err := json.Marshal(ec)
	if err != nil {
		return err
	}
	return atomicWriteFile(path, b, 0o600)
}

func ReadEncryptedCache(path string) (*EncryptedCache, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	ec := &EncryptedCache{}
	return ec, json.Unmarshal(b, ec)
}

func (ec *EncryptedCache) digest() [32]byte {
	copy := *ec
	copy.Signature = nil
	data, _ := json.Marshal(copy)
	return sha256.Sum256(append([]byte("natssl-cache-v1|"), data...))
}
func (ec *EncryptedCache) Sign(ca *CA) error {
	d := ec.digest()
	sig, err := ecdsa.SignASN1(rand.Reader, ca.Key, d[:])
	ec.Signature = sig
	return err
}
func (ec *EncryptedCache) Verify(ca *x509.Certificate) error {
	if ec.Version != 1 || ec.Sequence == 0 || len(ec.Nonce) != 12 || len(ec.SealedKey) != 80 || len(ec.Ciphertext) < 16 {
		return fmt.Errorf("invalid signed cache envelope")
	}
	pub, ok := ca.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("Root CA is not ECDSA")
	}
	d := ec.digest()
	if !ecdsa.VerifyASN1(pub, d[:], ec.Signature) {
		return fmt.Errorf("invalid cache signature")
	}
	return nil
}

// Clients cannot decrypt snapshots, so authenticate their signed envelope and
// persist the monotonic sequence together with the ciphertext in one rename.
func acceptCache(cfg *Config, data []byte) error {
	rootData, err := os.ReadFile(cfg.caCertPath())
	if err != nil {
		return err
	}
	root, err := parseRootCA(rootData)
	if err != nil {
		return err
	}
	var ec EncryptedCache
	if err := json.Unmarshal(data, &ec); err != nil {
		return err
	}
	if err := ec.Verify(root); err != nil {
		return err
	}
	unlock, err := lockFile(cfg.cachePath() + ".lock")
	if err != nil {
		return err
	}
	defer unlock()
	previous, err := ReadEncryptedCache(cfg.cachePath())
	if err == nil {
		if err := previous.Verify(root); err != nil && !(previous.Sequence == 0 && len(previous.Signature) == 0) {
			return fmt.Errorf("existing cache invalid: %w", err)
		}
		if ec.Sequence < previous.Sequence {
			return fmt.Errorf("stale cache sequence %d (current %d)", ec.Sequence, previous.Sequence)
		}
		if ec.Sequence == previous.Sequence {
			return nil
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return atomicWriteFile(cfg.cachePath(), data, 0o600)
}
