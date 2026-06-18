package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
)

type EncryptedCache struct {
	Version    int    `json:"v"`
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
	aesKey, err := OpenKeyWithRecovery(ec.SealedKey, rk)
	if err != nil {
		return nil, err
	}
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
	return os.WriteFile(path, b, 0o600)
}

func ReadEncryptedCache(path string) (*EncryptedCache, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	ec := &EncryptedCache{}
	return ec, json.Unmarshal(b, ec)
}
