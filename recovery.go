package main

import (
	"crypto/rand"
	"encoding/base64"
	"errors"

	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

type RecoveryKey struct {
	Private [32]byte
	Public  [32]byte
}

// GenerateRecovery: 256-бит энтропии → 24 слова BIP-39 и X25519-пара.
func GenerateRecovery() (*RecoveryKey, string, error) {
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		return nil, "", err
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return nil, "", err
	}
	rk, err := recoveryFromEntropy(entropy)
	if err != nil {
		return nil, "", err
	}
	return rk, mnemonic, nil
}

func recoveryFromEntropy(entropy []byte) (*RecoveryKey, error) {
	if len(entropy) != 32 {
		return nil, errors.New("recovery entropy must be 32 bytes (24 words)")
	}
	rk := &RecoveryKey{}
	copy(rk.Private[:], entropy)
	pub, err := curve25519.X25519(rk.Private[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	copy(rk.Public[:], pub)
	return rk, nil
}

// RecoveryFromMnemonic: восстановление приватного ключа из сид-фразы.
func RecoveryFromMnemonic(mnemonic string) (*RecoveryKey, error) {
	entropy, err := bip39.EntropyFromMnemonic(mnemonic)
	if err != nil {
		return nil, errors.New("invalid 24-word seed phrase: " + err.Error())
	}
	return recoveryFromEntropy(entropy)
}

func (rk *RecoveryKey) PublicBase64() string {
	return base64.StdEncoding.EncodeToString(rk.Public[:])
}

func RecoveryPublicFromBase64(s string) (*[32]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(raw) != 32 {
		return nil, errors.New("invalid recovery public key")
	}
	var pub [32]byte
	copy(pub[:], raw)
	return &pub, nil
}

// SealKeyToRecovery / OpenKeyWithRecovery — анонимный SealedBox для AES-ключа.
func SealKeyToRecovery(aesKey []byte, pub *[32]byte) ([]byte, error) {
	return box.SealAnonymous(nil, aesKey, pub, rand.Reader)
}

func OpenKeyWithRecovery(sealed []byte, rk *RecoveryKey) ([]byte, error) {
	out, ok := box.OpenAnonymous(nil, sealed, &rk.Public, &rk.Private)
	if !ok {
		return nil, errors.New("recovery key does not match this network cache")
	}
	return out, nil
}
