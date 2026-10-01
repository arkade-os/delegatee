// Package ecies seals a secret to a public key.
//
//	ciphertext = ephemeralPub[33 compressed] || nonce[12] || AES-256-GCM(plaintext, key, nonce, aad=ephemeralPub)
//	key        = HKDF-SHA256(ikm=sharedX, salt=ephemeralPub, info="covclaimd/preimage/v1", 32 bytes)
//	sharedX    = the 32-byte x coordinate of ephemeralPriv*recipientPub (== recipientPriv*ephemeralPub)
package ecies

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/btcec/v2"
)

const (
	pubKeyLen = 33
	nonceLen  = 12
	gcmTagLen = 16
	minLen    = pubKeyLen + nonceLen + gcmTagLen
	hkdfInfo  = "covclaimd/preimage/v1"
)

// Encrypt seals plaintext with a random ephemeral key and nonce.
func Encrypt(to *btcec.PublicKey, plaintext []byte) ([]byte, error) {
	if to == nil {
		return nil, fmt.Errorf("ecies: recipient public key is nil")
	}

	ephPriv, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("ecies: generate ephemeral key: %w", err)
	}
	ephPub := ephPriv.PubKey().SerializeCompressed()

	key, err := deriveKey(ephPriv, to, ephPub)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("ecies: generate nonce: %w", err)
	}

	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, pubKeyLen+nonceLen+len(plaintext)+gcmTagLen)
	out = append(out, ephPub...)
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, plaintext, ephPub)
	return out, nil
}

// Decrypt opens a ciphertext sealed by Encrypt to key's public key.
func Decrypt(key *btcec.PrivateKey, ciphertext []byte) ([]byte, error) {
	if key == nil {
		return nil, fmt.Errorf("ecies: private key is nil")
	}
	if len(ciphertext) < minLen {
		return nil, fmt.Errorf("ecies: ciphertext too short: got %d bytes, need at least %d", len(ciphertext), minLen)
	}

	ephPubBytes := ciphertext[:pubKeyLen]
	nonce := ciphertext[pubKeyLen : pubKeyLen+nonceLen]
	ct := ciphertext[pubKeyLen+nonceLen:]

	ephPub, err := btcec.ParsePubKey(ephPubBytes)
	if err != nil {
		return nil, fmt.Errorf("ecies: invalid ephemeral public key: %w", err)
	}

	symKey, err := deriveKey(key, ephPub, ephPubBytes)
	if err != nil {
		return nil, err
	}

	aead, err := newAEAD(symKey)
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, nonce, ct, ephPubBytes)
	if err != nil {
		return nil, fmt.Errorf("ecies: decrypt: %w", err)
	}
	return plaintext, nil
}

// DecryptAny tries each key in order, so a ciphertext sealed to a superseded key still opens.
func DecryptAny(keys []*btcec.PrivateKey, ciphertext []byte) ([]byte, error) {
	for _, key := range keys {
		if plaintext, err := Decrypt(key, ciphertext); err == nil {
			return plaintext, nil
		}
	}
	return nil, fmt.Errorf("ecies: no key opens the ciphertext, tried %d", len(keys))
}

// deriveKey is symmetric: (ephPriv, recipientPub) encrypts, (recipientPriv, ephPub) decrypts.
func deriveKey(priv *btcec.PrivateKey, pub *btcec.PublicKey, salt []byte) ([]byte, error) {
	key, err := hkdf.Key(sha256.New, btcec.GenerateSharedSecret(priv, pub), salt, hkdfInfo, 32)
	if err != nil {
		return nil, fmt.Errorf("ecies: derive key: %w", err)
	}
	return key, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("ecies: aes cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("ecies: gcm: %w", err)
	}
	return aead, nil
}
