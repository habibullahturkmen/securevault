package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// nonceSize is the standard AES-GCM nonce length: 96 bits.
const nonceSize = 12

// dekSize is the per-object data-encryption key length: AES-256.
const dekSize = 32

// newDEK returns a fresh random 32-byte data-encryption key.
func newDEK() ([]byte, error) {
	dek := make([]byte, dekSize)
	if _, err := rand.Read(dek); err != nil {
		return nil, fmt.Errorf("storage: generate DEK: %w", err)
	}
	return dek, nil
}

// wrapDEK encrypts a DEK under the KEK with AES-256-GCM. The content hash is
// bound in as associated data, so a wrapped key cannot be replayed for a
// different object. Layout: nonce || ciphertext+tag.
func wrapDEK(kek, dek, aad []byte) ([]byte, error) {
	gcm, err := newGCM(kek)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("storage: generate wrap nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, dek, aad), nil
}

// unwrapDEK reverses wrapDEK, authenticating against the same associated data.
func unwrapDEK(kek, wrapped, aad []byte) ([]byte, error) {
	gcm, err := newGCM(kek)
	if err != nil {
		return nil, err
	}
	if len(wrapped) < nonceSize {
		return nil, errors.New("storage: wrapped DEK too short")
	}
	return gcm.Open(nil, wrapped[:nonceSize], wrapped[nonceSize:], aad)
}

// encrypt seals plaintext under the DEK with a fresh 96-bit nonce, binding
// the content hash as associated data. Returns the nonce and ciphertext+tag
// separately for the object file layout.
func encrypt(dek, plaintext, aad []byte) (nonce, sealed []byte, err error) {
	gcm, err := newGCM(dek)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("storage: generate content nonce: %w", err)
	}
	return nonce, gcm.Seal(nil, nonce, plaintext, aad), nil
}

// decrypt opens ciphertext+tag, failing if the tag or associated data does
// not authenticate.
func decrypt(dek, nonce, sealed, aad []byte) ([]byte, error) {
	gcm, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, sealed, aad)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("storage: init cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("storage: init GCM: %w", err)
	}
	return gcm, nil
}
