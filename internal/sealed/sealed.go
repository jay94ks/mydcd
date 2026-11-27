// SPDX-License-Identifier: Apache-2.0

// Package sealed encrypts small private records with a key derived from the
// cluster master key that only current voters hold. Every record kind uses
// its own HKDF info, so keys of different kinds are independent.
package sealed

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
)

// ErrSealed is the only error: callers must not learn why opening failed.
var ErrSealed = errors.New("sealed record unavailable")

const (
	nonceSize = 12
	tagSize   = 16
	// Overhead is the bytes Seal adds to the plain text.
	Overhead = nonceSize + tagSize
)

func aead(master, salt []byte, info string) (cipher.AEAD, error) {
	if len(master) != 32 || len(salt) == 0 || info == "" {
		return nil, ErrSealed
	}
	key, err := hkdf.Key(sha256.New, master, salt, info, 32)
	if err != nil {
		return nil, ErrSealed
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrSealed
	}
	return cipher.NewGCM(block)
}

// Seal returns nonce ‖ AES-256-GCM(K, plain, aad), where
// K = HKDF-SHA256(master, salt, info).
func Seal(master, salt []byte, info string, plain, aad []byte) ([]byte, error) {
	if len(plain) == 0 {
		return nil, ErrSealed
	}
	a, err := aead(master, salt, info)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceSize)
	if _, err = rand.Read(nonce); err != nil {
		return nil, ErrSealed
	}
	return a.Seal(nonce, nonce, plain, aad), nil
}

// Open reverses Seal. The caller clears the result.
func Open(master, salt []byte, info string, sealed, aad []byte) ([]byte, error) {
	if len(sealed) <= Overhead {
		return nil, ErrSealed
	}
	a, err := aead(master, salt, info)
	if err != nil {
		return nil, err
	}
	out, err := a.Open(nil, sealed[:nonceSize], sealed[nonceSize:], aad)
	if err != nil {
		return nil, ErrSealed
	}
	return out, nil
}
