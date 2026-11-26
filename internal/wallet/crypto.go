// SPDX-License-Identifier: Apache-2.0

package wallet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"

	"golang.org/x/crypto/argon2"
)

func walletAEAD(password []byte, salt [16]byte) (cipher.AEAD, error) {
	if len(password) < 1 || len(password) > 1024 {
		return nil, ErrWallet
	}
	key := argon2.IDKey(password, salt[:], Iterations, MemoryKiB, Threads, 32)
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrWallet
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrWallet
	}
	return aead, nil
}

// Seal uses fresh salt/nonce for every save. All header bytes are authenticated.
func Seal(password []byte, entries []Entry) ([]byte, error) {
	if len(password) < 1 || len(password) > 1024 {
		return nil, ErrWallet
	}
	plain, err := EncodePayload(entries)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	h := Header{CipherLength: uint32(len(plain) + 16)}
	if _, err = rand.Read(h.Salt[:]); err != nil {
		return nil, ErrWallet
	}
	if _, err = rand.Read(h.Nonce[:]); err != nil {
		return nil, ErrWallet
	}
	header, err := h.Encode()
	if err != nil {
		return nil, err
	}
	aead, err := walletAEAD(password, h.Salt)
	if err != nil {
		return nil, err
	}
	return aead.Seal(header, h.Nonce[:], plain, header), nil
}

// Unseal rejects invalid format/cost/length before KDF and returns no partial key
// set for a wrong password, authentication failure, or malformed plaintext.
func Unseal(password, raw []byte) ([]Entry, error) {
	h, err := DecodeHeader(raw)
	if err != nil {
		return nil, err
	}
	aead, err := walletAEAD(password, h.Salt)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, h.Nonce[:], raw[HeaderSize:], raw[:HeaderSize])
	if err != nil {
		return nil, ErrWallet
	}
	defer clear(plain)
	return DecodePayload(plain)
}
