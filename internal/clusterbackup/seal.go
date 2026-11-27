// SPDX-License-Identifier: Apache-2.0

package clusterbackup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
)

// Recipient is the one-time X25519 key the CLI makes for one backup request.
// Its public half goes into the signed cluster-backup operation, so the
// voter seals the master key to exactly the key the administrator approved.
type Recipient struct{ private *ecdh.PrivateKey }

// NewRecipient makes a fresh one-time key.
func NewRecipient() (Recipient, error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	return Recipient{k}, err
}

// Public is the key to name in the operation.
func (r Recipient) Public() [32]byte {
	var out [32]byte
	copy(out[:], r.private.PublicKey().Bytes())
	return out
}

// SealedMaster is the master key sealed to a Recipient.
type SealedMaster struct {
	Ephemeral [32]byte
	Box       []byte
}

func sealKey(shared []byte, cluster [32]byte, operation string, recipient, ephemeral [32]byte) (cipher.AEAD, []byte, error) {
	info := append([]byte("sfc-cluster-backup-seal-1\x00"), cluster[:]...)
	info = append(info, recipient[:]...)
	info = append(info, ephemeral[:]...)
	info = append(info, operation...)
	key, err := hkdf.Key(sha256.New, shared, nil, string(info), 32)
	if err != nil {
		return nil, nil, err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	return aead, info, err
}

// SealMaster seals master to recipient for one operation. A fresh ephemeral
// key per call makes the zero nonce safe.
func SealMaster(recipient [32]byte, cluster [32]byte, operation string, master []byte) (SealedMaster, error) {
	pub, err := ecdh.X25519().NewPublicKey(recipient[:])
	if err != nil || len(master) != 32 {
		return SealedMaster{}, ErrBackup
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return SealedMaster{}, err
	}
	shared, err := eph.ECDH(pub)
	if err != nil {
		return SealedMaster{}, ErrBackup
	}
	defer clear(shared)
	var out SealedMaster
	copy(out.Ephemeral[:], eph.PublicKey().Bytes())
	aead, info, err := sealKey(shared, cluster, operation, recipient, out.Ephemeral)
	if err != nil {
		return SealedMaster{}, err
	}
	out.Box = aead.Seal(nil, make([]byte, aead.NonceSize()), master, info)
	return out, nil
}

// Open unseals the master key sealed to r.
func (r Recipient) Open(cluster [32]byte, operation string, s SealedMaster) ([]byte, error) {
	pub, err := ecdh.X25519().NewPublicKey(s.Ephemeral[:])
	if err != nil {
		return nil, ErrBackup
	}
	shared, err := r.private.ECDH(pub)
	if err != nil {
		return nil, ErrBackup
	}
	defer clear(shared)
	aead, info, err := sealKey(shared, cluster, operation, r.Public(), s.Ephemeral)
	if err != nil {
		return nil, ErrBackup
	}
	master, err := aead.Open(nil, make([]byte, aead.NonceSize()), s.Box, info)
	if err != nil || len(master) != 32 {
		return nil, ErrBackup
	}
	return master, nil
}
