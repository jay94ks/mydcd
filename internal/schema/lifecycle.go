// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// Lifecycle reserves shared resources through Drain. A node's signed proof of
// terminal local absence is required before the reservation can be released.
type Lifecycle struct {
	Drain bool
	Nonce [16]byte
	Proof []byte
}

func (l Lifecycle) Released() bool { return l.Drain && len(l.Proof) == ed25519.SignatureSize }
func (l Lifecycle) Valid() bool {
	if !l.Drain {
		return l.Nonce == [16]byte{} && len(l.Proof) == 0
	}
	return l.Nonce != [16]byte{} && (len(l.Proof) == 0 || len(l.Proof) == ed25519.SignatureSize)
}
func GoneBytes(cluster [32]byte, key string, generation uint64, valueWithoutProof []byte) []byte {
	return GoneDigestBytes(cluster, key, generation, sha256.Sum256(valueWithoutProof))
}

// GoneDigestBytes preserves the original signature bytes while allowing a
// reader to verify a terminal fact without receiving the private native spec.
func GoneDigestBytes(cluster [32]byte, key string, generation uint64, digest [32]byte) []byte {
	b := append([]byte("sfc-local-retirement-1"), cluster[:]...)
	b = binary.LittleEndian.AppendUint64(b, uint64(len(key)))
	b = append(b, key...)
	b = binary.LittleEndian.AppendUint64(b, generation)
	return append(b, digest[:]...)
}
func VerifyGone(pub [32]byte, cluster [32]byte, key string, generation uint64, valueWithoutProof, signature []byte) error {
	if generation == 0 || !ed25519.Verify(pub[:], GoneBytes(cluster, key, generation, valueWithoutProof), signature) {
		return errors.New("invalid local retirement proof")
	}
	return nil
}
