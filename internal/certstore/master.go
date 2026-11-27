// SPDX-License-Identifier: Apache-2.0

package certstore

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"

	"github.com/jay94ks/seafield/internal/storage"
	"github.com/jay94ks/seafield/internal/wallet"
	bolt "go.etcd.io/bbolt"
)

// The cluster certificate master key (32 bytes) lives only in the native
// store of current voters, sealed with each holder's installation
// identity. It never enters Raft. Each certificate key is derived from it:
//
//	K = HKDF-SHA256(master, salt = certificate ID, info = MasterInfo)
const MasterInfo = "sfc/certificate/v1"

var masterBucket = []byte("certificate-master-1")
var masterName = []byte("master")

type masterRecord struct {
	Schema         uint8
	Cluster, Owner [32]byte
	Key            []byte
}

// Derive returns the key of certificate id. The caller clears it.
func Derive(master []byte, id ID) ([]byte, error) {
	if len(master) != 32 || id == (ID{}) {
		return nil, ErrCertificate
	}
	return hkdf.Key(sha256.New, master, id[:], MasterInfo, 32)
}

// Master returns this holder's master key (storage.ErrMissing when it has
// none). The caller clears it.
func (n Native) Master() ([]byte, error) {
	if !n.valid() {
		return nil, ErrCertificate
	}
	var sealed []byte
	err := n.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(masterBucket)
		if b == nil || b.Get(masterName) == nil {
			return storage.ErrMissing
		}
		sealed = bytes.Clone(b.Get(masterName))
		return nil
	})
	if err != nil {
		return nil, err
	}
	seed := n.Identity.Seed()
	defer clear(seed)
	entries, err := wallet.Unseal(seed, sealed)
	if err != nil {
		return nil, ErrCertificate
	}
	defer wallet.Clear(entries)
	if len(entries) != 1 || entries[0].Name != "certificate-master" {
		return nil, ErrCertificate
	}
	var record masterRecord
	if json.Unmarshal(entries[0].Record, &record) != nil || record.Schema != 1 || record.Cluster != n.Cluster || record.Owner != n.owner() || len(record.Key) != 32 {
		clear(record.Key)
		return nil, ErrCertificate
	}
	return record.Key, nil
}

// HasMaster reports whether a master envelope is stored, without opening
// it (opening runs the wallet key derivation).
func (n Native) HasMaster() bool {
	found := false
	if n.valid() {
		_ = n.DB.View(func(tx *bolt.Tx) error {
			b := tx.Bucket(masterBucket)
			found = b != nil && b.Get(masterName) != nil
			return nil
		})
	}
	return found
}

// InstallMaster stores a master key received from a current voter. A
// holder that already has a different key refuses it.
func (n Native) InstallMaster(key []byte) error {
	if !n.valid() || len(key) != 32 {
		return ErrCertificate
	}
	if old, err := n.Master(); err == nil {
		same := bytes.Equal(old, key)
		clear(old)
		if !same {
			return ErrConflict
		}
		return nil
	} else if !errors.Is(err, storage.ErrMissing) {
		return err
	}
	raw, err := json.Marshal(masterRecord{1, n.Cluster, n.owner(), key})
	if err != nil {
		return ErrCertificate
	}
	defer clear(raw)
	seed := n.Identity.Seed()
	defer clear(seed)
	sealed, err := wallet.Seal(seed, []wallet.Entry{{Name: "certificate-master", Record: raw}})
	if err != nil {
		return ErrCertificate
	}
	return n.DB.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(masterBucket)
		if err != nil {
			return err
		}
		if b.Get(masterName) != nil {
			return ErrConflict
		}
		return b.Put(masterName, sealed)
	})
}

// GenerateMaster makes the cluster's master key. Only cluster init calls
// it, once, on the first voter.
func (n Native) GenerateMaster() error {
	key := make([]byte, 32)
	defer clear(key)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	return n.InstallMaster(key)
}

// EraseMaster removes this holder's master key (a demoted or removed
// voter).
func (n Native) EraseMaster() error {
	if !n.valid() {
		return ErrCertificate
	}
	return n.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(masterBucket)
		if b == nil {
			return nil
		}
		return b.Delete(masterName)
	})
}

// SealRequest asks a voter for the key of a certificate that is not yet in
// the store, so a member that is not a voter can seal an upload. Proof is a
// signature by the certificate's own private key over SealRequestBytes: the
// requester already holds that key, so the derived key tells it nothing
// new.
type SealRequest struct {
	Schema          uint8
	Cluster, Member [32]byte
	ID              ID
	Leaf            []byte
	At              int64
	Proof           []byte
}

func SealRequestBytes(q SealRequest) []byte {
	q.Proof = nil
	raw, _ := json.Marshal(q)
	digest := sha256.Sum256(append([]byte("sfc-certificate-seal-1\x00"), raw...))
	return digest[:]
}

// SignSealRequest signs q with the certificate private key.
func SignSealRequest(q SealRequest, key crypto.Signer) (SealRequest, error) {
	digest := SealRequestBytes(q)
	var err error
	if _, ok := key.Public().(*rsa.PublicKey); ok {
		q.Proof, err = key.Sign(rand.Reader, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	} else {
		q.Proof, err = key.Sign(rand.Reader, digest, crypto.SHA256)
	}
	if err != nil {
		return SealRequest{}, ErrCertificate
	}
	return q, nil
}

// Verify checks the leaf, its ID and the possession proof. Freshness and
// the requester's membership are the caller's checks.
func (q SealRequest) Verify(cluster [32]byte) error {
	if q.Schema != 1 || q.Cluster != cluster || q.Member == ([32]byte{}) || sha256.Sum256(q.Leaf) != q.ID || len(q.Proof) == 0 || len(q.Proof) > 1024 {
		return ErrCertificate
	}
	leaf, err := x509.ParseCertificate(q.Leaf)
	if err != nil {
		return ErrCertificate
	}
	digest := SealRequestBytes(q)
	switch pub := leaf.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, digest, q.Proof) {
			return ErrCertificate
		}
	case *rsa.PublicKey:
		if rsa.VerifyPSS(pub, crypto.SHA256, digest, q.Proof, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) != nil {
			return ErrCertificate
		}
	default:
		return ErrCertificate
	}
	return nil
}
