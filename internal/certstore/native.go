// SPDX-License-Identifier: Apache-2.0

package certstore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/jay94ks/mydcd/internal/storage"
	bolt "go.etcd.io/bbolt"
)

var nativeBucket = []byte("certificate-native-2")

// commitWindow bounds how long after UploadedAt a prepared certificate can
// still commit (Catalog.Put allows 120 seconds), with slack for clock skew.
const commitWindow = 600

type Native struct {
	DB       *storage.DB
	Cluster  [32]byte
	Identity ed25519.PrivateKey
}
type nativeRecord struct {
	Schema                 uint8
	Cluster, Owner, Digest [32]byte
	User, Request          string
	Version                Certificate
	Retired                bool
}

func (n Native) owner() [32]byte {
	var p [32]byte
	if len(n.Identity) == ed25519.PrivateKeySize {
		copy(p[:], n.Identity.Public().(ed25519.PublicKey))
	}
	return p
}
func (n Native) valid() bool {
	return n.DB != nil && n.Cluster != ([32]byte{}) && n.owner() != ([32]byte{})
}
func requestKey(user, request string) []byte {
	h := sha256.Sum256([]byte(user + "\x00" + request))
	return []byte("request/" + hex.EncodeToString(h[:]))
}
func (n Native) Recover(user, request string) (Certificate, error) {
	if !n.valid() {
		return Certificate{}, ErrCertificate
	}
	var record nativeRecord
	err := n.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(nativeBucket)
		if b == nil {
			return storage.ErrMissing
		}
		raw := b.Get(requestKey(user, request))
		if raw == nil {
			return storage.ErrMissing
		}
		return json.Unmarshal(raw, &record)
	})
	if err != nil {
		return Certificate{}, err
	}
	if record.Schema != 1 || record.Cluster != n.Cluster || record.Owner != n.owner() || record.User != user || record.Request != request || record.Retired || record.Version.Validate() != nil || record.Digest != record.Version.Digest() {
		return Certificate{}, ErrCertificate
	}
	if err = n.DB.Sync(); err != nil {
		return Certificate{}, err
	}
	return record.Version, nil
}

// Prepare durably stores the public receipt of an upload, sealed with key
// (the key derived for this certificate), before it is exposed. Recovery
// reads that same fact without accepting key bytes. No key is kept here:
// a voter derives it again from the master key.
func (n Native) Prepare(user, request string, at int64, material Material, key []byte) (Certificate, error) {
	if !n.valid() {
		return Certificate{}, ErrCertificate
	}
	if old, err := n.Recover(user, request); err == nil {
		if !bytes.Equal(old.Chain, material.Chain) {
			return Certificate{}, ErrConflict
		}
		if _, err = tls.X509KeyPair(material.Chain, material.Key); err != nil {
			return Certificate{}, ErrCertificate
		}
		return old, nil
	} else if !errors.Is(err, storage.ErrMissing) {
		return Certificate{}, err
	}
	v, err := Seal(n.Cluster, user, request, at, material, key, n.Identity)
	if err != nil {
		return Certificate{}, err
	}
	record := nativeRecord{Schema: 1, Cluster: n.Cluster, Owner: n.owner(), Digest: v.Digest(), User: user, Request: request, Version: v}
	raw, err := json.Marshal(record)
	if err != nil {
		return Certificate{}, err
	}
	err = n.DB.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(nativeBucket)
		if err != nil {
			return err
		}
		if b.Get(requestKey(user, request)) != nil {
			return ErrConflict
		}
		return b.Put(requestKey(user, request), raw)
	})
	if err != nil {
		return Certificate{}, err
	}
	return v, nil
}

// Sweep retires the upload receipts of certificates that left the store. A
// prepared certificate not yet in the store survives until it can no longer
// commit (commitWindow after UploadedAt) or expires.
func (n Native) Sweep(c Catalog, at int64) error {
	if !n.valid() || c.Validate() != nil || c.Cluster != n.Cluster {
		return ErrCertificate
	}
	return n.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(nativeBucket)
		if b == nil {
			return nil
		}
		cursor := b.Cursor()
		for k, raw := cursor.First(); k != nil; k, raw = cursor.Next() {
			var record nativeRecord
			if json.Unmarshal(raw, &record) != nil || record.Schema != 1 || record.Cluster != n.Cluster || record.Owner != n.owner() {
				return ErrCertificate
			}
			if record.Retired {
				continue
			}
			m := record.Version.Metadata
			e, stored := c.Entry(m.ID)
			stored = stored && e.Certificate.Digest() == record.Digest
			expired := at >= m.NotAfter
			if !expired && (stored || at <= m.UploadedAt+commitWindow) {
				continue
			}
			record.Version.Chain = nil
			record.Version.SealedKey = nil
			record.Retired = true
			encoded, err := json.Marshal(record)
			if err != nil {
				return err
			}
			if err = b.Put(k, encoded); err != nil {
				return err
			}
		}
		return nil
	})
}
