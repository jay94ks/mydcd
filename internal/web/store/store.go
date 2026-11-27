// SPDX-License-Identifier: Apache-2.0

// Package store keeps the web daemon's own auxiliary records in one bbolt
// file. sfcd stays the authority for cluster state; deleting this file does
// not change the cluster. Passwords, tokens, private keys, session keys and
// Vault values are never stored here.
package store

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	bolt "go.etcd.io/bbolt"
)

// SchemaVersion is the web DB schema version.
const SchemaVersion = 1

var (
	bucketMeta        = []byte("meta")
	bucketOps         = []byte("ops")
	bucketOpsByState  = []byte("ops-by-state")
	bucketSessions    = []byte("sessions")
	bucketArchived    = []byte("archived")
	bucketGraphLayout = []byte("graph-layout")
	bucketPrefs       = []byte("prefs")
	bucketSettings    = []byte("web-settings")
	bucketAudit       = []byte("web-audit")
	bucketNotify      = []byte("notifications")
	bucketNotifyPrefs = []byte("notify-prefs")
	bucketDNSProv     = []byte("dns-providers")
	bucketDNSDomains  = []byte("dns-domains")
	bucketDNSManaged  = []byte("dns-managed")
	bucketDNSHistory  = []byte("dns-history")
	bucketACMEAcct    = []byte("acme-accounts")
	bucketACMECerts   = []byte("acme-certs")
	bucketACMEOrders  = []byte("acme-orders")
	bucketSaOrigins   = []byte("standalone-origins")

	allBuckets = [][]byte{bucketMeta, bucketOps, bucketOpsByState, bucketSessions, bucketArchived, bucketGraphLayout, bucketPrefs,
		bucketSettings, bucketAudit, bucketNotify, bucketNotifyPrefs,
		bucketDNSProv, bucketDNSDomains, bucketDNSManaged, bucketDNSHistory, bucketDNSServers, bucketACMEAuto,
		bucketACMEAcct, bucketACMECerts, bucketACMEOrders, bucketSaOrigins,
		bucketAIConfig, bucketAICatalog, bucketAIUsage, bucketAIAudit, bucketAIConversations, bucketAIProposals,
		bucketIncidents, bucketIncidentPolicy, bucketGuides, bucketWebhooks, bucketWebhookLinks, bucketWebhookDeliveries, bucketWebhookCDChecks,
		bucketMCPServers, bucketWebhookCDCheckHistory, bucketTrash, bucketVPSDNS}

	keySchema = []byte("schema")
)

// ErrNotFound is returned when a record does not exist.
var ErrNotFound = errors.New("store: not found")

// ErrConflict is returned when a record exists with different content.
var ErrConflict = errors.New("store: conflict")

// Store is the web daemon's bbolt database.
type Store struct {
	db       *bolt.DB
	onChange atomic.Pointer[func(Change)]
}

// Change is one committed write of a record the live socket reports
// (internal/web/server/live.go): an op or notification of User, an
// incident of Tenant ("" for a cluster incident).
type Change struct {
	Kind    string // "op", "notification", "incident"
	User    string
	Tenant  string
	ID      string // "" when several records of User changed at once
	Deleted bool
}

// OnChange sets the function told about every committed Change. It runs
// after the transaction, outside it, and must not block.
func (s *Store) OnChange(fn func(Change)) { s.onChange.Store(&fn) }

func (s *Store) changed(err error, c Change) {
	if err != nil {
		return
	}
	if fn := s.onChange.Load(); fn != nil && *fn != nil {
		(*fn)(c)
	}
}

// Open opens (creating if needed) the DB file with mode 0600 and migrates the
// schema. bbolt's file lock makes a second web process fail to open it.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open web db %s: %w", path, err)
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the DB.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	return s.db.Update(func(tx *bolt.Tx) error {
		for _, b := range allBuckets {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		meta := tx.Bucket(bucketMeta)
		raw := meta.Get(keySchema)
		if raw == nil {
			return meta.Put(keySchema, u64(SchemaVersion))
		}
		if v := binary.BigEndian.Uint64(raw); v != SchemaVersion {
			return fmt.Errorf("web db schema %d is not supported (want %d)", v, SchemaVersion)
		}
		return nil
	})
}

func u64(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}

func key(parts ...string) []byte {
	return []byte(joinKey(parts...))
}

// joinKey joins key parts with NUL so that user-chosen names containing "/"
// cannot collide with another tuple.
func joinKey(parts ...string) string {
	var buf bytes.Buffer
	for i, p := range parts {
		if i > 0 {
			buf.WriteByte(0)
		}
		buf.WriteString(p)
	}
	return buf.String()
}

func prefix(parts ...string) []byte {
	return append(key(parts...), 0)
}

func putJSON(b *bolt.Bucket, k []byte, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return b.Put(k, raw)
}

func getJSON(b *bolt.Bucket, k []byte, v any) error {
	raw := b.Get(k)
	if raw == nil {
		return ErrNotFound
	}
	return json.Unmarshal(raw, v)
}
