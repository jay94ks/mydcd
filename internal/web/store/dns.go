// SPDX-License-Identifier: Apache-2.0

package store

import (
	"encoding/json"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// External DNS rows (devel/design/web-dns-plan.md). Record values stay with
// the provider; these rows hold only connection data, assignments, marks of
// records MyDC made and the change history. Provider tokens are in sealed
// files, never here.

// DNSProvider is one provider connection (one API token).
type DNSProvider struct {
	ID           string    `json:"id"`
	Vendor       string    `json:"vendor"`
	Name         string    `json:"name"`
	TokenHint    string    `json:"tokenHint"` // last 4 characters
	TokenExpires time.Time `json:"tokenExpires,omitzero"`
	Account      string    `json:"account,omitempty"`
	LastCheck    time.Time `json:"lastCheck,omitzero"`
	LastCheckOK  bool      `json:"lastCheckOk"`
	LastError    string    `json:"lastError,omitempty"`
	Remaining    int       `json:"remaining"`
	CreatedBy    string    `json:"createdBy"`
	CreatedAt    time.Time `json:"createdAt"`
}

// DNSAssignment gives a workspace a range of names in a domain.
type DNSAssignment struct {
	Tenant string   `json:"tenant"`
	Names  []string `json:"names"` // "shop", "*.shop"
}

// DNSDomain is a connected external domain.
type DNSDomain struct {
	Domain      string          `json:"domain"`
	Provider    string          `json:"provider"`
	DefaultTTL  int             `json:"defaultTtl"`
	Assignments []DNSAssignment `json:"assignments"`
	AddedBy     string          `json:"addedBy"`
	AddedAt     time.Time       `json:"addedAt"`
}

// DNSManaged marks an RRSet MyDC wrote.
type DNSManaged struct {
	Domain      string    `json:"domain"`
	Name        string    `json:"name"`
	Type        string    `json:"type"`
	Tenant      string    `json:"tenant,omitempty"`
	App         string    `json:"app,omitempty"`
	By          string    `json:"by"`
	Fingerprint string    `json:"fingerprint"`
	At          time.Time `json:"at"`
}

// DNSChange is one RRSet before and after (null = absent).
type DNSChange struct {
	Name   string          `json:"name"`
	Type   string          `json:"type"`
	Before json.RawMessage `json:"before"`
	After  json.RawMessage `json:"after"`
}

// DNSHistory is one applied change list. Kept until a user deletes it.
type DNSHistory struct {
	ID       string      `json:"id"` // the web op ID of the apply
	Domain   string      `json:"domain"`
	At       time.Time   `json:"at"`
	User     string      `json:"user"`
	Username string      `json:"username"`
	Tenant   string      `json:"tenant,omitempty"` // workspace the change was made for
	Changes  []DNSChange `json:"changes"`
	Digest   string      `json:"digest"` // of the request, for idempotent retries
	Result   string      `json:"result"` // applied, failed, unknown
	Error    string      `json:"error,omitempty"`
	Snapshot string      `json:"snapshot,omitempty"` // provider snapshot before the change
	RevertOf string      `json:"revertOf,omitempty"`
}

// PutDNSProvider creates or replaces a provider row.
func (s *Store) PutDNSProvider(p *DNSProvider) error {
	return s.db.Update(func(tx *bolt.Tx) error { return putJSON(tx.Bucket(bucketDNSProv), []byte(p.ID), p) })
}

// GetDNSProvider loads a provider row.
func (s *Store) GetDNSProvider(id string) (*DNSProvider, error) {
	var p DNSProvider
	err := s.db.View(func(tx *bolt.Tx) error { return getJSON(tx.Bucket(bucketDNSProv), []byte(id), &p) })
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// ListDNSProviders lists provider rows by ID.
func (s *Store) ListDNSProviders() ([]*DNSProvider, error) {
	var out []*DNSProvider
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketDNSProv).ForEach(func(_, v []byte) error {
			var p DNSProvider
			if err := jsonUnmarshal(v, &p); err != nil {
				return err
			}
			out = append(out, &p)
			return nil
		})
	})
	return out, err
}

// DeleteDNSProvider removes a provider row. It fails with ErrConflict while a
// domain uses it.
func (s *Store) DeleteDNSProvider(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if tx.Bucket(bucketDNSProv).Get([]byte(id)) == nil {
			return ErrNotFound
		}
		inUse := false
		_ = tx.Bucket(bucketDNSDomains).ForEach(func(_, v []byte) error {
			var d DNSDomain
			if jsonUnmarshal(v, &d) == nil && d.Provider == id {
				inUse = true
			}
			return nil
		})
		if inUse {
			return ErrConflict
		}
		return tx.Bucket(bucketDNSProv).Delete([]byte(id))
	})
}

// CreateDNSDomain adds a domain; ErrConflict if it is already connected.
func (s *Store) CreateDNSDomain(d *DNSDomain) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketDNSDomains)
		if b.Get([]byte(d.Domain)) != nil {
			return ErrConflict
		}
		return putJSON(b, []byte(d.Domain), d)
	})
}

// PutDNSDomain replaces an existing domain row.
func (s *Store) PutDNSDomain(d *DNSDomain) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketDNSDomains)
		if b.Get([]byte(d.Domain)) == nil {
			return ErrNotFound
		}
		return putJSON(b, []byte(d.Domain), d)
	})
}

// GetDNSDomain loads a domain row.
func (s *Store) GetDNSDomain(domain string) (*DNSDomain, error) {
	var d DNSDomain
	err := s.db.View(func(tx *bolt.Tx) error { return getJSON(tx.Bucket(bucketDNSDomains), []byte(domain), &d) })
	if err != nil {
		return nil, err
	}
	return &d, nil
}

// ListDNSDomains lists domain rows by name.
func (s *Store) ListDNSDomains() ([]*DNSDomain, error) {
	var out []*DNSDomain
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketDNSDomains).ForEach(func(_, v []byte) error {
			var d DNSDomain
			if err := jsonUnmarshal(v, &d); err != nil {
				return err
			}
			out = append(out, &d)
			return nil
		})
	})
	return out, err
}

// DeleteDNSDomain removes a domain row and its managed marks. History and
// the provider's records stay.
func (s *Store) DeleteDNSDomain(domain string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if tx.Bucket(bucketDNSDomains).Get([]byte(domain)) == nil {
			return ErrNotFound
		}
		if err := tx.Bucket(bucketDNSDomains).Delete([]byte(domain)); err != nil {
			return err
		}
		if err := tx.Bucket(bucketDNSServers).Delete([]byte(domain)); err != nil {
			return err
		}
		return deletePrefix(tx.Bucket(bucketDNSManaged), prefix(domain))
	})
}

func deletePrefix(b *bolt.Bucket, p []byte) error {
	c := b.Cursor()
	var dead [][]byte
	for k, _ := c.Seek(p); k != nil && hasPrefix(k, p); k, _ = c.Next() {
		dead = append(dead, append([]byte(nil), k...))
	}
	for _, k := range dead {
		if err := b.Delete(k); err != nil {
			return err
		}
	}
	return nil
}

// ListDNSManaged returns a domain's managed marks keyed "name|type".
func (s *Store) ListDNSManaged(domain string) (map[string]*DNSManaged, error) {
	out := map[string]*DNSManaged{}
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketDNSManaged).Cursor()
		p := prefix(domain)
		for k, v := c.Seek(p); k != nil && hasPrefix(k, p); k, v = c.Next() {
			var m DNSManaged
			if err := jsonUnmarshal(v, &m); err != nil {
				return err
			}
			out[m.Name+"|"+m.Type] = &m
		}
		return nil
	})
	return out, err
}

// ApplyDNSManaged sets and removes managed marks in one transaction.
func (s *Store) ApplyDNSManaged(domain string, set []*DNSManaged, remove [][2]string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketDNSManaged)
		for _, r := range remove {
			if err := b.Delete(key(domain, r[0], r[1])); err != nil {
				return err
			}
		}
		for _, m := range set {
			if err := putJSON(b, key(domain, m.Name, m.Type), m); err != nil {
				return err
			}
		}
		return nil
	})
}

func dnsHistKey(domain string, at time.Time, id string) []byte {
	return key(domain, fmt.Sprintf("%020d", at.UnixNano()), id)
}

// PutDNSHistory creates or replaces a history entry.
func (s *Store) PutDNSHistory(h *DNSHistory) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return putJSON(tx.Bucket(bucketDNSHistory), dnsHistKey(h.Domain, h.At, h.ID), h)
	})
}

// ListDNSHistory returns a domain's history, newest first.
func (s *Store) ListDNSHistory(domain string, limit int) ([]*DNSHistory, error) {
	var all []*DNSHistory
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketDNSHistory).Cursor()
		p := prefix(domain)
		for k, v := c.Seek(p); k != nil && hasPrefix(k, p); k, v = c.Next() {
			var h DNSHistory
			if err := jsonUnmarshal(v, &h); err != nil {
				return err
			}
			all = append(all, &h)
		}
		return nil
	})
	out := make([]*DNSHistory, 0, len(all))
	for i := len(all) - 1; i >= 0 && (limit <= 0 || len(out) < limit); i-- {
		out = append(out, all[i])
	}
	return out, err
}

// GetDNSHistory finds a history entry by ID.
func (s *Store) GetDNSHistory(domain, id string) (*DNSHistory, error) {
	var out *DNSHistory
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketDNSHistory).Cursor()
		p := prefix(domain)
		for k, v := c.Seek(p); k != nil && hasPrefix(k, p); k, v = c.Next() {
			if lastPart(k) == id {
				var h DNSHistory
				if err := jsonUnmarshal(v, &h); err != nil {
					return err
				}
				out = &h
				return nil
			}
		}
		return ErrNotFound
	})
	return out, err
}

// DeleteDNSHistory removes a history entry (only by an explicit user
// delete).
func (s *Store) DeleteDNSHistory(domain, id string) error {
	h, err := s.GetDNSHistory(domain, id)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketDNSHistory).Delete(dnsHistKey(domain, h.At, h.ID))
	})
}
