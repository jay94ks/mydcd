// SPDX-License-Identifier: Apache-2.0

package store

import (
	"encoding/json"
	"errors"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"
)

// "Bring back what was deleted" (UI-A5). A delete keeps the definition it
// removed for the retention period; a restore makes the same definition
// again. No secret value is kept: sealed secrets and tokens are dropped at
// delete as before.

var bucketTrash = []byte("trash")

// Trash kinds.
const (
	TrashWebhook         = "webhook"
	TrashMCPServer       = "mcp-server"
	TrashGuide           = "guide"
	TrashDNSRecord       = "dns-record"
	TrashClusterAppRoute = "cluster-app-route"
)

// TrashItem is one deleted definition.
type TrashItem struct {
	ID          string    `json:"id"`
	Kind        string    `json:"kind"`
	Tenant      string    `json:"tenant,omitempty"`
	Name        string    `json:"name"`
	DeletedBy   string    `json:"deletedBy"`
	DeletedByID string    `json:"deletedById"`
	DeletedAt   time.Time `json:"deletedAt"`
	ExpiresAt   time.Time `json:"expiresAt"`
	// Op: the web op that deleted it (definitions sfcd keeps).
	Op string `json:"op,omitempty"`
	// Data is the kind's definition (TrashWebhookData, …).
	Data json.RawMessage `json:"data"`
}

// TrashWebhookData: the webhook and its links.
type TrashWebhookData struct {
	Webhook Webhook        `json:"webhook"`
	Links   []*WebhookLink `json:"links,omitempty"`
}

// TrashMCPData: the server and the guideline scopes that named it.
type TrashMCPData struct {
	Server MCPServer `json:"server"`
	Guides []string  `json:"guides,omitempty"`
}

// TrashGuideData: the current guidelines and every earlier version.
type TrashGuideData struct {
	Current  Guide    `json:"current"`
	Versions []*Guide `json:"versions,omitempty"`
}

// TrashDNSRecordData: one record added by hand to a network's managed DNS
// (services.DNSRecord, as sfcd keeps it).
type TrashDNSRecordData struct {
	Network string          `json:"network"`
	Record  json.RawMessage `json:"record"`
}

// TrashClusterAppRouteData: a cluster app's whole route declaration
// (deployment.IngressDeclaration).
type TrashClusterAppRouteData struct {
	App     string          `json:"app"`
	Ingress json.RawMessage `json:"ingress"`
}

// PutTrash stores an item; an item with the same ID is replaced.
func (s *Store) PutTrash(it *TrashItem) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return putJSON(tx.Bucket(bucketTrash), []byte(it.ID), it)
	})
}

// GetTrash loads one item.
func (s *Store) GetTrash(id string) (*TrashItem, error) {
	var it TrashItem
	err := s.db.View(func(tx *bolt.Tx) error { return getJSON(tx.Bucket(bucketTrash), []byte(id), &it) })
	if err != nil {
		return nil, err
	}
	return &it, nil
}

// ListTrash lists every item not yet expired at now, newest first.
func (s *Store) ListTrash(now time.Time) ([]*TrashItem, error) {
	var out []*TrashItem
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketTrash).ForEach(func(_, v []byte) error {
			var it TrashItem
			if err := jsonUnmarshal(v, &it); err != nil {
				return err
			}
			if it.ExpiresAt.After(now) {
				out = append(out, &it)
			}
			return nil
		})
	})
	sort.SliceStable(out, func(i, j int) bool { return out[i].DeletedAt.After(out[j].DeletedAt) })
	return out, err
}

// TakeTrash removes an item and returns it (restore and empty).
func (s *Store) TakeTrash(id string) (*TrashItem, error) {
	var it TrashItem
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketTrash)
		if err := getJSON(b, []byte(id), &it); err != nil {
			return err
		}
		return b.Delete([]byte(id))
	})
	if err != nil {
		return nil, err
	}
	return &it, nil
}

// PruneTrash drops the items expired at now.
func (s *Store) PruneTrash(now time.Time) (int, error) {
	n := 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketTrash)
		var dead [][]byte
		if err := b.ForEach(func(k, v []byte) error {
			var it TrashItem
			if jsonUnmarshal(v, &it) == nil && !it.ExpiresAt.After(now) {
				dead = append(dead, append([]byte(nil), k...))
			}
			return nil
		}); err != nil {
			return err
		}
		for _, k := range dead {
			if err := b.Delete(k); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	return n, err
}

// RestoreWebhook puts a deleted webhook and its links back; ErrConflict
// when the name is taken. Revisions start over.
func (s *Store) RestoreWebhook(h *Webhook, links []*WebhookLink) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketWebhooks)
		if b.Get([]byte(h.Name)) != nil {
			return ErrConflict
		}
		h.Revision = 1
		if err := putJSON(b, []byte(h.Name), h); err != nil {
			return err
		}
		lb := tx.Bucket(bucketWebhookLinks)
		for _, l := range links {
			if lb.Get([]byte(l.ID)) != nil {
				continue
			}
			l.Webhook, l.Revision = h.Name, 1
			if err := putJSON(lb, []byte(l.ID), l); err != nil {
				return err
			}
		}
		return nil
	})
}

// RestoreGuide puts deleted guidelines and their versions back;
// ErrConflict when the scope has guidelines now.
func (s *Store) RestoreGuide(cur *Guide, versions []*Guide) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketGuides)
		if b.Get(guideKey(cur.Scope)) != nil {
			return ErrConflict
		}
		for _, v := range versions {
			if err := putJSON(b, guideVersionKey(cur.Scope, v.Version), v); err != nil {
				return err
			}
		}
		if err := putJSON(b, guideVersionKey(cur.Scope, cur.Version), cur); err != nil {
			return err
		}
		return putJSON(b, guideKey(cur.Scope), cur)
	})
}

// AddGuideMCP adds an MCP server back to the guideline scopes that named it
// (those that still exist).
func (s *Store) AddGuideMCP(name string, scopes []string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketGuides)
		for _, sc := range scopes {
			var g Guide
			err := getJSON(b, guideKey(sc), &g)
			if errors.Is(err, ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			if !containsString(g.Fields.MCPServers, name) {
				g.Fields.MCPServers = append(g.Fields.MCPServers, name)
				if err := putJSON(b, guideKey(sc), &g); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func containsString(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
