// SPDX-License-Identifier: Apache-2.0

package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Incident response guidelines (W2.3a): what people write for diagnosis
// and the coordinator, per scope (cluster, tenant/T, app/T/A), every saved
// version kept until the scope is deleted.

var bucketGuides = []byte("ai-guidelines")

// Guide is one saved version of a scope's guidelines.
type Guide struct {
	Scope     string      `json:"scope"` // cluster, tenant/T, app/T/A
	Tenant    string      `json:"tenant,omitempty"`
	App       string      `json:"app,omitempty"`
	Version   uint64      `json:"version"`
	Text      string      `json:"text"`
	Fields    GuideFields `json:"fields"`
	Deliver   GuideTo     `json:"deliver"`
	UpdatedBy string      `json:"updatedBy"`
	UpdatedAt time.Time   `json:"updatedAt"`
}

// GuideFields are the fixed fields.
type GuideFields struct {
	Prefer     []string   `json:"prefer"`
	Avoid      GuideAvoid `json:"avoid"`
	MCPServers []string   `json:"mcpServers"`
	Notify     []string   `json:"notify"`
	Critical   []string   `json:"critical"`
}

// GuideAvoid is what never to propose.
type GuideAvoid struct {
	Actions  []string `json:"actions"`
	Services []string `json:"services"`
}

// GuideTo says where the text goes (the impact assessment never gets it).
type GuideTo struct {
	Diagnose    bool `json:"diagnose"`
	Coordinator bool `json:"coordinator"`
}

func guideKey(scope string) []byte { return key("cur", scope) }
func guideVersionKey(scope string, v uint64) []byte {
	return key("ver", scope, fmt.Sprintf("%020d", v))
}

// GetGuide returns the current version of a scope (nil when none).
func (s *Store) GetGuide(scope string) (*Guide, error) {
	var out *Guide
	err := s.db.View(func(tx *bolt.Tx) error {
		var g Guide
		err := getJSON(tx.Bucket(bucketGuides), guideKey(scope), &g)
		if err == ErrNotFound {
			return nil
		}
		out = &g
		return err
	})
	return out, err
}

// GetGuideVersion returns one version of a scope.
func (s *Store) GetGuideVersion(scope string, v uint64) (*Guide, error) {
	var g Guide
	err := s.db.View(func(tx *bolt.Tx) error {
		return getJSON(tx.Bucket(bucketGuides), guideVersionKey(scope, v), &g)
	})
	if err != nil {
		return nil, err
	}
	return &g, nil
}

// SaveGuide stores g as the next version of its scope when the current
// version is expected (0 = none yet); ErrConflict otherwise.
func (s *Store) SaveGuide(g *Guide, expected uint64) (err error) {
	defer func() { s.changed(err, Change{Kind: "guide", Tenant: g.Tenant, ID: g.Scope}) }()
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketGuides)
		var cur Guide
		v := uint64(0)
		if err := getJSON(b, guideKey(g.Scope), &cur); err == nil {
			v = cur.Version
		} else if err != ErrNotFound {
			return err
		}
		if v != expected {
			return ErrConflict
		}
		g.Version = v + 1
		if err := putJSON(b, guideVersionKey(g.Scope, g.Version), g); err != nil {
			return err
		}
		return putJSON(b, guideKey(g.Scope), g)
	})
}

// ListGuides returns the current version of every scope.
func (s *Store) ListGuides() ([]*Guide, error) {
	var out []*Guide
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketGuides).Cursor()
		p := prefix("cur")
		for k, v := c.Seek(p); k != nil && bytes.HasPrefix(k, p); k, v = c.Next() {
			var g Guide
			if err := json.Unmarshal(v, &g); err != nil {
				return err
			}
			out = append(out, &g)
		}
		return nil
	})
	return out, err
}

// ListGuideVersions returns every version of a scope, oldest first.
func (s *Store) ListGuideVersions(scope string) ([]*Guide, error) {
	var out []*Guide
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketGuides).Cursor()
		p := prefix("ver", scope)
		for k, v := c.Seek(p); k != nil && bytes.HasPrefix(k, p); k, v = c.Next() {
			var g Guide
			if err := json.Unmarshal(v, &g); err != nil {
				return err
			}
			out = append(out, &g)
		}
		return nil
	})
	return out, err
}

// DeleteGuide deletes a scope and all its versions.
func (s *Store) DeleteGuide(scope string) (err error) {
	defer func() {
		s.changed(err, Change{Kind: "guide", Tenant: guideScopeTenant(scope), ID: scope, Deleted: true})
	}()
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketGuides)
		if b.Get(guideKey(scope)) == nil {
			return ErrNotFound
		}
		var drop [][]byte
		c := b.Cursor()
		p := prefix("ver", scope)
		for k, _ := c.Seek(p); k != nil && bytes.HasPrefix(k, p); k, _ = c.Next() {
			drop = append(drop, append([]byte(nil), k...))
		}
		drop = append(drop, guideKey(scope))
		for _, k := range drop {
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
}

// guideScopeTenant is the tenant of a guide scope (cluster, tenant/T,
// app/T/A).
func guideScopeTenant(scope string) string {
	parts := strings.Split(scope, "/")
	if len(parts) >= 2 && (parts[0] == "tenant" || parts[0] == "app") {
		return parts[1]
	}
	return ""
}
