// SPDX-License-Identifier: Apache-2.0

package store

import (
	"time"

	bolt "go.etcd.io/bbolt"
)

// StandaloneOrigin records that a standalone container definition was filled
// by copying an app service's settings (UI-3E '가져온 설정'). It is web data
// only: the copy has no link to the app, so sfcd keeps nothing of it. An
// entry is tied to the web op of the standalone-up that sent the definition
// and counts only once that op applied.
type StandaloneOrigin struct {
	OpID       string    `json:"opId"`
	State      string    `json:"state"` // the op's state, updated when it settles
	App        string    `json:"app,omitempty"`
	Deployment string    `json:"deployment,omitempty"`
	Service    string    `json:"service,omitempty"`
	Items      []string  `json:"items,omitempty"`
	User       string    `json:"user"`
	Username   string    `json:"username"`
	At         time.Time `json:"at"`
	SettledAt  time.Time `json:"settledAt,omitzero"`
}

// standaloneOriginKeep bounds the entries kept per container.
const standaloneOriginKeep = 8

type standaloneOrigins struct {
	Entries []StandaloneOrigin `json:"entries"` // newest first
}

// AddStandaloneOrigin adds an entry for an up op of tenant/name. An entry with
// an empty App records an up without a copied origin, so a later plain up
// clears what is shown. Re-adding the same op replaces its entry.
func (s *Store) AddStandaloneOrigin(tenant, name string, e StandaloneOrigin) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b, k := tx.Bucket(bucketSaOrigins), key(tenant, name)
		var cur standaloneOrigins
		if err := getJSON(b, k, &cur); err != nil && err != ErrNotFound {
			return err
		}
		out := []StandaloneOrigin{e}
		for _, o := range cur.Entries {
			if o.OpID != e.OpID && len(out) < standaloneOriginKeep {
				out = append(out, o)
			}
		}
		return putJSON(b, k, standaloneOrigins{out})
	})
}

// SettleStandaloneOrigin copies an op's state onto its entry, if any.
func (s *Store) SettleStandaloneOrigin(tenant, name, opID, state string, at time.Time) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b, k := tx.Bucket(bucketSaOrigins), key(tenant, name)
		var cur standaloneOrigins
		if err := getJSON(b, k, &cur); err != nil {
			if err == ErrNotFound {
				return nil
			}
			return err
		}
		for i := range cur.Entries {
			if cur.Entries[i].OpID == opID {
				cur.Entries[i].State, cur.Entries[i].SettledAt = state, at
				return putJSON(b, k, cur)
			}
		}
		return nil
	})
}

// StandaloneOrigin returns the newest entry whose op applied, or nil. An
// entry with no App (a plain up) also returns nil.
func (s *Store) StandaloneOrigin(tenant, name string) (*StandaloneOrigin, error) {
	var out *StandaloneOrigin
	err := s.db.View(func(tx *bolt.Tx) error {
		var cur standaloneOrigins
		if err := getJSON(tx.Bucket(bucketSaOrigins), key(tenant, name), &cur); err != nil {
			if err == ErrNotFound {
				return nil
			}
			return err
		}
		for _, o := range cur.Entries {
			if o.State == OpApplied {
				if o.App != "" {
					out = &o
				}
				return nil
			}
		}
		return nil
	})
	return out, err
}

// DeleteStandaloneOrigins forgets every entry of tenant/name.
func (s *Store) DeleteStandaloneOrigins(tenant, name string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketSaOrigins).Delete(key(tenant, name))
	})
}

// RenameStandaloneOrigins moves the entries of tenant/old to tenant/new (a
// pin that renamed the container), replacing any left under the new name.
func (s *Store) RenameStandaloneOrigins(tenant, old, new string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSaOrigins)
		raw := b.Get(key(tenant, old))
		if raw == nil {
			return b.Delete(key(tenant, new))
		}
		if err := b.Put(key(tenant, new), append([]byte(nil), raw...)); err != nil {
			return err
		}
		return b.Delete(key(tenant, old))
	})
}
