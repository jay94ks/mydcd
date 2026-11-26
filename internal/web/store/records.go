// SPDX-License-Identifier: Apache-2.0

package store

import (
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// SessionRow is the persisted listing of a web login. Only the hash of the
// cookie session ID is stored; the MYDCP session itself lives in memory.
type SessionRow struct {
	Hash       string    `json:"hash"`
	User       string    `json:"user"`
	Username   string    `json:"username"`
	Method     string    `json:"method"`
	IssuedAt   time.Time `json:"issuedAt"`
	ExpiresAt  time.Time `json:"expiresAt"`
	LastActive time.Time `json:"lastActive"`
	EndedAt    time.Time `json:"endedAt,omitzero"`
	EndReason  string    `json:"endReason,omitempty"`
}

// PutSession creates or replaces a session row.
func (s *Store) PutSession(r *SessionRow) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return putJSON(tx.Bucket(bucketSessions), []byte(r.Hash), r)
	})
}

// EndSession marks a session row ended.
func (s *Store) EndSession(hash, reason string, at time.Time) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSessions)
		var r SessionRow
		if err := getJSON(b, []byte(hash), &r); err != nil {
			return err
		}
		if r.EndedAt.IsZero() {
			r.EndedAt, r.EndReason = at, reason
		}
		return putJSON(b, []byte(hash), &r)
	})
}

// ListSessions lists session rows of a user ("" for all).
func (s *Store) ListSessions(user string) ([]*SessionRow, error) {
	var out []*SessionRow
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketSessions).ForEach(func(_, v []byte) error {
			var r SessionRow
			if err := jsonUnmarshal(v, &r); err != nil {
				return err
			}
			if user == "" || r.User == user {
				out = append(out, &r)
			}
			return nil
		})
	})
	return out, err
}

// ExpireOpenSessions ends every open row. Called on start: a restart drops all
// MYDCP sessions, so remaining rows are expired.
func (s *Store) ExpireOpenSessions(at time.Time) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSessions)
		var rows []*SessionRow
		if err := b.ForEach(func(_, v []byte) error {
			var r SessionRow
			if err := jsonUnmarshal(v, &r); err != nil {
				return err
			}
			if r.EndedAt.IsZero() {
				rows = append(rows, &r)
			}
			return nil
		}); err != nil {
			return err
		}
		for _, r := range rows {
			r.EndedAt, r.EndReason = at, "restart"
			if err := putJSON(b, []byte(r.Hash), r); err != nil {
				return err
			}
		}
		return nil
	})
}

// PruneSessions deletes rows ended before cutoff.
func (s *Store) PruneSessions(cutoff time.Time) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSessions)
		var dead [][]byte
		if err := b.ForEach(func(k, v []byte) error {
			var r SessionRow
			if err := jsonUnmarshal(v, &r); err != nil {
				return err
			}
			if !r.EndedAt.IsZero() && r.EndedAt.Before(cutoff) {
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
		}
		return nil
	})
}

// ArchivedApp is an app definition saved right before down-app so it can be
// deployed again. It is removed only by an explicit purge.
type ArchivedApp struct {
	Key        string    `json:"key"`
	Tenant     string    `json:"tenant"`
	App        string    `json:"app"`
	Deployment string    `json:"deployment"`
	Source     []byte    `json:"source"` // app.yaml original
	Digest     string    `json:"digest"`
	Version    uint64    `json:"version"`
	Volumes    []string  `json:"volumes,omitempty"` // data stores left behind
	DownBy     string    `json:"downBy"`
	DownAt     time.Time `json:"downAt"`
	DownOp     string    `json:"downOp,omitempty"` // web op ID of down-app
}

func archivedKey(tenant, app, deployment string, at time.Time) string {
	return joinKey(tenant, app, deployment, fmt.Sprintf("%020d", at.UnixNano()))
}

// PutArchived stores an archived app and returns its key.
func (s *Store) PutArchived(a *ArchivedApp) (string, error) {
	a.Key = archivedKey(a.Tenant, a.App, a.Deployment, a.DownAt)
	err := s.db.Update(func(tx *bolt.Tx) error {
		return putJSON(tx.Bucket(bucketArchived), []byte(a.Key), a)
	})
	return a.Key, err
}

// UpdateArchived replaces an existing archived row.
func (s *Store) UpdateArchived(a *ArchivedApp) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketArchived)
		if b.Get([]byte(a.Key)) == nil {
			return ErrNotFound
		}
		return putJSON(b, []byte(a.Key), a)
	})
}

// ListArchived lists archived apps of a tenant, newest first.
func (s *Store) ListArchived(tenant string) ([]*ArchivedApp, error) {
	var out []*ArchivedApp
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketArchived).Cursor()
		p := prefix(tenant)
		for k, v := c.Seek(p); k != nil && hasPrefix(k, p); k, v = c.Next() {
			var a ArchivedApp
			if err := jsonUnmarshal(v, &a); err != nil {
				return err
			}
			out = append([]*ArchivedApp{&a}, out...)
		}
		return nil
	})
	return out, err
}

// GetArchived loads one archived app.
func (s *Store) GetArchived(k string) (*ArchivedApp, error) {
	var a ArchivedApp
	err := s.db.View(func(tx *bolt.Tx) error {
		return getJSON(tx.Bucket(bucketArchived), []byte(k), &a)
	})
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// DeleteArchived removes an archived app (explicit purge only).
func (s *Store) DeleteArchived(k string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketArchived)
		if b.Get([]byte(k)) == nil {
			return ErrNotFound
		}
		return b.Delete([]byte(k))
	})
}

// DeleteArchivedByOp removes the archive rows saved for the down-app web op
// opID in tenant (used when that down turns out not to have applied).
func (s *Store) DeleteArchivedByOp(tenant, opID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketArchived)
		c := b.Cursor()
		p := prefix(tenant)
		var dead [][]byte
		for k, v := c.Seek(p); k != nil && hasPrefix(k, p); k, v = c.Next() {
			var a ArchivedApp
			if err := jsonUnmarshal(v, &a); err != nil {
				return err
			}
			if a.DownOp == opID {
				dead = append(dead, append([]byte(nil), k...))
			}
		}
		for _, k := range dead {
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
}

// GetLayout returns the stored graph-editor block positions (raw JSON).
func (s *Store) GetLayout(tenant, app, deployment string) ([]byte, error) {
	var out []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketGraphLayout).Get(key(tenant, app, deployment))
		if v == nil {
			return ErrNotFound
		}
		out = append([]byte(nil), v...)
		return nil
	})
	return out, err
}

// PutLayout stores graph-editor block positions (raw JSON).
func (s *Store) PutLayout(tenant, app, deployment string, raw []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketGraphLayout).Put(key(tenant, app, deployment), raw)
	})
}

// GetPrefs returns a user's UI preferences (raw JSON), or nil.
func (s *Store) GetPrefs(user string) ([]byte, error) {
	var out []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		if v := tx.Bucket(bucketPrefs).Get([]byte(user)); v != nil {
			out = append([]byte(nil), v...)
		}
		return nil
	})
	return out, err
}

// PutPrefs stores a user's UI preferences (raw JSON).
func (s *Store) PutPrefs(user string, raw []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketPrefs).Put([]byte(user), raw)
	})
}
