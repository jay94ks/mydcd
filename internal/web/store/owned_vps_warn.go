// SPDX-License-Identifier: Apache-2.0

package store

import bolt "go.etcd.io/bbolt"

var bucketOwnedVPSWarn = []byte("owned-vps-warned")

// OwnedVPSWarn is the last subscription-end notice sent for an owned VPS
// (devel/design/vps-hostinger.md §3): Days is the smallest threshold already
// sent for the subscription that ends at ExpiresAt. A renewal moves
// ExpiresAt and the notices start over.
type OwnedVPSWarn struct {
	Server    string `json:"server"`
	ExpiresAt int64  `json:"expiresAt"`
	Days      int    `json:"days"`
}

// GetOwnedVPSWarn returns the server's notice state (ErrNotFound when none
// was sent).
func (s *Store) GetOwnedVPSWarn(server string) (*OwnedVPSWarn, error) {
	w := &OwnedVPSWarn{}
	err := s.db.View(func(tx *bolt.Tx) error {
		return getJSON(tx.Bucket(bucketOwnedVPSWarn), []byte(server), w)
	})
	return w, err
}

// PutOwnedVPSWarn stores or replaces the server's notice state.
func (s *Store) PutOwnedVPSWarn(w *OwnedVPSWarn) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return putJSON(tx.Bucket(bucketOwnedVPSWarn), []byte(w.Server), w)
	})
}

// ListOwnedVPSWarns returns every notice state.
func (s *Store) ListOwnedVPSWarns() ([]*OwnedVPSWarn, error) {
	out := []*OwnedVPSWarn{}
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketOwnedVPSWarn).ForEach(func(k, _ []byte) error {
			w := &OwnedVPSWarn{}
			if err := getJSON(tx.Bucket(bucketOwnedVPSWarn), k, w); err != nil {
				return err
			}
			out = append(out, w)
			return nil
		})
	})
	return out, err
}

// DeleteOwnedVPSWarn forgets a detached server (no error when none).
func (s *Store) DeleteOwnedVPSWarn(server string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketOwnedVPSWarn).Delete([]byte(server))
	})
}
