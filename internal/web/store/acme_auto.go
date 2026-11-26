// SPDX-License-Identifier: Apache-2.0

package store

import (
	"time"

	bolt "go.etcd.io/bbolt"
)

// Automatic issuance settings (UI-57 "자동 발급"): web-own data. The hosts
// it watches come from mydcd's ingress mapping, read each round, and are
// not kept here.

var bucketACMEAuto = []byte("acme-auto")

var acmeAutoKey = []byte("settings")

// ACMEAuto is the one settings row.
type ACMEAuto struct {
	Enabled            bool                       `json:"enabled"` // default for domains without a row
	Account            string                     `json:"account,omitempty"`
	KeyTypes           []string                   `json:"keyTypes"`
	DualRSA            bool                       `json:"dualRsa"`
	NotifyAfterMinutes int                        `json:"notifyAfterMinutes"`
	Domains            map[string]*ACMEAutoDomain `json:"domains"`
	Ignored            map[string]time.Time       `json:"ignored"` // host → when
	Revision           uint64                     `json:"revision"`
	UpdatedBy          string                     `json:"updatedBy,omitempty"`
	UpdatedAt          time.Time                  `json:"updatedAt,omitzero"`
}

// ACMEAutoDomain is one external domain's choice.
type ACMEAutoDomain struct {
	Enabled  bool     `json:"enabled"`
	Mode     string   `json:"mode"` // per-host, wildcard
	KeyTypes []string `json:"keyTypes,omitempty"`
}

func (a *ACMEAuto) fill() {
	if a.Domains == nil {
		a.Domains = map[string]*ACMEAutoDomain{}
	}
	if a.Ignored == nil {
		a.Ignored = map[string]time.Time{}
	}
	if a.NotifyAfterMinutes == 0 && a.Revision == 0 {
		a.NotifyAfterMinutes = 10
	}
}

// GetACMEAuto returns the settings (defaults when never saved).
func (s *Store) GetACMEAuto() (*ACMEAuto, error) {
	a := &ACMEAuto{}
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketACMEAuto)
		if b.Get(acmeAutoKey) == nil {
			return nil
		}
		return getJSON(b, acmeAutoKey, a)
	})
	a.fill()
	return a, err
}

// UpdateACMEAuto changes the settings; expected must be the current
// revision (ErrConflict otherwise).
func (s *Store) UpdateACMEAuto(expected uint64, fn func(a *ACMEAuto) error) (*ACMEAuto, error) {
	var out *ACMEAuto
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketACMEAuto)
		a := &ACMEAuto{}
		if b.Get(acmeAutoKey) != nil {
			if err := getJSON(b, acmeAutoKey, a); err != nil {
				return err
			}
		}
		a.fill()
		if expected != a.Revision {
			return ErrConflict
		}
		if err := fn(a); err != nil {
			return err
		}
		a.Revision++
		out = a
		return putJSON(b, acmeAutoKey, a)
	})
	return out, err
}
