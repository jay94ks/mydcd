// SPDX-License-Identifier: Apache-2.0

package store

import (
	"time"

	bolt "go.etcd.io/bbolt"
)

var bucketVPSDNS = []byte("vps-dns-holds")

// VPSDNSHold is one domain's records taken off for a stopped VPS server
// (devel/design/vps-nodes.md §5a). The change is temporary: when the
// server runs again the web daemon puts the addresses back into each set
// whose fingerprint is still After; a set someone changed meanwhile stays
// as it is and is listed in Blocked.
type VPSDNSHold struct {
	Server string       `json:"server"`
	Domain string       `json:"domain"`
	At     time.Time    `json:"at"`
	Sets   []VPSDNSSet  `json:"sets"`
	Kept   []VPSDNSKept `json:"kept,omitempty"` // left in: the server's address was the last one
	// Blocked: sets not put back because they changed while the server
	// was stopped. The hold stays until an administrator dismisses it.
	Blocked []VPSDNSSet `json:"blocked,omitempty"`
	// Request is the stop it was made for (the server's PowerRequest): a
	// later stop takes the addresses out again.
	Request string `json:"request,omitempty"`
	// History is the DNS history row of the withdrawal.
	History string `json:"history,omitempty"`
}

// VPSDNSSet is one RRSet the server's addresses were taken out of.
type VPSDNSSet struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Removed []string `json:"removed"`
	After   string   `json:"after"` // fingerprint of the set without them
}

// VPSDNSKept is a set left as it was.
type VPSDNSKept struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

func vpsDNSKey(server, domain string) []byte { return []byte(server + "\x00" + domain) }

// PutVPSDNSHold stores or replaces a hold.
func (s *Store) PutVPSDNSHold(h *VPSDNSHold) error {
	err := s.db.Update(func(tx *bolt.Tx) error {
		return putJSON(tx.Bucket(bucketVPSDNS), vpsDNSKey(h.Server, h.Domain), h)
	})
	s.changed(err, Change{Kind: "vps-dns-hold", ID: h.Server})
	return err
}

// DeleteVPSDNSHold removes a hold (no error when there is none).
func (s *Store) DeleteVPSDNSHold(server, domain string) error {
	err := s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketVPSDNS).Delete(vpsDNSKey(server, domain))
	})
	s.changed(err, Change{Kind: "vps-dns-hold", ID: server})
	return err
}

// ListVPSDNSHolds returns every hold, by server then domain.
func (s *Store) ListVPSDNSHolds() ([]*VPSDNSHold, error) {
	out := []*VPSDNSHold{}
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketVPSDNS).ForEach(func(k, _ []byte) error {
			h := &VPSDNSHold{}
			if err := getJSON(tx.Bucket(bucketVPSDNS), k, h); err != nil {
				return err
			}
			out = append(out, h)
			return nil
		})
	})
	return out, err
}
