// SPDX-License-Identifier: Apache-2.0

package store

import (
	"time"

	bolt "go.etcd.io/bbolt"
)

// The servers a domain's Seafield Cluster records point at (canvas ExtDomainDetail
// "연결된 서버"): web-own data. The ingress state itself is sfcd's and
// read each time.

var bucketDNSServers = []byte("dns-servers")

// DNSServerLinks is one domain's linked servers.
type DNSServerLinks struct {
	Domain   string                    `json:"domain"`
	Rows     map[string]*DNSServerLink `json:"rows"` // by node
	Revision uint64                    `json:"revision"`
}

// DNSServerLink is one linked server.
type DNSServerLink struct {
	AddressSource string    `json:"addressSource"` // node, manual
	Addresses     []string  `json:"addresses"`     // manual only
	AutoRemove    bool      `json:"autoRemove"`
	Reach         *DNSReach `json:"reach,omitempty"`
	By            string    `json:"by"`
	At            time.Time `json:"at"`
}

// DNSReach is the last outside reach check.
type DNSReach struct {
	OK    bool      `json:"ok"`
	At    time.Time `json:"at"`
	Error string    `json:"error,omitempty"`
}

// GetDNSServerLinks returns a domain's links (empty when none).
func (s *Store) GetDNSServerLinks(domain string) (*DNSServerLinks, error) {
	l := &DNSServerLinks{Domain: domain, Rows: map[string]*DNSServerLink{}}
	err := s.db.View(func(tx *bolt.Tx) error {
		if v := tx.Bucket(bucketDNSServers).Get([]byte(domain)); v == nil {
			return nil
		}
		return getJSON(tx.Bucket(bucketDNSServers), []byte(domain), l)
	})
	if l.Rows == nil {
		l.Rows = map[string]*DNSServerLink{}
	}
	return l, err
}

// UpdateDNSServerLinks changes a domain's links; expected must be the
// current revision (ErrConflict otherwise).
func (s *Store) UpdateDNSServerLinks(domain string, expected uint64, fn func(l *DNSServerLinks) error) (*DNSServerLinks, error) {
	var out *DNSServerLinks
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketDNSServers)
		l := &DNSServerLinks{Domain: domain, Rows: map[string]*DNSServerLink{}}
		if b.Get([]byte(domain)) != nil {
			if err := getJSON(b, []byte(domain), l); err != nil {
				return err
			}
		}
		if l.Rows == nil {
			l.Rows = map[string]*DNSServerLink{}
		}
		if expected != l.Revision {
			return ErrConflict
		}
		if err := fn(l); err != nil {
			return err
		}
		l.Revision++
		out = l
		return putJSON(b, []byte(domain), l)
	})
	return out, err
}

// SetDNSReach records reach checks without a revision change.
func (s *Store) SetDNSReach(domain string, reach map[string]*DNSReach) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketDNSServers)
		if b.Get([]byte(domain)) == nil {
			return nil
		}
		var l DNSServerLinks
		if err := getJSON(b, []byte(domain), &l); err != nil {
			return err
		}
		for n, r := range reach {
			if row := l.Rows[n]; row != nil {
				row.Reach = r
			}
		}
		return putJSON(b, []byte(domain), &l)
	})
}
