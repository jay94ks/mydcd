// SPDX-License-Identifier: Apache-2.0

package certstore

import (
	"bytes"
	"encoding/json"
	"math"
	"net/netip"
	"slices"
	"strings"
)

// Entry is one stored certificate. Disabled certificates never hold links;
// putting the same ID again does not bring them back.
type Entry struct {
	Certificate Certificate
	DisabledBy  string `json:",omitempty"`
	DisabledAt  int64  `json:",omitempty"`
}

func (e Entry) Disabled() bool { return e.DisabledAt != 0 }

type Catalog struct {
	Schema       uint8
	Cluster      [32]byte
	Revision     uint64
	Certificates []Entry  `json:",omitempty"`
	Domains      []Domain `json:",omitempty"`
	// ACMEResponder is the HTTP-01 responder ingress forwards to.
	ACMEResponder *ACMEResponder `json:",omitempty"`
}

// Certificate states (devel/design/certificate-store.md §4).
const (
	StateLinked         = "linked"
	StateUnlinked       = "unlinked"
	StatePendingDestroy = "pending-destroy"
)

// Link is one (host, family) -> certificate link.
type Link struct {
	Host, Family string
	ID           ID
}

// PublicEntry is the list row: certificate facts without chain or ciphertext.
type PublicEntry struct {
	Metadata   Metadata
	State      string
	Links      []Link `json:",omitempty"`
	DisabledBy string `json:",omitempty"`
	DisabledAt int64  `json:",omitempty"`
}

func New(cluster [32]byte) Catalog { return Catalog{Schema: 2, Cluster: cluster} }
func (c Catalog) Validate() error {
	if c.Schema != 2 || c.Cluster == ([32]byte{}) || len(c.Certificates) > MaxEntries || c.validateDomains() != nil || !c.ACMEResponder.valid() {
		return ErrCertificate
	}
	var last ID
	for i, e := range c.Certificates {
		v := e.Certificate
		if v.Validate() != nil || v.Cluster != c.Cluster || i > 0 && bytes.Compare(v.Metadata.ID[:], last[:]) <= 0 || (e.DisabledAt == 0) != (e.DisabledBy == "") || e.DisabledAt < 0 || len(e.DisabledBy) > 128 {
			return ErrCertificate
		}
		last = v.Metadata.ID
	}
	return nil
}
func (c Catalog) Own() Catalog {
	raw, _ := json.Marshal(c)
	var own Catalog
	_ = json.Unmarshal(raw, &own)
	return own
}
func (c Catalog) index(id ID) int {
	i, ok := slices.BinarySearchFunc(c.Certificates, id, func(e Entry, id ID) int { return bytes.Compare(e.Certificate.Metadata.ID[:], id[:]) })
	if !ok {
		return -1
	}
	return i
}
func (c Catalog) Entry(id ID) (Entry, bool) {
	i := c.index(id)
	if i < 0 {
		return Entry{}, false
	}
	raw, _ := json.Marshal(c.Certificates[i])
	var own Entry
	_ = json.Unmarshal(raw, &own)
	return own, true
}

func (c Catalog) bump(next Catalog) (Catalog, error) {
	if next.Revision == math.MaxUint64 {
		return c, ErrConflict
	}
	next.Revision++
	if raw, err := json.Marshal(next); err != nil || len(raw) > 16<<20 {
		return c, ErrConflict
	}
	return next, nil
}

// Put adds a certificate. An ID already in the store is a conflict: callers
// check first and report the existing certificate.
func (c Catalog) Put(v Certificate, at int64) (Catalog, error) {
	if c.Validate() != nil || v.Validate() != nil || v.Cluster != c.Cluster || at < v.Metadata.UploadedAt || at-v.Metadata.UploadedAt > 120 || at >= v.Metadata.NotAfter {
		return c, ErrCertificate
	}
	if c.index(v.Metadata.ID) >= 0 || len(c.Certificates) >= MaxEntries {
		return c, ErrConflict
	}
	next := c.Own()
	next.Certificates = append(next.Certificates, Entry{Certificate: v})
	slices.SortFunc(next.Certificates, func(a, b Entry) int {
		return bytes.Compare(a.Certificate.Metadata.ID[:], b.Certificate.Metadata.ID[:])
	})
	return c.bump(next)
}

// Delete removes an unlinked or pending-destroy certificate. A linked one is
// refused with ErrLinked; its links say where it is in use.
func (c Catalog) Delete(id ID, at int64) (Catalog, error) {
	i := c.index(id)
	if c.Validate() != nil || i < 0 {
		return c, ErrConflict
	}
	if len(c.LinksOf(id, at)) > 0 {
		return c, ErrLinked
	}
	next := c.Own()
	next.Certificates = slices.Delete(next.Certificates, i, i+1)
	if len(next.Certificates) == 0 {
		next.Certificates = nil
	}
	return c.bump(next)
}

// Disable drops every link of a certificate at once.
func (c Catalog) Disable(id ID, user string, at int64) (Catalog, error) {
	i := c.index(id)
	if c.Validate() != nil || i < 0 || c.Certificates[i].Disabled() || user == "" || len(user) > 128 || at <= 0 {
		return c, ErrConflict
	}
	next := c.Own()
	next.Certificates[i].DisabledBy, next.Certificates[i].DisabledAt = user, at
	return c.bump(next)
}

// Expire removes every certificate whose NotAfter has passed, whatever its
// state. Links move by the usual rule because they are derived.
func (c Catalog) Expire(at int64) (Catalog, []Metadata, error) {
	if c.Validate() != nil || at < 0 {
		return c, nil, ErrCertificate
	}
	next := c.Own()
	var removed []Metadata
	next.Certificates = slices.DeleteFunc(next.Certificates, func(e Entry) bool {
		if at >= e.Certificate.Metadata.NotAfter {
			removed = append(removed, e.Certificate.Metadata)
			return true
		}
		return false
	})
	if len(removed) == 0 {
		return c, nil, nil
	}
	if len(next.Certificates) == 0 {
		next.Certificates = nil
	}
	next, err := c.bump(next)
	if err != nil {
		return c, nil, err
	}
	return next, removed, nil
}

func (c Catalog) registered(host string) bool {
	return slices.ContainsFunc(c.Domains, func(d Domain) bool { return DomainCovers(d.Name, host) })
}
func better(a, b Metadata) bool {
	if a.NotAfter != b.NotAfter {
		return a.NotAfter > b.NotAfter
	}
	return bytes.Compare(a.ID[:], b.ID[:]) < 0
}

// Links derives every link at `at`: for each (registered host, family) the
// non-disabled certificate valid at `at` with the latest NotAfter (ties by
// ID). Because only valid certificates enter the store and expired ones are
// removed, this equals moving a link on put when the newcomer expires later.
func (c Catalog) Links(at int64) []Link {
	best := map[[2]string]Metadata{}
	for _, e := range c.Certificates {
		m := e.Certificate.Metadata
		if e.Disabled() || at < m.NotBefore || at >= m.NotAfter {
			continue
		}
		for _, h := range m.Hosts {
			if !c.registered(h) {
				continue
			}
			k := [2]string{h, Family(m.Algorithm)}
			if old, ok := best[k]; !ok || better(m, old) {
				best[k] = m
			}
		}
	}
	out := make([]Link, 0, len(best))
	for k, m := range best {
		out = append(out, Link{Host: k[0], Family: k[1], ID: m.ID})
	}
	slices.SortFunc(out, func(a, b Link) int {
		if n := strings.Compare(a.Host, b.Host); n != 0 {
			return n
		}
		return strings.Compare(a.Family, b.Family)
	})
	return out
}
func (c Catalog) LinksOf(id ID, at int64) []Link {
	return slices.DeleteFunc(c.Links(at), func(l Link) bool { return l.ID != id })
}

// State is linked, unlinked (no host inside a registered domain) or
// pending-destroy (registered hosts all held by others, or disabled).
func (c Catalog) State(e Entry, at int64) string {
	if len(c.LinksOf(e.Certificate.Metadata.ID, at)) > 0 {
		return StateLinked
	}
	if !e.Disabled() && !slices.ContainsFunc(e.Certificate.Metadata.Hosts, c.registered) {
		return StateUnlinked
	}
	return StatePendingDestroy
}
func (c Catalog) Public(at int64) []PublicEntry {
	links := c.Links(at)
	out := make([]PublicEntry, 0, len(c.Certificates))
	for _, e := range c.Certificates {
		row := PublicEntry{Metadata: e.Certificate.Metadata, DisabledBy: e.DisabledBy, DisabledAt: e.DisabledAt}
		for _, l := range links {
			if l.ID == row.Metadata.ID {
				row.Links = append(row.Links, l)
			}
		}
		row.State = c.State(e, at)
		out = append(out, row)
	}
	return out
}

// MatchHost scores a certificate host against a request host: 2 exact, 1
// one-level wildcard, 0 none.
func MatchHost(pattern, host string) int {
	host = strings.ToLower(host)
	if pattern == host {
		return 2
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:]
		if strings.HasSuffix(host, suffix) && !strings.Contains(strings.TrimSuffix(host, suffix), ".") && len(host) > len(suffix) {
			return 1
		}
	}
	return 0
}

// LookupHost returns the linked certificate of each family for host: the
// exact host's link, else the one-level wildcard's (never for an IP, which
// is compared in canonical form). ECDSA comes first.
func (c Catalog) LookupHost(host string, at int64) []Certificate {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	ip := false
	if a, err := netip.ParseAddr(host); err == nil {
		host, ip = a.Unmap().String(), true
	}
	links := c.Links(at)
	var out []Certificate
	for _, family := range []string{"ecdsa", "rsa"} {
		pick := -1
		for i, l := range links {
			if l.Family != family {
				continue
			}
			if l.Host == host {
				pick = i
				break
			}
			if pick < 0 && !ip && !strings.HasPrefix(host, "*.") && MatchHost(l.Host, host) == 1 {
				pick = i
			}
		}
		if pick >= 0 {
			e, _ := c.Entry(links[pick].ID)
			out = append(out, e.Certificate)
		}
	}
	return out
}

// Serves reports whether id is a certificate LookupHost returns for host.
func (c Catalog) Serves(host string, id ID, at int64) bool {
	return slices.ContainsFunc(c.LookupHost(host, at), func(v Certificate) bool { return v.Metadata.ID == id })
}

// Find resolves a `certificate show` argument: a full or 12+ character ID
// prefix, or issuer DN (or CN) plus serial. It reports false unless exactly
// one certificate matches.
func (c Catalog) Find(prefix, issuer, serial string) (Entry, bool) {
	var found []Entry
	for _, e := range c.Certificates {
		m := e.Certificate.Metadata
		switch {
		case prefix != "":
			if len(prefix) >= 12 && strings.HasPrefix(m.ID.String(), strings.ToLower(prefix)) {
				found = append(found, e)
			}
		case serial != "" && issuer != "":
			s := strings.TrimLeft(strings.ToLower(strings.ReplaceAll(serial, ":", "")), "0")
			if strings.TrimLeft(m.Serial, "0") == s && (m.Issuer == issuer || issuerCN(m.Issuer) == issuer) {
				found = append(found, e)
			}
		}
	}
	if len(found) != 1 {
		return Entry{}, false
	}
	own, _ := c.Entry(found[0].Certificate.Metadata.ID)
	return own, true
}
func issuerCN(dn string) string {
	for _, part := range strings.Split(dn, ",") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(part), "CN="); ok {
			return v
		}
	}
	return ""
}

// LookupPublic is LookupHost over list rows: per family, the exact host's
// link, else the one-level wildcard's.
func LookupPublic(rows []PublicEntry, host string) []PublicEntry {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	var out []PublicEntry
	for _, family := range []string{"ecdsa", "rsa"} {
		var exact, wild *PublicEntry
		for i := range rows {
			for _, l := range rows[i].Links {
				if l.Family != family {
					continue
				}
				if l.Host == host {
					exact = &rows[i]
				} else if wild == nil && !strings.HasPrefix(host, "*.") && MatchHost(l.Host, host) == 1 {
					wild = &rows[i]
				}
			}
		}
		if exact != nil {
			out = append(out, *exact)
		} else if wild != nil {
			out = append(out, *wild)
		}
	}
	return out
}

// Covers reports whether one of the certificate's hosts serves host.
func (m Metadata) Covers(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return slices.ContainsFunc(m.Hosts, func(h string) bool { return MatchHost(h, host) > 0 })
}
