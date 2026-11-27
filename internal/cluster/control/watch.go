// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"
	"encoding/json"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
)

// A change watch tells a reader WHICH records a committed change touched,
// never their content: the reader reads the record it may see through its
// usual query (devel/design/web-live-updates.md). Records are found by
// comparing two states book by book; a book whose root revision did not move
// is not decoded.

// WatchKey names one record a reader can query.
type WatchKey struct {
	// Kind is "app", "volume", "network", "node" or "tenant".
	Kind string
	// Tenant is the owning tenant, "" for a cluster record (a node, a
	// member of the system network).
	Tenant string `json:",omitempty"`
	// Name is the record's own name in that query: the app name, the
	// volume key, the network ID, the node ID, the tenant ID.
	Name string
}

// WatchRef is one changed record. Deleted is true when the record no longer
// exists in the newer state.
type WatchRef struct {
	WatchKey
	Deleted bool `json:",omitempty"`
}

// WatchRecords is the record → content digest map of one book.
type WatchRecords map[WatchKey][32]byte

// WatchBooks is every book a change watch follows, by its root key.
var WatchBooks = []string{AppsKey, VolumesKey, ResourcesKey, MembersKey, CatalogKey}

// WatchBookRevision is the root row revision of book: it moves with every
// write to the book, so an unchanged revision means unchanged records.
func WatchBookRevision(s state.State, book string) uint64 { return s.Object(book).Revision }

func watchDigest(v any) ([32]byte, bool) {
	raw, err := json.Marshal(v)
	if err != nil {
		return [32]byte{}, false
	}
	return sha256.Sum256(raw), true
}

// add folds one more value into key's digest. Several values under one key
// (a network's entries on each server) are folded in their sorted order by
// the caller.
func (r WatchRecords) add(k WatchKey, v any) bool {
	d, ok := watchDigest(v)
	if !ok {
		return false
	}
	if old, exists := r[k]; exists {
		d = sha256.Sum256(append(old[:], d[:]...))
	}
	r[k] = d
	return true
}

// WatchRecords reads the records of one book in s.
func (p Policy) WatchRecords(s state.State, book string) (WatchRecords, error) {
	out := WatchRecords{}
	switch book {
	case AppsKey:
		apps, err := p.ReadApps(s)
		if err != nil {
			return nil, err
		}
		for _, v := range apps.Records() {
			if !out.add(WatchKey{"app", v.Tenant, v.App}, v) {
				return nil, ErrCatalog
			}
		}
	case VolumesKey:
		v, err := p.Volumes(s)
		if err != nil {
			return nil, err
		}
		keys := make([]string, 0, len(v.entries))
		for k := range v.entries {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			e := v.entries[k]
			if !out.add(WatchKey{"volume", e.State.Scope().Tenant, k}, e) {
				return nil, ErrCatalog
			}
		}
	case ResourcesKey:
		r, err := p.Resources(s)
		if err != nil {
			return nil, err
		}
		for _, n := range r.Networks.AllNetworks() {
			tenant := n.Tenant
			if n.System {
				tenant = ""
			}
			if !out.add(WatchKey{"network", tenant, n.ID}, n) {
				return nil, ErrCatalog
			}
		}
	case MembersKey:
		d, err := p.Members(s)
		if err != nil {
			return nil, err
		}
		perNode := map[string][]any{}
		for _, e := range d.Entries {
			perNode[e.Peer.ID] = append(perNode[e.Peer.ID], e)
		}
		for _, x := range d.Drains {
			perNode[x.Node] = append(perNode[x.Node], x)
		}
		for _, x := range d.Cordons {
			perNode[x.Node] = append(perNode[x.Node], x)
		}
		for node, values := range perNode {
			for _, v := range values {
				if !out.add(WatchKey{"node", "", node}, v) {
					return nil, ErrCatalog
				}
			}
		}
	case CatalogKey:
		c, err := p.Catalog(s)
		if err != nil {
			return nil, err
		}
		tenants := c.Tenants()
		slices.SortFunc(tenants, func(a, b access.Tenant) int { return strings.Compare(a.ID, b.ID) })
		for _, t := range tenants {
			if !out.add(WatchKey{"tenant", t.ID, t.ID}, t) {
				return nil, ErrCatalog
			}
		}
	default:
		return nil, ErrCatalog
	}
	return out, nil
}

// WatchDiff is every record that differs between older and newer, in a
// stable order.
func WatchDiff(older, newer WatchRecords) []WatchRef {
	var out []WatchRef
	for k, d := range newer {
		if old, ok := older[k]; !ok || old != d {
			out = append(out, WatchRef{WatchKey: k})
		}
	}
	for k := range older {
		if _, ok := newer[k]; !ok {
			out = append(out, WatchRef{WatchKey: k, Deleted: true})
		}
	}
	slices.SortFunc(out, func(a, b WatchRef) int {
		return strings.Compare(a.Kind+"\x00"+a.Tenant+"\x00"+a.Name, b.Kind+"\x00"+b.Tenant+"\x00"+b.Name)
	})
	return out
}
