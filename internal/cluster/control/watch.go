// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"hash/fnv"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/network/services"
)

// A change watch tells a reader WHICH records a committed change touched,
// never their content: the reader reads the record it may see through its
// usual query (devel/design/web-live-updates.md). Records are found by
// comparing two states book by book; a book whose root revision did not move
// is not decoded.

// WatchKey names one record a reader can query.
type WatchKey struct {
	// Kind is "app", "volume", "network", "node", "tenant", "registry",
	// "registry-maintenance" (a built-in registry's GC and prune jobs, named
	// by the registry ID), "ingress", "dns", "certificate", "domain",
	// "host-grant" (a route host decision, named "<tenant>/<host>") or
	// "acme-responder".
	Kind string
	// Tenant is the owning tenant, "" for a cluster record (a node, a
	// member of the system network).
	Tenant string `json:",omitempty"`
	// Name is the record's own name in that query: the app name, the
	// volume key, the network ID, the node ID, the tenant ID, the registry
	// ID, the network ID of a managed DNS, the certificate ID, the domain.
	// An ingress record is named by its part: "block/<id>",
	// "balance/<app>/<route>", "drain/<app>/<node>", "gateway/<node>",
	// "cluster-app-route/<app>" or "history".
	Name string
	// User is the owner of a per-user record (a node shell session): it
	// and cluster managers hear of it.
	User string `json:",omitempty"`
}

// WatchRef is one changed record. Deleted is true when the record no longer
// exists in the newer state.
type WatchRef struct {
	WatchKey
	Deleted bool `json:",omitempty"`
}

// WatchRecords is the record → content digest map of one book.
type WatchRecords map[WatchKey][32]byte

// WatchBooks is every book a change watch follows, by its root key. Managed
// DNS is one row per network under services.ManagedDNSPrefix.
var WatchBooks = []string{AppsKey, VolumesKey, ResourcesKey, MembersKey, CatalogKey, RegistriesKey, RegistryMaintenanceKey, IngressManagementKey, CertificatesKey, VPSKey, NodeShellKey, services.ManagedDNSPrefix}

// WatchBookRevision is the root row revision of book: it moves with every
// write to the book, so an unchanged revision means unchanged records. A
// book of many rows (a key prefix) folds every row's key and revision.
func WatchBookRevision(s state.State, book string) uint64 {
	if !strings.HasSuffix(book, "/") {
		return s.Object(book).Revision
	}
	rows := s.Objects(book)
	keys := make([]string, 0, len(rows))
	for k := range rows {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	h := fnv.New64a()
	for _, k := range keys {
		var rev [8]byte
		binary.BigEndian.PutUint64(rev[:], rows[k].Revision)
		h.Write([]byte(k))
		h.Write([]byte{0})
		h.Write(rev[:])
	}
	return h.Sum64()
}

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
			if !out.add(WatchKey{Kind: "app", Tenant: v.Tenant, Name: v.App}, v) {
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
			if !out.add(WatchKey{Kind: "volume", Tenant: e.State.Scope().Tenant, Name: k}, e) {
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
			if !out.add(WatchKey{Kind: "network", Tenant: tenant, Name: n.ID}, n) {
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
				if !out.add(WatchKey{Kind: "node", Tenant: "", Name: node}, v) {
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
			if !out.add(WatchKey{Kind: "tenant", Tenant: t.ID, Name: t.ID}, t) {
				return nil, ErrCatalog
			}
		}
	case RegistriesKey:
		r, err := p.Registries(s)
		if err != nil {
			return nil, err
		}
		for _, e := range r.Entries() {
			if !out.add(WatchKey{Kind: "registry", Tenant: e.Spec.Tenant, Name: e.Spec.ID}, e) {
				return nil, ErrCatalog
			}
		}
	case RegistryMaintenanceKey:
		j, err := p.RegistryMaintenanceJobs(s)
		if err != nil {
			return nil, err
		}
		for _, row := range j.Records {
			if row.Change.External != nil {
				continue
			}
			if !out.add(WatchKey{Kind: "registry-maintenance", Tenant: row.Change.Tenant, Name: row.Change.RegistryID()}, row) {
				return nil, ErrCatalog
			}
		}
	case IngressManagementKey:
		b, err := p.IngressManagement(s)
		if err != nil {
			return nil, err
		}
		if !b.watchRecords(out) {
			return nil, ErrCatalog
		}
	case CertificatesKey:
		c, err := p.Certificates(s)
		if err != nil {
			return nil, err
		}
		for _, e := range c.Certificates {
			if !out.add(WatchKey{Kind: "certificate", Tenant: "", Name: e.Certificate.Metadata.ID.String()}, e) {
				return nil, ErrCatalog
			}
		}
		for _, d := range c.Domains {
			if !out.add(WatchKey{Kind: "domain", Tenant: "", Name: d.Name}, d) {
				return nil, ErrCatalog
			}
		}
		for _, g := range c.Grants {
			if !out.add(WatchKey{Kind: "host-grant", Tenant: g.Tenant, Name: g.Tenant + "/" + g.Host}, g) {
				return nil, ErrCatalog
			}
		}
		if c.ACMEResponder != nil && !out.add(WatchKey{Kind: "acme-responder", Tenant: "", Name: "acme-responder"}, c.ACMEResponder) {
			return nil, ErrCatalog
		}
	case VPSKey:
		v, err := p.VPS(s)
		if err != nil {
			return nil, err
		}
		for _, a := range v.Accounts {
			if !out.add(WatchKey{Kind: "vps", Name: "account/" + a.Name}, a) {
				return nil, ErrCatalog
			}
		}
		for _, x := range v.Servers {
			if !out.add(WatchKey{Kind: "vps", Name: "server/" + x.Name}, x) {
				return nil, ErrCatalog
			}
		}
	case NodeShellKey:
		b, err := p.NodeShells(s)
		if err != nil {
			return nil, err
		}
		if !out.add(WatchKey{Kind: "node-shell", Name: "policy"}, b.Policy) {
			return nil, ErrCatalog
		}
		for _, r := range b.Readiness {
			if !out.add(WatchKey{Kind: "node-shell", Name: "node/" + r.Node}, r) {
				return nil, ErrCatalog
			}
		}
		for _, r := range b.Records {
			if !out.add(WatchKey{Kind: "node-shell-session", Name: r.Session.SessionID, User: r.Session.User}, r) {
				return nil, ErrCatalog
			}
		}
	case services.ManagedDNSPrefix:
		sources, err := p.ManagedDNS(s)
		if err != nil {
			return nil, err
		}
		for _, v := range sources {
			if !out.add(WatchKey{Kind: "dns", Tenant: v.Definition.Tenant, Name: v.Definition.Network}, v) {
				return nil, ErrCatalog
			}
		}
	default:
		return nil, ErrCatalog
	}
	return out, nil
}

// watchRecords names the ingress book's records. Mappings are not here:
// they follow from app goals, whose "app" records already move.
func (b IngressManagement) watchRecords(out WatchRecords) bool {
	ok := true
	add := func(tenant, name string, v any) {
		ok = out.add(WatchKey{Kind: "ingress", Tenant: tenant, Name: name}, v) && ok
	}
	for _, r := range b.Blocks {
		add(r.Block.Tenant, "block/"+r.Block.ID, r)
	}
	for _, r := range b.Balances {
		add(r.Tenant, "balance/"+r.App+"/"+r.Route, r)
	}
	for _, r := range b.Drains {
		add(r.Tenant, "drain/"+r.App+"/"+r.Node, r)
	}
	for _, r := range b.NodeGatewaysRecords {
		add("", "gateway/"+r.Node, r)
	}
	for _, r := range b.ClusterAppRoutes {
		add("", "cluster-app-route/"+r.App, r)
	}
	for _, r := range b.History {
		add(r.Tenant, "history", r)
	}
	return ok
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
