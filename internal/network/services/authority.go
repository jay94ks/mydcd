// SPDX-License-Identifier: Apache-2.0

package services

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/tenancy"
	"net/netip"
	"slices"
	"strings"
)

var ErrLease = errors.New("network authority, address, time or revision conflict")

const maxRecords = 4096

// Source binds DNS and route consumers to a committed CIDR owner/pool.
type Source struct {
	Cluster                     [32]byte
	Tenant, Network, Pool, Node string
	Owner                       [32]byte
	NetworkGeneration           uint64
	Prefix                      netip.Prefix
	Gateway                     netip.Addr
	MTU                         int
}

// Authority shares the committed IPAM Book with DNS/route references. Actual
// container addressing is applied by Docker IPAM; this is not a DHCP server.
type Authority struct {
	cluster    [32]byte
	revision   uint64
	at         int64
	book       network.Book
	references referenceState
	archives   map[string]RetiredNetwork
}

func NewAuthority(cluster [32]byte, shared network.Book) (Authority, error) {
	book, err := network.Restore(shared.Checkpoint())
	if cluster == ([32]byte{}) || err != nil {
		return Authority{}, ErrLease
	}
	for _, v := range book.Checkpoint().Allocations {
		if strings.HasPrefix(v.Endpoint, "dhcp/") {
			return Authority{}, ErrLease
		}
	}
	a := Authority{cluster: cluster, book: book, archives: map[string]RetiredNetwork{}}
	a.references.init()
	return a, nil
}

func id(s string) bool {
	if len(s) < 1 || len(s) > 63 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func serviceKey(tenant, name string) string   { return tenant + "/" + name }
func fullPool(s Source) string                { return s.Tenant + "/" + s.Network + "/" + s.Pool }
func poolOwner(s Source) string               { return hex.EncodeToString(s.Owner[:]) }
func (a Authority) Revision() uint64          { return a.revision }
func (a Authority) LastProposalAt() int64     { return a.at }
func (a Authority) Cluster() [32]byte         { return a.cluster }
func (a Authority) AddressBook() network.Book { return a.book }

func (a Authority) WithCommittedStaticAllocation(v network.Allocation, networkID string) (Authority, error) {
	if strings.HasPrefix(v.Endpoint, "dhcp/") {
		return a, ErrLease
	}
	pool, known := a.book.Pool(v.Pool)
	if !known || pool.Network != networkID || pool.Owner != v.Owner {
		return a, ErrLease
	}
	if old, found := a.book.Allocation(v.Endpoint); found {
		if old != v {
			return a, ErrLease
		}
		return a, nil
	}
	book, err := a.book.WithCommittedAllocation(v.Endpoint, v.Owner, networkID, v.Generation, v.Address)
	got, found := book.Allocation(v.Endpoint)
	if err != nil || !found || got != v {
		return a, ErrLease
	}
	q, err := a.clone()
	if err != nil {
		return a, err
	}
	q.book = book
	return q, nil
}

func (a Authority) ResizeAddresses(capacity int) (Authority, error) {
	book, e := a.book.Resize(capacity)
	if e != nil {
		return a, ErrLease
	}
	q, e := a.clone()
	if e != nil {
		return a, e
	}
	q.book = book
	return q, nil
}

func (a Authority) SyncPools(n tenancy.Networks) (Authority, error) {
	if n.Cluster() != a.cluster {
		return a, ErrLease
	}
	desired, e := n.AddressPlan(1)
	if e != nil {
		return a, ErrLease
	}
	current := map[string]network.Pool{}
	for _, p := range a.book.Checkpoint().Pools {
		current[p.ID] = p
	}
	book := a.book
	changed := false
	for _, p := range desired.Checkpoint().Pools {
		if old, exists := current[p.ID]; exists {
			x, y := old, p
			x.Draining = false
			y.Draining = false
			if x != y || old.Draining && !p.Draining {
				return a, ErrLease
			}
			if p.Draining && !old.Draining {
				book, e = book.DrainPool(p.ID, p.Owner)
				changed = true
			}
		} else {
			book, e = book.AddPool(p)
			changed = true
		}
		if e != nil {
			return a, ErrLease
		}
	}
	if !changed {
		return a, nil
	}
	q, e := a.clone()
	if e != nil {
		return a, e
	}
	q.book = book
	return q, nil
}

func (a Authority) clone() (Authority, error) {
	if a.cluster == ([32]byte{}) || a.revision == ^uint64(0) {
		return a, ErrLease
	}
	q := a
	q.references = a.references.clone()
	q.archives = map[string]RetiredNetwork{}
	for k, v := range a.archives {
		q.archives[k] = ownRetiredNetwork(v)
	}
	q.revision++
	return q, nil
}

func source(n tenancy.Networks, cluster [32]byte, tenant, name, pool string) (Source, bool) {
	v, ok := n.Network(tenant, name)
	if !ok || n.Cluster() != cluster || v.Draining {
		return Source{}, false
	}
	return retainedSource(n, cluster, tenant, name, pool)
}

// retainedSource identifies an existing resource for positive cleanup only.
// Fresh serving/admission continues to use source/currentSource.
func retainedSource(n tenancy.Networks, cluster [32]byte, tenant, name, pool string) (Source, bool) {
	v, ok := n.Network(tenant, name)
	if !ok || n.Cluster() != cluster {
		return Source{}, false
	}
	for _, p := range v.Pools {
		if p.ID == pool {
			return Source{cluster, tenant, name, pool, v.Node, v.Owner, v.Generation, p.Prefix, p.Gateway, p.MTU}, true
		}
	}
	return Source{}, false
}

func currentSource(c access.Catalog, n tenancy.Networks, s Source) bool {
	t, ok := c.Tenant(s.Tenant)
	if !ok || !t.Enabled || t.Phase != access.TenantActive || !slices.Contains(t.AllowedNodes, s.Node) {
		return false
	}
	v, ok := source(n, s.Cluster, s.Tenant, s.Network, s.Pool)
	return ok && v == s
}

func (a Authority) ReserveStatic(endpoint, owner, networkID, pool string, generation uint64, want netip.Addr) (Authority, network.Allocation, error) {
	if pool == "" || strings.HasPrefix(endpoint, "dhcp/") {
		return a, network.Allocation{}, ErrLease
	}
	if old, ok := a.book.Allocation(endpoint); ok {
		if a.addressFenced(old) {
			return a, network.Allocation{}, ErrLease
		}
		book, alloc, err := a.book.Reserve(endpoint, owner, networkID, pool, generation, want)
		if err != nil || alloc != old {
			return a, network.Allocation{}, ErrLease
		}
		q := a
		q.book = book
		return q, alloc, nil
	}
	// Explicit addresses are required by typed static task declarations.
	if !want.IsValid() {
		return a, network.Allocation{}, ErrLease
	}
	book, alloc, err := a.book.Reserve(endpoint, owner, networkID, pool, generation, want)
	if err != nil {
		return a, network.Allocation{}, ErrLease
	}
	q, err := a.clone()
	if err != nil {
		return a, network.Allocation{}, err
	}
	q.book = book
	return q, alloc, nil
}

func (a Authority) ReleaseStatic(alloc network.Allocation, proof AddressOwnerClose, now int64) (Authority, error) {
	if strings.HasPrefix(alloc.Endpoint, "dhcp/") {
		return a, ErrLease
	}
	f, exists := a.AddressRetirement(alloc)
	if !exists || f.ReclaimedRevision != 0 || !a.referencesSettled(f) || !validAddressOwnerClose(a.cluster, f, proof, now) {
		return a, ErrLease
	}
	book, err := a.book.Release(alloc)
	if err != nil {
		return a, ErrLease
	}
	q, err := a.clone()
	if err != nil {
		return a, err
	}
	q.book = book
	f.ReclaimedRevision = q.revision
	v := proof
	v.Signature = slices.Clone(v.Signature)
	f.OwnerClose = &v
	q.references.Fences[f.ID] = f
	q.at = max(q.at, now)
	return q, nil
}

func verifyOwner(s Source, raw, sig []byte) bool {
	return ed25519.Verify(ed25519.PublicKey(s.Owner[:]), raw, sig)
}
