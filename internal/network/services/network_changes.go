// SPDX-License-Identifier: Apache-2.0

package services

import (
	"crypto/ed25519"
	"encoding/json"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/tenancy"
)

// RetiredNetwork preserves original CIDR ownership and positive closure read-only.
// It is not an operational allocator or a second source of admission authority.
type RetiredNetwork struct {
	Network                    tenancy.Network
	ChangeGeneration, Revision uint64
	At                         int64
	Closed                     tenancy.NetworkClosure
	Services                   []json.RawMessage
	Clients                    []json.RawMessage
	Leases                     []json.RawMessage
	Change                     *tenancy.NetworkChange `json:",omitempty"`
	Sources                    []RetiredNativeSource  `json:",omitempty"`
}

func retiredNetworkKey(n tenancy.Network) string {
	return serviceKey(n.Tenant, n.ID) + "/" + generationText(n.Generation)
}
func ownRetiredNetwork(v RetiredNetwork) RetiredNetwork {
	v.Network.Pools = slices.Clone(v.Network.Pools)
	v.Network.TunnelAddresses = slices.Clone(v.Network.TunnelAddresses)
	v.Closed.Signature = slices.Clone(v.Closed.Signature)
	if v.Change != nil {
		change := v.Change.Clone()
		v.Change = &change
	}
	v.Sources = ownRetiredSources(v.Sources)
	return v
}
func (a Authority) RetiredNetwork(tenant, id string, generation uint64) (RetiredNetwork, bool) {
	v, ok := a.archives[serviceKey(tenant, id)+"/"+generationText(generation)]
	return ownRetiredNetwork(v), ok
}
func belongsToNetwork(s Source, v tenancy.Network) bool {
	return s.Tenant == v.Tenant && s.Network == v.ID && s.NetworkGeneration == v.Generation && s.Node == v.Node && s.Owner == v.Owner
}

// BeginNetworkChangeDrain publishes the catalog Drain and the SAME Book's pool
// Drain together. The candidate is not a native shutdown or lease revocation.
func (a Authority) BeginNetworkChangeDrain(c access.Catalog, n tenancy.Networks, actor, tenant, id string, generation, expected uint64) (Authority, tenancy.Networks, error) {
	next, e := n.BeginChangeDrain(c, actor, tenant, id, generation, expected)
	if e != nil {
		return a, n, e
	}
	q, e := a.SyncPools(next)
	if e != nil {
		return a, n, e
	}
	return q, next, nil
}
func (a Authority) networkQuiescent(n tenancy.Network) bool {
	for _, alloc := range a.book.Checkpoint().Allocations {
		if strings.HasPrefix(alloc.Pool, serviceKey(n.Tenant, n.ID)+"/") {
			return false
		}
	}
	for _, c := range a.references.Consumers {
		if c.Closed != nil {
			continue
		}
		if belongsToNetwork(c.Local, n) {
			return false
		}
		for _, m := range c.Members {
			if belongsToNetwork(m.Source, n) {
				return false
			}
		}
	}
	return true
}

// NetworkReferencesSettled is a read-only preflight over the SAME Book and
// reference predicate used by Fence/Commit/Retire. It proves neither native
// absence nor current authority, and cannot authorize reuse by itself.
func (a Authority) NetworkReferencesSettled(n tenancy.Network) bool {
	return n.Tenant != "" && n.ID != "" && n.Generation != 0 && n.Owner != ([32]byte{}) && a.networkQuiescent(n)
}
func (a Authority) FenceNetworkChange(c access.Catalog, n tenancy.Networks, actor, tenant, id string, generation, expected uint64, p tenancy.NetworkClosure) (Authority, tenancy.Networks, error) {
	v, ok := n.Network(tenant, id)
	if !ok || n.Cluster() != a.cluster || !a.networkQuiescent(v) {
		return a, n, ErrLease
	}
	next, e := n.FenceChange(c, actor, tenant, id, generation, expected, p)
	if e != nil {
		return a, n, e
	}
	return a, next, nil
}
func (a Authority) archiveNetwork(v tenancy.Network, generation uint64, proof tenancy.NetworkClosure) (Authority, error) {
	if !a.networkQuiescent(v) || len(a.archives) >= maxRecords {
		return a, ErrLease
	}
	key := retiredNetworkKey(v)
	if _, exists := a.archives[key]; exists {
		return a, ErrLease
	}
	q, e := a.CompactReferences()
	if e != nil {
		return a, e
	}
	old := RetiredNetwork{Network: v, ChangeGeneration: generation, Revision: q.revision, At: q.at, Closed: proof}
	for _, p := range v.Pools {
		pool := serviceKey(v.Tenant, v.ID) + "/" + p.ID
		owner := poolOwner(Source{Owner: v.Owner})
		q.book, e = q.book.DrainPool(pool, owner)
		if e != nil {
			return a, e
		}
		q.book, e = q.book.RemovePool(pool, owner)
		if e != nil {
			return a, e
		}
	}
	q.archives[key] = ownRetiredNetwork(old)
	if e = q.validateArchives(); e != nil {
		return a, e
	}
	return q, nil
}

// CommitNetworkChange atomically retires old Book pools and admission, retains
// completed original metadata/floors and publishes new owner/generation pools.
// Target native preparation/installation is a separate local journal boundary.
func (a Authority) CommitNetworkChange(c access.Catalog, n tenancy.Networks, actor, tenant, id string, generation, expected uint64) (Authority, tenancy.Networks, error) {
	return a.CommitNetworkChanges(c, n, actor, []tenancy.NetworkChangeVersion{{Tenant: tenant, ID: id, Generation: generation, Revision: expected}})
}

func (a Authority) CommitNetworkChanges(c access.Catalog, n tenancy.Networks, actor string, versions []tenancy.NetworkChangeVersion) (Authority, tenancy.Networks, error) {
	if n.Cluster() != a.cluster || len(versions) == 0 || len(versions) > 32 {
		return a, n, ErrLease
	}
	for _, version := range versions {
		v, live := n.Network(version.Tenant, version.ID)
		if !live || !a.networkQuiescent(v) {
			return a, n, ErrLease
		}
	}
	next, e := n.CommitChanges(c, actor, versions)
	if e != nil {
		return a, n, e
	}
	q := a
	for _, version := range versions {
		v, _ := n.Network(version.Tenant, version.ID)
		ch, _ := n.Change(version.Tenant, version.ID)
		q, e = q.archiveNetwork(v, version.Generation, *ch.SourceClosed)
		if e != nil {
			return a, n, e
		}
	}
	q, e = q.SyncPools(next)
	if e != nil {
		return a, n, e
	}
	if _, e = q.Encode(); e != nil {
		return a, n, e
	}
	return q, next, nil
}
func (a Authority) RetireNetwork(c access.Catalog, n tenancy.Networks, actor string, p tenancy.NetworkClosure) (Authority, tenancy.Networks, error) {
	v, live := n.Network(p.Tenant, p.Network)
	if !live || n.Cluster() != a.cluster || !a.networkQuiescent(v) {
		return a, n, ErrLease
	}
	next, e := n.Retire(c, actor, p)
	if e != nil {
		return a, n, e
	}
	q, e := a.archiveNetwork(v, 0, p)
	if e != nil {
		return a, n, e
	}
	if _, e = q.Encode(); e != nil {
		return a, n, e
	}
	return q, next, nil
}

func (a Authority) validateArchives() error {
	if len(a.archives) > maxRecords {
		return ErrLease
	}
	for key, v := range a.archives {
		n, p := v.Network, v.Closed
		if key != retiredNetworkKey(n) || n.Generation == 0 || v.ChangeGeneration != n.PendingChange || n.Revision < n.Generation || !n.Draining || v.Revision == 0 || v.Revision > a.revision || v.At < 0 || v.At > a.at || len(n.Pools) < 1 || len(n.Pools) > 16 || p.Cluster != a.cluster || p.Tenant != n.Tenant || p.Network != n.ID || p.Node != n.Node || p.Owner != n.Owner || p.Generation != n.Generation || p.Revision != n.Revision || !p.NativeGone || p.PendingEndpoints != 0 || p.PendingFlows != 0 || p.PendingPins != 0 || !ed25519.Verify(ed25519.PublicKey(p.Owner[:]), tenancy.NetworkClosureBytes(p), p.Signature) {
			return ErrLease
		}
		if len(v.Services) != 0 || len(v.Clients) != 0 || len(v.Leases) != 0 {
			return ErrLease
		}
		if validateRetiredSources(a.cluster, v) != nil {
			return ErrLease
		}
		book, e := network.NewBook(1)
		if e != nil {
			return ErrLease
		}
		for i, p := range n.Pools {
			if !id(p.ID) || i > 0 && p.ID <= n.Pools[i-1].ID {
				return ErrLease
			}
			book, e = book.AddPool(network.Pool{ID: serviceKey(n.Tenant, n.ID) + "/" + p.ID, Network: serviceKey(n.Tenant, n.ID), Owner: poolOwner(Source{Owner: n.Owner}), Prefix: p.Prefix, Gateway: p.Gateway, MTU: p.MTU, IPAM: p.IPAM, Draining: true})
			if e != nil {
				return ErrLease
			}
		}
		if _, e = network.Restore(book.Checkpoint()); e != nil {
			return ErrLease
		}
	}
	return nil
}
