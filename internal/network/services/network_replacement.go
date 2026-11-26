// SPDX-License-Identifier: Apache-2.0

package services

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/tenancy"
)

// RetiredNativeSource describes the exact old native generation. It is never
// Desired/Ready, and cannot authorize reopening a removed node's source.
type RetiredNativeSource struct {
	Key                  string
	Generation, Revision uint64
	Bridge               *network.BridgeSpec `json:",omitempty"`
	Tunnel               *network.TunnelSpec `json:",omitempty"`
}

func ownRetiredSources(sources []RetiredNativeSource) []RetiredNativeSource {
	q := slices.Clone(sources)
	for i := range q {
		if q[i].Bridge != nil {
			b := *q[i].Bridge
			b.Pools = slices.Clone(b.Pools)
			b.Lifecycle.Proof = slices.Clone(b.Lifecycle.Proof)
			q[i].Bridge = &b
		}
		if q[i].Tunnel != nil {
			t := q[i].Tunnel.Clone()
			q[i].Tunnel = &t
		}
	}
	return q
}

func validateRetiredSources(cluster [32]byte, archive RetiredNetwork) error {
	// A member that left alone (LeaveTUN) has no change record: its own
	// closure is the archive's Closed proof, checked by validateArchives.
	if len(archive.Sources) > 2 || len(archive.Sources) != 0 && (archive.Change == nil && archive.ChangeGeneration != 0 || archive.Sources[0].Bridge == nil) {
		return ErrLease
	}
	if archive.Change != nil {
		change := archive.Change
		if change.CheckRetired(cluster, archive.Network) != nil || change.SourceClosed == nil || change.Generation != archive.ChangeGeneration {
			return ErrLease
		}
		a, _ := json.Marshal(change.SourceClosed)
		b, _ := json.Marshal(archive.Closed)
		if !bytes.Equal(a, b) {
			return ErrLease
		}
	}
	owner := hex.EncodeToString(cluster[:]) + "/" + hex.EncodeToString(archive.Network.Owner[:])
	last := ""
	for _, source := range archive.Sources {
		identity, err := tenancy.ParseSourceIdentity(source.Key)
		if err != nil || source.Key <= last || source.Generation == 0 || source.Revision < source.Generation || identity.Tenant != archive.Network.Tenant || identity.Network != archive.Network.Logical || identity.Node != archive.Network.Node || (source.Bridge == nil) == (source.Tunnel == nil) {
			return ErrLease
		}
		last = source.Key
		if source.Bridge != nil {
			raw, _ := json.Marshal(source.Bridge)
			b, err := network.DecodeBridge(string(raw))
			if err != nil || identity.Kind != "bridge" || b.Owner != owner || b.Network != archive.Network.ID || b.Lifecycle.Drain || len(b.Pools) != len(archive.Network.Pools) {
				return ErrLease
			}
			for i, pool := range archive.Network.Pools {
				p := b.Pools[i]
				if p.ID != archive.Network.ID+"/"+pool.ID || p.Prefix != pool.Prefix || p.Gateway != pool.Gateway || p.MTU != pool.MTU || p.IPAM != pool.IPAM {
					return ErrLease
				}
			}
		} else {
			raw, _ := json.Marshal(source.Tunnel)
			t, err := network.DecodeTunnel(string(raw))
			if err != nil || identity.Kind != "tun" || t.Owner != owner || t.Network != tenancy.PacketNamespace(archive.Network.Tenant, archive.Network.Logical) || t.MTU != archive.Network.Pools[0].MTU || t.Lifecycle.Drain || !slices.Equal(t.Addresses, archive.Network.TunnelAddresses) {
				return ErrLease
			}
		}
	}
	return nil
}

// RetiredNetworks returns owned historical metadata for local journal recovery.
func (a Authority) RetiredNetworks() []RetiredNetwork {
	keys := make([]string, 0, len(a.archives))
	for key := range a.archives {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	q := make([]RetiredNetwork, 0, len(keys))
	for _, key := range keys {
		q = append(q, ownRetiredNetwork(a.archives[key]))
	}
	return q
}

// ReplaceTUN archives every original member/change before replacing the group.
// descriptors are exact closed source facts from the same committed FSM view.
func (a Authority) ReplaceTUN(c access.Catalog, n tenancy.Networks, quotas tenancy.Quotas, actor string, expected uint64, versions []tenancy.NetworkChangeVersion, target tenancy.TUNDefinition, descriptors map[string][]RetiredNativeSource) (Authority, tenancy.Networks, error) {
	if n.Cluster() != a.cluster || len(descriptors) != len(versions) {
		return a, n, ErrLease
	}
	for _, version := range versions {
		original, found := n.Network(version.Tenant, version.ID)
		if !found || !a.networkQuiescent(original) {
			return a, n, ErrLease
		}
	}
	next, err := n.ReplaceTUN(c, quotas, actor, expected, versions, target)
	if err != nil {
		return a, n, err
	}
	q := a
	for _, version := range versions {
		original, _ := n.Network(version.Tenant, version.ID)
		change, _ := n.Change(version.Tenant, version.ID)
		q, err = q.archiveNetwork(original, change.Generation, *change.SourceClosed)
		if err != nil {
			return a, n, err
		}
		archive := q.archives[retiredNetworkKey(original)]
		archive.Change = &change
		archive.Sources = ownRetiredSources(descriptors[version.ID])
		slices.SortFunc(archive.Sources, func(a, b RetiredNativeSource) int { return strings.Compare(a.Key, b.Key) })
		if len(archive.Sources) == 0 || validateRetiredSources(a.cluster, archive) != nil {
			return a, n, ErrLease
		}
		q.archives[retiredNetworkKey(original)] = ownRetiredNetwork(archive)
	}
	q, err = q.SyncPools(next)
	if err != nil {
		return a, n, err
	}
	if _, err := q.Encode(); err != nil {
		return a, n, err
	}
	return q, next, nil
}

// LeaveTUN retires one drained member of a TUN network on its own closure
// and keeps every other member: the caller rewrites their TUN route sets in
// place. sources are the leaving member's exact closed Bridge/TUN facts.
func (a Authority) LeaveTUN(c access.Catalog, n tenancy.Networks, actor string, p tenancy.NetworkClosure, sources []RetiredNativeSource) (Authority, tenancy.Networks, error) {
	v, live := n.Network(p.Tenant, p.Network)
	if !live || v.Logical == "" || n.Cluster() != a.cluster || !a.networkQuiescent(v) || len(sources) != 2 {
		return a, n, ErrLease
	}
	others := 0
	for _, m := range n.AllNetworks() {
		if m.Tenant == v.Tenant && m.Logical == v.Logical && m.ID != v.ID {
			others++
		}
	}
	if others == 0 {
		return a, n, ErrLease
	}
	next, err := n.Retire(c, actor, p)
	if err != nil {
		return a, n, err
	}
	q, err := a.archiveNetwork(v, 0, p)
	if err != nil {
		return a, n, err
	}
	archive := q.archives[retiredNetworkKey(v)]
	archive.Sources = ownRetiredSources(sources)
	slices.SortFunc(archive.Sources, func(a, b RetiredNativeSource) int { return strings.Compare(a.Key, b.Key) })
	if validateRetiredSources(a.cluster, archive) != nil {
		return a, n, ErrLease
	}
	q.archives[retiredNetworkKey(v)] = ownRetiredNetwork(archive)
	if q, err = q.SyncPools(next); err != nil {
		return a, n, err
	}
	if _, err = q.Encode(); err != nil {
		return a, n, err
	}
	return q, next, nil
}
