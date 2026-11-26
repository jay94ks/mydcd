// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"slices"
	"strings"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/tenancy"
)

type NetworkBinding struct{ NetworkID, SourceKey string }

// NetworkReference owns only an app's borrow. Source is an immutable committed
// identity, not a string allowing arbitrary Docker network adoption. The native
// adapter must acquire that exact bridge generation and persist the reference
// before publishing Applied. Released/Gone refers to the borrow, not its source.
type NetworkReference struct {
	CatalogGeneration, CatalogRevision uint64
	Schema                             uint8
	Tenant, Network, Node              string
	Owner                              [32]byte
	Source                             ObjectRef
	Spec                               [32]byte
	Pools                              []tenancy.Subnet
	RetainSource                       bool
	ManagedName                        string             `json:",omitempty"`
	PacketNetwork                      string             `json:",omitempty"`
	ManagedSources                     []NetworkSourceRef `json:",omitempty"`
	Routes                             []netip.Prefix     `json:",omitempty"`
}

type NetworkSourceRef struct {
	Source ObjectRef
	Spec   [32]byte
}

// Namespace preserves the packet identity frozen in an accepted reference.
// A legacy single-owner reference has only its native network identity.
func (r NetworkReference) Namespace() string {
	if r.PacketNetwork != "" {
		return r.PacketNetwork
	}
	return r.Network
}

// LocalTunnel selects only the exact node-local dependency recorded by the
// accepted plan. It neither discovers a replacement nor borrows a native FD.
func (r NetworkReference) LocalTunnel() (ObjectRef, bool) {
	identity := tenancy.SourceIdentity{Kind: "tun", Tenant: r.Tenant, Network: r.ManagedName, Node: r.Node}
	key := identity.Key()
	if key == "" {
		return ObjectRef{}, false
	}
	for _, source := range r.ManagedSources {
		if source.Source.Key == key {
			return source.Source, true
		}
	}
	return ObjectRef{}, false
}

func scopedBridgeKey(key, tenant string) bool {
	if source, err := tenancy.ParseSourceIdentity(key); err == nil {
		return source.Kind == "bridge" && source.Tenant == tenant
	}
	parts := strings.Split(key, "/")
	if len(parts) < 5 || parts[0] != "network" || parts[1] != "bridge" || parts[2] != tenant {
		return false
	}
	for _, p := range parts[2:] {
		if !identifier(p) {
			return false
		}
	}
	return true
}

// A named app reference selects only one already registered exact source.
// Matching a native-looking name without the committed catalog is insufficient.
// The native consumer must still acquire/read back that original generation.
func currentNetworkBinding(ctx PlanningContext, tenant, node, name string) (NetworkBinding, error) {
	if _, ok := ctx.Networks.NamedNetwork(tenant, name, node); !ok {
		return NetworkBinding{}, inputError("EXTERNAL_NETWORK_NOT_CURRENT", name)
	}
	var found NetworkBinding
	for _, key := range mapKeys(ctx.Current) {
		if !scopedBridgeKey(key, tenant) {
			continue
		}
		candidate := NetworkBinding{NetworkID: name, SourceKey: key}
		if _, err := resolveNetworkReference(ctx, tenant, node, name, candidate); err != nil {
			continue
		}
		if found.SourceKey != "" {
			return NetworkBinding{}, inputError("EXTERNAL_NETWORK_AMBIGUOUS", name)
		}
		found = candidate
	}
	if found.SourceKey == "" {
		return NetworkBinding{}, inputError("EXTERNAL_NETWORK_BINDING_REQUIRED", name)
	}
	return found, nil
}
func resolveNetworkReference(ctx PlanningContext, tenant, node, name string, binding NetworkBinding) (NetworkReference, error) {
	return resolveNetworkReferenceFor(ctx, tenant, node, name, binding, nil)
}

func resolveNetworkReferenceFor(ctx PlanningContext, tenant, node, name string, binding NetworkBinding, retained *NetworkReference) (NetworkReference, error) {
	if binding.NetworkID != name || !scopedBridgeKey(binding.SourceKey, tenant) {
		return NetworkReference{}, inputError("EXTERNAL_NETWORK_SCOPE", name)
	}
	n, ok := ctx.Networks.NamedNetwork(tenant, name, node)
	if retained != nil {
		// Only an already accepted reference can select its original catalog
		// row while a candidate reserves capacity. This is not fresh admission:
		// the caller compares the complete reconstructed reference below.
		n, ok = ctx.Networks.Network(tenant, retained.Network)
		ok = ok && n.Logical == retained.ManagedName && (n.Logical == name || n.Logical == "" && n.ID == name)
	}
	peer, admitted := ctx.Nodes[node]
	source, exists := ctx.Current[binding.SourceKey]
	if !ok || !admitted || n.Draining || n.Node != node || !peer.resourceIdentity(ctx.Cluster, node, n.Owner) || !exists || !source.Present || source.Generation == 0 || source.Revision < source.Generation {
		return NetworkReference{}, inputError("EXTERNAL_NETWORK_NOT_CURRENT", name)
	}
	// App-created schema1 bridge goals and the existing R3 typed bridge format
	// are both readable. Neither path writes or relabels the source object.
	var g GoalCommand
	var pools []tenancy.Subnet
	if json.Unmarshal([]byte(source.Value), &g) == nil && g.Schema == 1 && g.Kind == "bridge" && g.Cluster == ctx.Cluster && g.Tenant == tenant && g.Node == node && g.Owner == n.Owner {
		if g.Lifecycle != nil {
			return NetworkReference{}, inputError("EXTERNAL_NETWORK_DRAINING", name)
		}
		var bridge struct {
			Network string
			MTU     int
			Pool    PoolDeclaration
		}
		if json.Unmarshal(g.Config, &bridge) != nil || PoolID(tenant, g.App, bridge.Network, node) != name || ResourceKey("bridge", tenant, g.App, bridge.Network+"/"+node) != binding.SourceKey {
			return NetworkReference{}, inputError("EXTERNAL_NETWORK_IDENTITY", name)
		}
		pools = []tenancy.Subnet{{ID: "pool", Prefix: mustPrefix(bridge.Pool.CIDR), Gateway: mustAddr(bridge.Pool.Gateway), MTU: bridge.MTU}}
	} else {
		s, e := network.DecodeBridge(source.Value)
		owner := hex.EncodeToString(ctx.Cluster[:]) + "/" + hex.EncodeToString(n.Owner[:])
		if e != nil || s.Lifecycle.Drain || s.Network != n.ID || s.Owner != owner {
			return NetworkReference{}, inputError("EXTERNAL_NETWORK_IDENTITY", name)
		}
		for _, p := range s.Pools {
			pools = append(pools, tenancy.Subnet{ID: p.ID, Prefix: p.Prefix, Gateway: p.Gateway, MTU: p.MTU, IPAM: p.IPAM})
		}
	}
	if len(pools) != len(n.Pools) {
		return NetworkReference{}, inputError("EXTERNAL_NETWORK_POOL_MISMATCH", name)
	}
	for _, pool := range pools {
		if !slices.ContainsFunc(n.Pools, func(p tenancy.Subnet) bool {
			return p.Prefix == pool.Prefix && p.Gateway == pool.Gateway && p.MTU == pool.MTU && p.IPAM == pool.IPAM
		}) {
			return NetworkReference{}, inputError("EXTERNAL_NETWORK_POOL_MISMATCH", name)
		}
	}
	ref := NetworkReference{Schema: 1, Tenant: tenant, Network: n.ID, Node: node, Owner: n.Owner, Source: ObjectRef{binding.SourceKey, source.Revision, source.Generation}, CatalogGeneration: n.Generation, CatalogRevision: n.Revision, Spec: sha256.Sum256([]byte(source.Value)), Pools: slices.Clone(n.Pools), RetainSource: true}
	if n.Logical != "" {
		rows, err := ctx.Networks.TUNSources(tenant, n.Logical)
		if err != nil {
			return NetworkReference{}, err
		}
		ref.ManagedName = n.Logical
		ref.PacketNetwork = tenancy.PacketNamespace(tenant, n.Logical)
		local := false
		for _, row := range rows {
			if row.Network.Draining {
				return NetworkReference{}, inputError("EXTERNAL_NETWORK_DRAINING", name)
			}
			if row.Network.Node == node {
				if row.BridgeKey != binding.SourceKey {
					return NetworkReference{}, inputError("EXTERNAL_NETWORK_IDENTITY", name)
				}
				local = true
				if row.Tunnel != nil {
					ref.Routes = slices.Clone(row.Tunnel.Routes)
				}
			}
			for _, key := range []string{row.BridgeKey, row.TunnelKey} {
				if key == "" {
					continue
				}
				o, exists := ctx.Current[key]
				expected, _ := json.Marshal(row.Bridge)
				if key == row.TunnelKey {
					expected, _ = json.Marshal(row.Tunnel)
				}
				if !exists || !o.Present || o.Generation == 0 || o.Revision < o.Generation || o.Value != string(expected) {
					return NetworkReference{}, inputError("EXTERNAL_NETWORK_NOT_CURRENT", name)
				}
				ref.ManagedSources = append(ref.ManagedSources, NetworkSourceRef{Source: ObjectRef{key, o.Revision, o.Generation}, Spec: sha256.Sum256([]byte(o.Value))})
			}
		}
		if !local {
			return NetworkReference{}, inputError("EXTERNAL_NETWORK_NOT_CURRENT", name)
		}
	}
	return ref, nil
}
func (r NetworkReference) Check(ctx PlanningContext) error {
	return r.check(ctx, false)
}

// CheckRetained validates an already accepted reference without granting new
// use. A pending candidate may coexist with its exact original catalog/source
// identities; Drain, source replacement or a changed generation still fail.
// New plans and actual native/Task admission must continue to use Check.
func (r NetworkReference) CheckRetained(ctx PlanningContext) error {
	return r.check(ctx, true)
}

func (r NetworkReference) check(ctx PlanningContext, retained bool) error {
	name := r.Network
	if r.ManagedName != "" {
		name = r.ManagedName
	}
	var frozen *NetworkReference
	if retained {
		frozen = &r
	}
	current, e := resolveNetworkReferenceFor(ctx, r.Tenant, r.Node, name, NetworkBinding{name, r.Source.Key}, frozen)
	if e != nil {
		return e
	}
	a, _ := json.Marshal(current)
	b, _ := json.Marshal(r)
	if !bytes.Equal(a, b) {
		return inputError("EXTERNAL_NETWORK_CHANGED", r.Network)
	}
	return nil
}
func acceptsReferenceAddress(ref NetworkReference, address string) bool {
	ip := mustAddr(address)
	if !ip.IsValid() {
		return false
	}
	for _, p := range ref.Pools {
		if p.Prefix.Contains(ip) && ip != p.Gateway && ip != p.Prefix.Addr() {
			return true
		}
	}
	return false
}

// ReferenceBridge reads the exact frozen source, without granting a new use.
// Current catalog/ACL/quorum admission remains in Check and the owner permit.
func ReferenceBridge(cluster [32]byte, ref NetworkReference, objects map[string]state.Object) (network.BridgeSpec, error) {
	return referenceBridge(cluster, ref, objects, false)
}

func referenceBridge(cluster [32]byte, ref NetworkReference, objects map[string]state.Object, retained bool) (network.BridgeSpec, error) {
	o, exists := objects[ref.Source.Key]
	if ref.Schema != 1 || !ref.RetainSource || !scopedBridgeKey(ref.Source.Key, ref.Tenant) || !exists || !o.Present || o.Generation != ref.Source.Generation || o.Revision != ref.Source.Revision || sha256.Sum256([]byte(o.Value)) != ref.Spec {
		return network.BridgeSpec{}, ErrInputs
	}
	for _, source := range ref.ManagedSources {
		actual, exists := objects[source.Source.Key]
		if !exists || !actual.Present || actual.Generation != source.Source.Generation || actual.Revision != source.Source.Revision || sha256.Sum256([]byte(actual.Value)) != source.Spec {
			return network.BridgeSpec{}, ErrInputs
		}
	}
	b, err := network.DecodeBridge(o.Value)
	if err != nil {
		goal, e := DecodeGoalResources(cluster, ref.Source.Key, o)
		if e != nil || goal.Bridge == nil {
			return network.BridgeSpec{}, ErrInputs
		}
		b = *goal.Bridge
	}
	owner := hex.EncodeToString(cluster[:]) + "/" + hex.EncodeToString(ref.Owner[:])
	if b.Network != ref.Network || b.Owner != owner || !retained && b.Lifecycle.Drain || len(b.Pools) != len(ref.Pools) {
		return network.BridgeSpec{}, ErrInputs
	}
	for _, pool := range b.Pools {
		if !slices.ContainsFunc(ref.Pools, func(p tenancy.Subnet) bool {
			return p.Prefix == pool.Prefix && p.Gateway == pool.Gateway && p.MTU == pool.MTU && p.IPAM == pool.IPAM
		}) {
			return network.BridgeSpec{}, ErrInputs
		}
	}
	return b, nil
}
