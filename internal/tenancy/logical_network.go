// SPDX-License-Identifier: Apache-2.0

package tenancy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/network"
)

// TUNDefinition reserves one named management network and all its node-local
// pools in the existing catalog. Owners are resolved from committed membership
// by the caller; this core does not turn self-asserted keys into membership.
type TUNDefinition struct {
	Tenant, Name string
	Members      []TUNNode
	GatewayMode  string `json:",omitempty"`
	System       bool   `json:",omitempty"` // the system network: Tenant "", Name SystemNetwork
	// Toggles are the options to turn on (NetworkToggle). ToggleLocal needs
	// exactly one member.
	Toggles []NetworkToggle `json:",omitempty"`
}

type TUNNode struct {
	Node  string
	Owner [32]byte
	Pools []Subnet
	// Addresses is left empty: the tunnel address is the server's reserved
	// address (SystemPolicy.Nodes), which sfcd fills in.
	Addresses []netip.Prefix `json:",omitempty"`
}

// fillTunnel gives a joining member its server's fixed address. A
// definition may not name another one.
func (n Networks) fillTunnel(member TUNNode) ([]netip.Prefix, bool) {
	a, ok := n.NodeAddress(member.Node)
	tunnel := []netip.Prefix{netip.PrefixFrom(a, 32)}
	if !ok || len(member.Addresses) != 0 && !slices.Equal(member.Addresses, tunnel) {
		return nil, false
	}
	return tunnel, true
}

type TUNSource struct {
	Network              Network
	BridgeKey, TunnelKey string
	Bridge               network.BridgeSpec
	Tunnel               *network.TunnelSpec
}

func logicalMemberID(tenant, name, node string) string {
	h := sha256.Sum256([]byte("sfc-managed-network-member-1\x00" + tenant + "/" + name + "/" + node))
	return "mtn-" + hex.EncodeToString(h[:28])
}

func validLogicalMember(v Network) bool {
	if v.Logical == "" {
		return len(v.TunnelAddresses) == 0
	}
	// One IPv4 tunnel address: the server's address (validateLogicalNetworks
	// checks it against SystemPolicy.Nodes).
	if !validID(v.Logical) || v.ID != logicalMemberID(v.Tenant, v.Logical, v.Node) || len(v.TunnelAddresses) != 1 {
		return false
	}
	if p := v.TunnelAddresses[0]; !p.IsValid() || !p.Addr().Is4() || p.Bits() != 32 {
		return false
	}
	// IPv6 pools ride the same TUN: its routes need no IPv6 address.
	for _, p := range v.Pools {
		if p.MTU != v.Pools[0].MTU {
			return false
		}
	}
	return true
}

// reservationPrefixes are what a network keeps for itself: its pools. A
// tunnel address is the server's address, shared by all its networks.
func reservationPrefixes(v Network) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(v.Pools))
	for _, p := range v.Pools {
		out = append(out, p.Prefix)
	}
	return out
}

func reservationsOverlap(a, b Network) bool {
	for _, p := range reservationPrefixes(a) {
		for _, q := range reservationPrefixes(b) {
			if p.Overlaps(q) {
				return true
			}
		}
	}
	return false
}

// validateLogicalNetworks also runs when old/native projections join the
// catalog, so TUN host addresses cannot be reused as later app/native pools.
func (n Networks) validateLogicalNetworks() error {
	for _, v := range n.networks {
		if !validLogicalMember(v) {
			return ErrPolicy
		}
		if v.Logical == "" {
			continue
		}
		// The tunnel address is the server's (checked where the view knows
		// the servers: every change goes through one that does).
		if a, ok := n.NodeAddress(v.Node); n.servers != nil && (!ok || v.TunnelAddresses[0] != netip.PrefixFrom(a, 32)) || !network.ServerBlock.Contains(v.TunnelAddresses[0].Addr()) {
			return ErrPolicy
		}
		// The cluster and server blocks are no network's pool.
		if slices.ContainsFunc(v.Pools, func(p Subnet) bool {
			return p.Prefix.Overlaps(network.ServerBlock) || p.Prefix.Overlaps(network.ClusterBlock)
		}) {
			return ErrPolicy
		}
		for k, other := range n.networks {
			if k == key(v.Tenant, v.ID) {
				continue
			}
			if reservationsOverlap(v, other) {
				return ErrPolicy
			}
			if v.Tenant == other.Tenant && (other.ID == v.Logical || other.Logical == v.Logical && (other.Node == v.Node || other.Owner == v.Owner || other.Pools[0].MTU != v.Pools[0].MTU || other.GatewayMode != v.GatewayMode)) {
				return ErrPolicy
			}
		}
	}
	return nil
}

// CreateTUN is all-or-nothing and advances the catalog once, irrespective of
// node count. It uses the existing pool allocator and network quotas; no
// parallel registry, address authority or partially accepted member is created.
func (n Networks) CreateTUN(c access.Catalog, quotas Quotas, actor string, expected uint64, d TUNDefinition) (Networks, error) {
	if d.System || !validID(d.Tenant) {
		return n, ErrPolicy
	}
	return n.createTUN(quotas, expected, d, func(v Network, q Networks) error {
		return quotas.AdmitNetwork(c, actor, v.Tenant, v.Node, v.Owner, q)
	})
}

// CreateSystemTUN creates the system network (no tenant, System set) through
// the same reservation, pool and quota rules as CreateTUN. It checks no user:
// only sfcd's cluster app dependency reaches it, never a tenant network action.
// Members count against each node's server-wide network limit only.
func (n Networks) CreateSystemTUN(quotas Quotas, expected uint64, d TUNDefinition) (Networks, error) {
	if !d.System || d.Tenant != "" || d.Name != SystemNetwork {
		return n, ErrPolicy
	}
	// Every work server is a member, so the system network is never local.
	if len(d.Toggles) != 0 {
		return n, ErrPolicy
	}
	return n.createTUN(quotas, expected, d, func(v Network, q Networks) error {
		return quotas.admitScopes(v.Tenant, v.Node, v.Owner, q)
	})
}

func (n Networks) createTUN(quotas Quotas, expected uint64, d TUNDefinition, admit func(Network, Networks) error) (Networks, error) {
	if expected != n.revision {
		return n, access.ErrConflict
	}
	if !validID(d.Name) || len(d.Members) < 1 || len(d.Members) > 32 || len(d.Members) > maxNetworks-len(n.networks) || quotas.Cluster() != n.cluster || d.GatewayMode != "" && d.GatewayMode != network.ManagedGatewayMode {
		return n, ErrPolicy
	}
	for _, old := range n.networks {
		if old.Tenant == d.Tenant && (old.ID == d.Name || old.Logical == d.Name) {
			return n, access.ErrConflict
		}
	}
	toggles, ok := sortedToggles(d.Toggles)
	if !ok {
		return n, ErrPolicy
	}
	q, err := n.clone()
	if err != nil {
		return n, err
	}
	for _, member := range d.Members {
		if member.Addresses, ok = q.fillTunnel(member); !ok {
			return n, ErrPolicy
		}
		v := Network{Tenant: d.Tenant, ID: logicalMemberID(d.Tenant, d.Name, member.Node), Node: member.Node, Owner: member.Owner, Logical: d.Name, Pools: slices.Clone(member.Pools), TunnelAddresses: slices.Clone(member.Addresses), Generation: q.revision, Revision: q.revision, GatewayMode: d.GatewayMode, System: d.System, Toggles: slices.Clone(toggles)}
		slices.SortFunc(v.Pools, func(a, b Subnet) int { return strings.Compare(a.ID, b.ID) })
		slices.SortFunc(v.TunnelAddresses, func(a, b netip.Prefix) int { return strings.Compare(a.String(), b.String()) })
		if !validNetwork(v) || q.reservedOverlap(v, "") {
			return n, ErrPolicy
		}
		if _, exists := q.networks[key(v.Tenant, v.ID)]; exists {
			return n, access.ErrConflict
		}
		if err = admit(v, q); err != nil {
			return n, err
		}
		q.networks[key(v.Tenant, v.ID)] = ownNetwork(v)
	}
	if _, err = q.AddressPlan(1); err != nil || quotas.ValidateNetworks(q) != nil {
		return n, ErrPolicy
	}
	if _, err = q.TUNSources(d.Tenant, d.Name); err != nil {
		return n, err
	}
	return q, nil
}

// NamedNetwork resolves a logical name at the service's exact node. A group
// change closes new admission across the group; a draining member only on
// its own server. Existing frozen
// references remain available for original-result and lifetime settlement.
func (n Networks) NamedNetwork(tenant, name, node string) (Network, bool) {
	if tenant == "" {
		// The system network has no tenant, so no user app resolves it.
		return Network{}, false
	}
	if v, exists := n.Network(tenant, name); exists {
		return v, v.Logical == "" && v.Node == node && !v.Draining && v.PendingChange == 0
	}
	var found Network
	for _, v := range n.networks {
		if v.Tenant != tenant || v.Logical != name {
			continue
		}
		// A group change closes admission everywhere; a member leaving on its
		// own (drained, then leave-tun-network) closes only its own server.
		if v.PendingChange != 0 || v.Draining && v.Node == node {
			return Network{}, false
		}
		if v.Node == node {
			if found.ID != "" {
				return Network{}, false
			}
			found = ownNetwork(v)
		}
	}
	return found, found.ID != ""
}

// TUNSources deterministically projects the same committed reservation into
// existing native Bridge/Tunnel specs. Source generations come from the FSM
// objects, not from this derived view. Every member has its TUN, a lone one
// with no routes, so a server joining or leaving only rewrites route sets in
// place and never adds or removes another member's device.
func (n Networks) TUNSources(tenant, name string) ([]TUNSource, error) {
	var members []Network
	for _, v := range n.AllNetworks() {
		if v.Tenant == tenant && v.Logical == name {
			members = append(members, v)
		}
	}
	if len(members) == 0 || !togglesAllowed(members) || n.validateLogicalNetworks() != nil {
		return nil, ErrPolicy
	}
	var hosts map[string][]netip.Addr
	if tenant == "" && name == SystemNetwork {
		hosts = n.ClusterAppHosts()
	}
	var out []TUNSource
	for _, v := range members {
		owner := hex.EncodeToString(n.cluster[:]) + "/" + hex.EncodeToString(v.Owner[:])
		identity := SourceIdentity{Kind: "bridge", Tenant: tenant, Network: name, Node: v.Node}
		row := TUNSource{Network: ownNetwork(v), BridgeKey: identity.Key()}
		row.Bridge = network.BridgeSpec{Schema: 1, Network: v.ID, Owner: owner, MTU: v.Pools[0].MTU, Internal: true}
		if v.GatewayMode == network.ManagedGatewayMode {
			row.Bridge.Internal, row.Bridge.GatewayMode = false, v.GatewayMode
		}
		for _, p := range v.Pools {
			row.Bridge.Pools = append(row.Bridge.Pools, network.Pool{ID: v.ID + "/" + p.ID, Network: v.ID, Owner: owner, Prefix: p.Prefix, Gateway: p.Gateway, MTU: p.MTU, IPAM: p.IPAM})
		}
		raw, _ := json.Marshal(row.Bridge)
		if _, err := network.DecodeBridge(string(raw)); err != nil {
			return nil, err
		}
		spec := network.TunnelSpec{Schema: 1, Owner: owner, Network: PacketNamespace(tenant, name), MTU: row.Bridge.MTU, RouteMetric: 100, Addresses: slices.Clone(v.TunnelAddresses), Routes: []netip.Prefix{}}
		for _, remote := range members {
			if remote.ID == v.ID {
				continue
			}
			for _, p := range remote.Pools {
				spec.Routes = append(spec.Routes, p.Prefix)
			}
			spec.Routes = append(spec.Routes, remote.TunnelAddresses...)
			for _, a := range hosts[remote.Node] {
				spec.Routes = append(spec.Routes, netip.PrefixFrom(a, 32))
			}
		}
		slices.SortFunc(spec.Routes, func(a, b netip.Prefix) int { return strings.Compare(a.String(), b.String()) })
		raw, _ = json.Marshal(spec)
		if _, err := network.DecodeTunnel(string(raw)); err != nil {
			return nil, err
		}
		identity.Kind = "tun"
		row.TunnelKey = identity.Key()
		row.Tunnel = &spec
		out = append(out, row)
	}
	return out, nil
}

// JoinTUN adds one server to an existing TUN network without touching the
// other members: their reservations stay, and only their tunnel route sets
// grow (the caller rewrites those sources in place under the same
// generation). The new member takes the network's MTU and gateway mode.
func (n Networks) JoinTUN(c access.Catalog, quotas Quotas, actor string, expected uint64, tenant, name string, member TUNNode) (Networks, error) {
	if !validID(tenant) || !validID(name) || c.Authorize(actor, tenant, access.ManageNetwork, member.Node) != nil {
		return n, access.ErrDenied
	}
	return n.joinTUN(quotas, expected, tenant, name, member, func(v Network, q Networks) error {
		return quotas.AdmitNetwork(c, actor, v.Tenant, v.Node, v.Owner, q)
	})
}

// JoinSystemTUN adds one server to the system network (cluster app dependency).
func (n Networks) JoinSystemTUN(quotas Quotas, expected uint64, member TUNNode) (Networks, error) {
	return n.joinTUN(quotas, expected, "", SystemNetwork, member, func(v Network, q Networks) error {
		return quotas.admitScopes(v.Tenant, v.Node, v.Owner, q)
	})
}

func (n Networks) joinTUN(quotas Quotas, expected uint64, tenant, name string, member TUNNode, admit func(Network, Networks) error) (Networks, error) {
	if expected != n.revision {
		return n, access.ErrConflict
	}
	if quotas.Cluster() != n.cluster || len(n.networks) >= maxNetworks {
		return n, ErrPolicy
	}
	var first Network
	count := 0
	for _, v := range n.networks {
		if v.Tenant != tenant || v.Logical != name {
			continue
		}
		if v.Draining || v.PendingChange != 0 {
			return n, ErrPolicy
		}
		if v.Node == member.Node {
			return n, access.ErrConflict
		}
		if count == 0 || v.ID < first.ID {
			first = v
		}
		count++
	}
	if count == 0 || count >= 32 {
		return n, ErrPolicy
	}
	q, err := n.clone()
	if err != nil {
		return n, err
	}
	var filled bool
	if member.Addresses, filled = q.fillTunnel(member); !filled {
		return n, ErrPolicy
	}
	v := Network{Tenant: tenant, ID: logicalMemberID(tenant, name, member.Node), Node: member.Node, Owner: member.Owner, Logical: name, Pools: slices.Clone(member.Pools), TunnelAddresses: slices.Clone(member.Addresses), Generation: q.revision, Revision: q.revision, GatewayMode: first.GatewayMode, System: first.System, Toggles: slices.Clone(first.Toggles)}
	slices.SortFunc(v.Pools, func(a, b Subnet) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(v.TunnelAddresses, func(a, b netip.Prefix) int { return strings.Compare(a.String(), b.String()) })
	if !validNetwork(v) || v.Pools[0].MTU != first.Pools[0].MTU || q.reservedOverlap(v, "") {
		return n, ErrPolicy
	}
	if _, exists := q.networks[key(v.Tenant, v.ID)]; exists {
		return n, access.ErrConflict
	}
	if err = admit(v, q); err != nil {
		return n, err
	}
	q.networks[key(v.Tenant, v.ID)] = ownNetwork(v)
	if _, err = q.AddressPlan(1); err != nil || quotas.ValidateNetworks(q) != nil {
		return n, ErrPolicy
	}
	if _, err = q.TUNSources(tenant, name); err != nil {
		return n, err
	}
	return q, nil
}
