// SPDX-License-Identifier: Apache-2.0

// Package tenancy contains shared network ownership and bilateral route policy.
// It has no native effects. The FSM must publish its candidate atomically with
// the authenticated command result. Node keys come from the committed roster,
// never from a caller's self-asserted owner field.
package tenancy

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/network"
)

var ErrPolicy = errors.New("tenant network policy, ownership or revision conflict")

const (
	maxNetworks = 4096
	maxRoutes   = 4096
	maxPools    = 16
)

type Subnet struct {
	ID      string
	Prefix  netip.Prefix
	Gateway netip.Addr
	MTU     int
	IPAM    network.PoolIPAM `json:",omitzero"`
}

type Network struct {
	Tenant, ID, Node     string
	Owner                [32]byte
	Generation, Revision uint64
	Draining             bool
	Pools                []Subnet
	PendingChange        uint64         `json:",omitempty"`
	Logical              string         `json:",omitempty"`
	TunnelAddresses      []netip.Prefix `json:",omitempty"`
	GatewayMode          string         `json:",omitempty"`
	// System marks a member of the cluster-owned system network. It has no
	// tenant; only sfcd's cluster app dependency controls it (CreateSystemTUN),
	// never the tenant network actions.
	System bool `json:",omitempty"`
	// Toggles are the network's options that are on (NetworkToggle, sorted),
	// the same on every member of a TUN network.
	Toggles []NetworkToggle `json:",omitempty"`
}

// SystemNetwork is the name of the cluster-owned TUN network all cluster apps
// share. User apps cannot resolve it.
const SystemNetwork = "sfc-system"

// SystemScope stands for the system network where a tenant name is needed
// (native consumer budgets, tenant isolation). It is not a valid tenant ID,
// so no tenant shares it.
const SystemScope = "sfc:system"

// Scope is the network's tenant, or SystemScope for the system network.
func (v Network) Scope() string {
	if v.System {
		return SystemScope
	}
	return v.Tenant
}

// validScope: a tenant network names a tenant; a system network names none.
func validScope(v Network) bool {
	if v.System {
		return v.Tenant == "" && v.Logical == SystemNetwork
	}
	return validID(v.Tenant)
}

// Networks is immutable. The revision also supplies non-reusable generations,
// including after an object has been retired and its name is created again.
type Networks struct {
	cluster  [32]byte
	revision uint64
	networks map[string]Network
	routes   map[string]Route
	changes  map[string]NetworkChange
	bridges  map[string]VirtualBridge
	system   SystemPolicy
	// servers are the servers' fixed addresses (WithServers); not stored.
	servers map[string]netip.Addr
}

func New(cluster [32]byte) (Networks, error) {
	if cluster == ([32]byte{}) {
		return Networks{}, ErrPolicy
	}
	return Networks{cluster: cluster, networks: map[string]Network{}, routes: map[string]Route{}, changes: map[string]NetworkChange{}, bridges: map[string]VirtualBridge{}}, nil
}
func validID(s string) bool {
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
func key(tenant, id string) string { return tenant + "/" + id }
func ownNetwork(n Network) Network {
	n.Pools = slices.Clone(n.Pools)
	n.TunnelAddresses = slices.Clone(n.TunnelAddresses)
	n.Toggles = slices.Clone(n.Toggles)
	return n
}
func (n Networks) Revision() uint64  { return n.revision }
func (n Networks) Cluster() [32]byte { return n.cluster }
func (n Networks) Network(tenant, id string) (Network, bool) {
	v, ok := n.networks[key(tenant, id)]
	return ownNetwork(v), ok
}

// LogicalName is a member network's logical name, the member ID for a plain
// network, or "" when there is no such member.
func (n Networks) LogicalName(tenant, id string) string {
	v, ok := n.networks[key(tenant, id)]
	switch {
	case !ok:
		return ""
	case v.Logical != "":
		return v.Logical
	}
	return v.ID
}
func (n Networks) VisibleNetworks(c access.Catalog, actor string) []Network {
	var out []Network
	for _, v := range n.networks {
		if c.Authorize(actor, v.Tenant, access.Read, "") == nil {
			out = append(out, ownNetwork(v))
		}
	}
	slices.SortFunc(out, func(a, b Network) int { return strings.Compare(key(a.Tenant, a.ID), key(b.Tenant, b.ID)) })
	return out
}
func (n Networks) clone() (Networks, error) {
	if n.cluster == ([32]byte{}) || n.networks == nil || n.routes == nil || n.changes == nil || n.bridges == nil || n.revision == ^uint64(0) {
		return n, ErrPolicy
	}
	q := Networks{cluster: n.cluster, revision: n.revision + 1, networks: map[string]Network{}, routes: map[string]Route{}, changes: map[string]NetworkChange{}, bridges: map[string]VirtualBridge{}, servers: n.servers}
	for k, v := range n.networks {
		q.networks[k] = ownNetwork(v)
	}
	for k, v := range n.routes {
		q.routes[k] = ownRoute(v)
	}
	for k, v := range n.changes {
		q.changes[k] = ownChange(v)
	}
	for k, v := range n.bridges {
		q.bridges[k] = ownBridge(v)
	}
	q.system = n.SystemPolicy()
	return q, nil
}

// AddressPlan derives the existing A7 allocator's pools. An actual IPAM adapter
// must retain its allocations/floors while reconciling this desired pool set;
// calling this method is not permission to reset an operational allocator.
func (n Networks) AddressPlan(capacity int) (network.Book, error) {
	b, err := network.NewBook(capacity)
	if err != nil {
		return b, err
	}
	if n.validateLogicalNetworks() != nil {
		return b, ErrPolicy
	}
	ids := make([]string, 0, len(n.networks))
	for id := range n.networks {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		v := n.networks[id]
		for _, p := range v.Pools {
			b, err = b.AddPool(network.Pool{ID: id + "/" + p.ID, Network: id, Owner: hex.EncodeToString(v.Owner[:]), Prefix: p.Prefix, Gateway: p.Gateway, MTU: p.MTU, IPAM: p.IPAM, Draining: v.Draining})
			if err != nil {
				return b, err
			}
		}
	}
	return b, nil
}
func validNetwork(v Network) bool {
	if !validScope(v) || !validID(v.ID) || !validID(v.Node) || v.Owner == ([32]byte{}) || v.Generation == 0 || v.Revision < v.Generation || len(v.Pools) < 1 || len(v.Pools) > maxPools || v.GatewayMode != "" && (v.GatewayMode != network.ManagedGatewayMode || v.Logical == "") {
		return false
	}
	for i, p := range v.Pools {
		if !validID(p.ID) || i > 0 && p.ID <= v.Pools[i-1].ID {
			return false
		}
	}
	return validToggles(v) && validLogicalMember(v)
}

// Create reserves every subnet together. owner must be resolved from the
// authenticated, admitted node in the committed cluster configuration.
func (n Networks) Create(c access.Catalog, actor string, expected uint64, v Network) (Networks, error) {
	if v.System || v.Tenant == "" {
		return n, ErrPolicy
	}
	if c.Authorize(actor, v.Tenant, access.ManageNetwork, v.Node) != nil {
		return n, access.ErrDenied
	}
	if expected != n.revision {
		return n, access.ErrConflict
	}
	if v.Generation != 0 || v.Revision != 0 || v.Draining || v.PendingChange != 0 || v.Logical != "" || len(v.TunnelAddresses) != 0 || len(n.networks) >= maxNetworks {
		return n, ErrPolicy
	}
	for _, old := range n.networks {
		if old.Tenant == v.Tenant && old.Logical == v.ID {
			return n, access.ErrConflict
		}
	}
	k := key(v.Tenant, v.ID)
	if _, exists := n.networks[k]; exists {
		return n, access.ErrConflict
	}
	if n.reservedOverlap(v, "") {
		return n, ErrPolicy
	}
	q, err := n.clone()
	if err != nil {
		return n, err
	}
	v = ownNetwork(v)
	slices.SortFunc(v.Pools, func(a, b Subnet) int { return strings.Compare(a.ID, b.ID) })
	v.Generation = q.revision
	v.Revision = q.revision
	if !validNetwork(v) {
		return n, ErrPolicy
	}
	q.networks[k] = v
	if _, err = q.AddressPlan(1); err != nil {
		return n, ErrPolicy
	}
	return q, nil
}
func mayRetire(c access.Catalog, actor, tenant string, action access.Action) bool {
	// Removing a node grant must not prevent cleanup of its existing resources.
	return c.AuthorizeCleanup(actor, tenant, action) == nil
}
func (n Networks) Drain(c access.Catalog, actor, tenant, id string, expected uint64) (Networks, error) {
	if tenant == "" {
		return n, ErrPolicy
	}
	if !mayRetire(c, actor, tenant, access.ManageNetwork) {
		return n, access.ErrDenied
	}
	return n.drain(tenant, id, expected)
}

// DrainSystem drains one server's own system network member. The caller
// decides that the member may leave (no server uses the network, or the
// server is being removed); no user reaches it.
func (n Networks) DrainSystem(node string, expected uint64) (Networks, error) {
	v, ok := n.networks[key("", logicalMemberID("", SystemNetwork, node))]
	if !ok || !v.System || v.Node != node {
		return n, ErrPolicy
	}
	return n.drain("", v.ID, expected)
}

func (n Networks) drain(tenant, id string, expected uint64) (Networks, error) {
	v, ok := n.networks[key(tenant, id)]
	if !ok || v.Revision != expected {
		return n, access.ErrConflict
	}
	if v.Draining {
		return n, nil
	}
	q, err := n.clone()
	if err != nil {
		return n, err
	}
	v.Draining = true
	v.Revision = q.revision
	q.networks[key(tenant, id)] = v
	if change, ok := q.changes[key(tenant, id)]; ok && change.Phase == ChangeReserved {
		change.Phase = ChangeDraining
		change.DrainingRevision = q.revision
		change.Revision = q.revision
		q.changes[key(tenant, id)] = change
	}
	// A binding change closes new admission immediately. Both old owners still
	// owe native/flow retirement, even if the local network is already gone.
	for k, r := range q.routes {
		if r.Phase != Revoking && (r.Source.Tenant == tenant && r.Source.Network == id || r.Destination.Tenant == tenant && r.Destination.Network == id) {
			r.Phase = Revoking
			r.Revision = q.revision
			r.Closures = nil
			q.routes[k] = r
		}
	}
	return q, nil
}

type NetworkClosure struct {
	Cluster                                     [32]byte
	Tenant, Network, Node                       string
	Owner                                       [32]byte
	Generation, Revision                        uint64
	NativeGone                                  bool
	PendingEndpoints, PendingFlows, PendingPins uint64
	Signature                                   []byte
}

func NetworkClosureBytes(p NetworkClosure) []byte {
	p.Signature = nil
	b, _ := json.Marshal(p)
	return append([]byte("sfc-network-closure-1\x00"), b...)
}
func (n Networks) Retire(c access.Catalog, actor string, p NetworkClosure) (Networks, error) {
	if p.Tenant == "" {
		return n, ErrPolicy
	}
	if !mayRetire(c, actor, p.Tenant, access.ManageNetwork) {
		return n, access.ErrDenied
	}
	return n.retire(p)
}

// RetireSystem removes one drained system network member on its own signed
// closure. The member's server signs it; no user reaches it.
func (n Networks) RetireSystem(p NetworkClosure) (Networks, error) {
	v, ok := n.networks[key("", p.Network)]
	if p.Tenant != "" || !ok || !v.System {
		return n, ErrPolicy
	}
	return n.retire(p)
}

// RetireDrained removes one drained workspace network member on its own
// server's signed closure. A user already drained it (drain-network, with
// cleanup permission); the server only settles that drain once its native
// sources are gone, so a delete finishes without the client that started it.
func (n Networks) RetireDrained(p NetworkClosure) (Networks, error) {
	v, ok := n.networks[key(p.Tenant, p.Network)]
	if p.Tenant == "" || !ok || v.System {
		return n, ErrPolicy
	}
	return n.retire(p)
}

func (n Networks) retire(p NetworkClosure) (Networks, error) {
	if ch, exists := n.changes[key(p.Tenant, p.Network)]; exists && changeActive(ch) {
		return n, ErrPolicy
	}
	v, ok := n.networks[key(p.Tenant, p.Network)]
	if !ok || !v.Draining || p.Cluster != n.cluster || p.Node != v.Node || p.Owner != v.Owner || p.Generation != v.Generation || p.Revision != v.Revision || !p.NativeGone || p.PendingEndpoints != 0 || p.PendingFlows != 0 || p.PendingPins != 0 || !ed25519.Verify(ed25519.PublicKey(v.Owner[:]), NetworkClosureBytes(p), p.Signature) {
		return n, ErrPolicy
	}
	for _, r := range n.routes {
		if r.Source.Tenant == v.Tenant && r.Source.Network == v.ID || r.Destination.Tenant == v.Tenant && r.Destination.Network == v.ID {
			return n, ErrPolicy
		}
	}
	if n.lastMemberBridged(v) {
		return n, ErrBridgeAttached
	}
	q, err := n.clone()
	if err != nil {
		return n, err
	}
	delete(q.networks, key(v.Tenant, v.ID))
	// a closing bridge no longer waits for this server
	q.settleBridges()
	return q, nil
}

type snapshot struct {
	Schema   uint8
	Cluster  [32]byte
	Revision uint64
	Networks []Network
	Routes   []Route
	Changes  []NetworkChange `json:",omitempty"`
	Bridges  []VirtualBridge `json:",omitempty"`
	System   *SystemPolicy   `json:",omitempty"`
}

func (n Networks) Encode() ([]byte, error) {
	if n.cluster == ([32]byte{}) || n.networks == nil || n.routes == nil {
		return nil, ErrPolicy
	}
	s := snapshot{Schema: 1, Cluster: n.cluster, Revision: n.revision}
	if !n.system.empty() {
		if !validSystemPolicy(n.system) {
			return nil, ErrPolicy
		}
		p := n.SystemPolicy()
		s.System = &p
	}
	for _, v := range n.networks {
		if v.PendingChange != 0 {
			ch, ok := n.changes[key(v.Tenant, v.ID)]
			if !ok || !changeActive(ch) || ch.Generation != v.PendingChange {
				return nil, ErrPolicy
			}
		}
		s.Networks = append(s.Networks, ownNetwork(v))
	}
	for _, v := range n.routes {
		s.Routes = append(s.Routes, ownRoute(v))
	}
	if n.changes == nil || len(n.changes) > maxNetworks {
		return nil, ErrPolicy
	}
	for _, v := range n.changes {
		if !n.validChange(v) {
			return nil, ErrPolicy
		}
		s.Changes = append(s.Changes, ownChange(v))
	}
	slices.SortFunc(s.Changes, func(a, b NetworkChange) int {
		return strings.Compare(key(a.Original.Tenant, a.Original.ID), key(b.Original.Tenant, b.Original.ID))
	})
	slices.SortFunc(s.Networks, func(a, b Network) int { return strings.Compare(key(a.Tenant, a.ID), key(b.Tenant, b.ID)) })
	slices.SortFunc(s.Routes, func(a, b Route) int { return strings.Compare(key(a.Source.Tenant, a.ID), key(b.Source.Tenant, b.ID)) })
	if n.bridges == nil || !n.validBridges() {
		return nil, ErrPolicy
	}
	if len(n.bridges) != 0 {
		s.Bridges = n.AllBridges()
	}
	raw, e := json.Marshal(s)
	if e != nil || len(raw) > 32<<20 {
		return nil, ErrPolicy
	}
	return raw, nil
}
func Decode(b []byte) (Networks, error) {
	var s snapshot
	if len(b) > 32<<20 || json.Unmarshal(b, &s) != nil || s.Schema != 1 || len(s.Networks) > maxNetworks || len(s.Routes) > maxRoutes || len(s.Changes) > maxNetworks || len(s.Bridges) > maxBridges {
		return Networks{}, ErrPolicy
	}
	n, err := New(s.Cluster)
	if err != nil {
		return Networks{}, err
	}
	n.revision = s.Revision
	if s.System != nil {
		if s.System.empty() || !validSystemPolicy(*s.System) {
			return Networks{}, ErrPolicy
		}
		n.system = s.System.clone()
	}
	for _, v := range s.Networks {
		k := key(v.Tenant, v.ID)
		if _, dup := n.networks[k]; dup || !validNetwork(v) || v.Revision > n.revision {
			return Networks{}, ErrPolicy
		}
		n.networks[k] = ownNetwork(v)
	}
	if _, err = n.AddressPlan(1); err != nil {
		return Networks{}, ErrPolicy
	}
	for _, r := range s.Routes {
		k := key(r.Source.Tenant, r.ID)
		if _, dup := n.routes[k]; dup || !validRoute(r) || r.Revision > n.revision || !n.validRouteOwners(r) {
			return Networks{}, ErrPolicy
		}
		n.routes[k] = ownRoute(r)
	}
	for _, v := range s.Changes {
		k := key(v.Original.Tenant, v.Original.ID)
		if _, dup := n.changes[k]; dup {
			return Networks{}, ErrPolicy
		}
		n.changes[k] = ownChange(v)
	}
	for _, b := range s.Bridges {
		k := key(b.A.Tenant, b.ID)
		if _, dup := n.bridges[k]; dup || b.Revision > n.revision {
			return Networks{}, ErrPolicy
		}
		n.bridges[k] = ownBridge(b)
	}
	for k, v := range n.changes {
		if !n.validChange(v) || changeActive(v) && n.reservedOverlap(v.Target, k) {
			return Networks{}, ErrPolicy
		}
	}
	canonical, err := n.Encode()
	if err != nil || !bytes.Equal(b, canonical) {
		return Networks{}, ErrPolicy
	}
	return n, nil
}
