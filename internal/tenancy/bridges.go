// SPDX-License-Identifier: Apache-2.0

package tenancy

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
)

// A virtual bridge links two whole TUN networks (devel/design/virtual-bridge.md):
// every member server of one reaches every member server of the other, and
// it follows the networks' members as they join and leave. It names the
// logical networks, not a member or a pool.

// The bridge refusals that have their own result reason. Each one is also
// ErrPolicy.
var (
	ErrBridgeExists    = bridgeError("a bridge already links these two networks")
	ErrPeerClosed      = bridgeError("the other network does not take bridges")
	ErrNetworkChanging = bridgeError("a bridged network is changing")
	ErrBridgeAttached  = bridgeError("a bridge is attached to the network")
)

type bridgeRefusal struct{ text string }

func bridgeError(text string) error          { return bridgeRefusal{text} }
func (e bridgeRefusal) Error() string        { return e.text }
func (e bridgeRefusal) Is(target error) bool { return target == ErrPolicy }

const maxBridges = 4096

type BridgeDirection string

const (
	BridgeBoth BridgeDirection = "both"
	// BridgeAToB: only A's servers start connections; B answers them.
	BridgeAToB BridgeDirection = "a-to-b"
	BridgeBToA BridgeDirection = "b-to-a"
)

type BridgePhase string

const (
	BridgePending BridgePhase = "pending"
	BridgeOpen    BridgePhase = "open"
	BridgeClosing BridgePhase = "closing"
)

// BridgeEnd names one side: a tenant and its TUN network's logical name.
type BridgeEnd struct{ Tenant, Network string }

// ToggleBridgeInbound lets another tenant pick the network as the B side of
// a bridge. Off, it refuses new proposals and approvals; an open bridge
// stays.
const ToggleBridgeInbound NetworkToggle = "bridge-inbound"

// VirtualBridge is keyed by A.Tenant/ID. Approvals are A's then B's; a
// bridge between two networks of one tenant has A's only. Closures are the
// member servers' signed reports, sorted by node, while closing.
type VirtualBridge struct {
	ID                   string
	Generation, Revision uint64
	A, B                 BridgeEnd
	Direction            BridgeDirection
	Protocol             uint8   `json:",omitempty"`
	Ports                []Ports `json:",omitempty"`
	Phase                BridgePhase
	Approvals            []Approval
	Closures             []BridgeClosure `json:",omitempty"`
}

// SameTenant: both networks belong to one tenant, so no second approval.
func (b VirtualBridge) SameTenant() bool { return b.A.Tenant == b.B.Tenant }

// BridgeClosure is one member server's report that it removed the bridge's
// routes and rules from its own devices, signed with its node key.
type BridgeClosure struct {
	Cluster    [32]byte
	Owner, ID  string
	Generation uint64
	Node       string
	Key        [32]byte
	Signature  []byte
}

func BridgeClosureBytes(p BridgeClosure) []byte {
	p.Signature = nil
	b, _ := json.Marshal(p)
	return append([]byte("sfc-bridge-closure-1\x00"), b...)
}

func ownBridge(b VirtualBridge) VirtualBridge {
	b.Ports = slices.Clone(b.Ports)
	b.Approvals = slices.Clone(b.Approvals)
	b.Closures = slices.Clone(b.Closures)
	for i := range b.Closures {
		b.Closures[i].Signature = slices.Clone(b.Closures[i].Signature)
	}
	return b
}

func validBridge(cluster [32]byte, b VirtualBridge) bool {
	if !validID(b.ID) || b.Generation == 0 || b.Revision < b.Generation || !validID(b.A.Tenant) || !validID(b.A.Network) || !validID(b.B.Tenant) || !validID(b.B.Network) || b.A == b.B || b.A.Network == SystemNetwork || b.B.Network == SystemNetwork {
		return false
	}
	if b.Direction != BridgeBoth && b.Direction != BridgeAToB && b.Direction != BridgeBToA || b.Protocol != 0 && b.Protocol != 6 && b.Protocol != 17 || b.Protocol == 0 && len(b.Ports) != 0 || len(b.Ports) > 64 {
		return false
	}
	for i, p := range b.Ports {
		if p.First == 0 || p.Last < p.First || i > 0 && p.First <= b.Ports[i-1].Last {
			return false
		}
	}
	want := 2
	if b.SameTenant() {
		want = 1
	}
	switch b.Phase {
	case BridgePending:
		if b.SameTenant() || len(b.Approvals) != 1 {
			return false
		}
	case BridgeOpen:
		if len(b.Approvals) != want {
			return false
		}
	case BridgeClosing:
		if len(b.Approvals) == 0 || len(b.Approvals) > want {
			return false
		}
	default:
		return false
	}
	for i, a := range b.Approvals {
		if a.Tenant != []string{b.A.Tenant, b.B.Tenant}[i] || !validID(a.User) || a.PolicyRevision == 0 {
			return false
		}
	}
	if b.Phase != BridgeClosing && len(b.Closures) != 0 {
		return false
	}
	for i, p := range b.Closures {
		if i > 0 && p.Node <= b.Closures[i-1].Node || !verifyBridgeClosure(cluster, b, p) {
			return false
		}
	}
	return true
}

func verifyBridgeClosure(cluster [32]byte, b VirtualBridge, p BridgeClosure) bool {
	return cluster != ([32]byte{}) && p.Cluster == cluster && p.Owner == b.A.Tenant && p.ID == b.ID && p.Generation == b.Generation && validID(p.Node) && p.Key != ([32]byte{}) && ed25519.Verify(ed25519.PublicKey(p.Key[:]), BridgeClosureBytes(p), p.Signature)
}

func (n Networks) Bridge(owner, id string) (VirtualBridge, bool) {
	b, ok := n.bridges[key(owner, id)]
	return ownBridge(b), ok
}

// AllBridges is the owned inventory, sorted by key. Authorization belongs at
// the read boundary.
func (n Networks) AllBridges() []VirtualBridge {
	out := make([]VirtualBridge, 0, len(n.bridges))
	for _, b := range n.bridges {
		out = append(out, ownBridge(b))
	}
	slices.SortFunc(out, func(a, b VirtualBridge) int { return strings.Compare(key(a.A.Tenant, a.ID), key(b.A.Tenant, b.ID)) })
	return out
}

// VisibleBridges are the bridges with a side the actor may read.
func (n Networks) VisibleBridges(c access.Catalog, actor string) []VirtualBridge {
	var out []VirtualBridge
	for _, b := range n.AllBridges() {
		if c.Authorize(actor, b.A.Tenant, access.Read, "") == nil || c.Authorize(actor, b.B.Tenant, access.Read, "") == nil {
			out = append(out, b)
		}
	}
	return out
}

// BridgesOf are the bridges with e as one side.
func (n Networks) BridgesOf(e BridgeEnd) []VirtualBridge {
	var out []VirtualBridge
	for _, b := range n.AllBridges() {
		if b.A == e || b.B == e {
			out = append(out, b)
		}
	}
	return out
}

// logicalMembers are a tenant TUN network's members (none for the system
// network or a plain network).
func (n Networks) logicalMembers(e BridgeEnd) []Network {
	var out []Network
	for _, v := range n.networks {
		if !v.System && v.Tenant == e.Tenant && v.Logical == e.Network {
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b Network) int { return strings.Compare(a.ID, b.ID) })
	return out
}

// bridgeEndReady: the network exists and no change or member drain is in
// progress on it.
func (n Networks) bridgeEnd(c access.Catalog, actor string, e BridgeEnd) ([]Network, error) {
	members := n.logicalMembers(e)
	if len(members) == 0 {
		return nil, ErrPolicy
	}
	for _, v := range members {
		if c.Authorize(actor, e.Tenant, access.ManageNetwork, v.Node) != nil {
			return nil, access.ErrDenied
		}
	}
	for _, v := range members {
		if v.Draining || v.PendingChange != 0 {
			return nil, ErrNetworkChanging
		}
	}
	return members, nil
}

func takesBridges(members []Network) bool {
	return len(members) != 0 && slices.Contains(members[0].Toggles, ToggleBridgeInbound)
}

// CreateBridge is create-virtual-bridge. Two networks of one tenant open
// at once on that tenant's manager; another tenant's network must take
// bridges (bridge-inbound) and its manager approves next.
func (n Networks) CreateBridge(c access.Catalog, actor string, expected uint64, b VirtualBridge) (Networks, error) {
	if b.Generation != 0 || b.Revision != 0 || b.Phase != "" || len(b.Approvals) != 0 || len(b.Closures) != 0 {
		return n, ErrPolicy
	}
	if b.Direction == "" {
		b.Direction = BridgeBoth
	}
	if !validID(b.A.Tenant) || !validID(b.B.Tenant) {
		return n, ErrPolicy
	}
	if _, err := n.bridgeEnd(c, actor, b.A); err != nil {
		return n, err
	}
	// The other side is checked as its own manager would be only when it
	// is the same tenant; across tenants its manager approves later.
	peer := n.logicalMembers(b.B)
	if b.SameTenant() {
		var err error
		if peer, err = n.bridgeEnd(c, actor, b.B); err != nil {
			return n, err
		}
	}
	if expected != n.revision {
		return n, access.ErrConflict
	}
	if _, exists := n.bridges[key(b.A.Tenant, b.ID)]; exists {
		return n, access.ErrConflict
	}
	for _, old := range n.bridges {
		if old.A == b.A && old.B == b.B || old.A == b.B && old.B == b.A {
			return n, ErrBridgeExists
		}
	}
	if len(n.bridges) >= maxBridges {
		return n, ErrPolicy
	}
	changing := slices.ContainsFunc(peer, func(v Network) bool { return v.Draining || v.PendingChange != 0 })
	// Another tenant's network that is missing, does not take bridges or is
	// changing looks the same from here: like a route endpoint, it is
	// simply not open, and nothing more about it is told.
	if !b.SameTenant() && (len(peer) == 0 || !takesBridges(peer) || changing) {
		return n, ErrPeerClosed
	}
	if changing {
		return n, ErrNetworkChanging
	}
	q, err := n.clone()
	if err != nil {
		return n, err
	}
	b = ownBridge(b)
	b.Generation, b.Revision = q.revision, q.revision
	b.Approvals = []Approval{{Tenant: b.A.Tenant, User: actor, PolicyRevision: c.Revision()}}
	b.Phase = BridgePending
	if b.SameTenant() {
		b.Phase = BridgeOpen
	}
	if !validBridge(n.cluster, b) || n.bridgeOverlap(b) {
		return n, ErrPolicy
	}
	q.bridges[key(b.A.Tenant, b.ID)] = b
	return q, nil
}

// bridgeOverlap re-checks that the two networks' reservations do not
// overlap. sfcd already keeps every reservation apart, so this holds for
// any two networks; the check keeps the invariant local to the bridge.
func (n Networks) bridgeOverlap(b VirtualBridge) bool {
	for _, x := range n.logicalMembers(b.A) {
		for _, y := range n.logicalMembers(b.B) {
			if reservationsOverlap(x, y) {
				return true
			}
		}
	}
	return false
}

// ApproveBridge is approve-virtual-bridge: B's manager approves a pending
// bridge from another tenant, which opens it. tenant is the approving side.
func (n Networks) ApproveBridge(c access.Catalog, actor, tenant, owner, id string, expected uint64) (Networks, error) {
	b, ok := n.bridges[key(owner, id)]
	if !ok || b.Revision != expected {
		return n, access.ErrConflict
	}
	if b.SameTenant() || tenant != b.B.Tenant {
		return n, ErrPolicy
	}
	peer, err := n.bridgeEnd(c, actor, b.B)
	if err != nil {
		return n, err
	}
	if b.Phase != BridgePending {
		return n, access.ErrConflict
	}
	for _, v := range n.logicalMembers(b.A) {
		if v.Draining || v.PendingChange != 0 {
			return n, ErrNetworkChanging
		}
	}
	if !takesBridges(peer) {
		return n, ErrPeerClosed
	}
	q, err := n.clone()
	if err != nil {
		return n, err
	}
	b = ownBridge(b)
	b.Revision = q.revision
	b.Approvals = append(b.Approvals, Approval{Tenant: tenant, User: actor, PolicyRevision: c.Revision()})
	b.Phase = BridgeOpen
	q.bridges[key(owner, id)] = b
	return q, nil
}

// CloseBridge is close-virtual-bridge from either side. A pending bridge is
// removed at once; an open one closes and is removed once every member
// server reported (ObserveBridgeClosed). It takes the side's cleanup
// authority, so a withdrawn server grant does not keep a bridge open.
func (n Networks) CloseBridge(c access.Catalog, actor, tenant, owner, id string, expected uint64) (Networks, error) {
	b, ok := n.bridges[key(owner, id)]
	if !ok || b.Revision != expected {
		return n, access.ErrConflict
	}
	if tenant != b.A.Tenant && tenant != b.B.Tenant {
		return n, ErrPolicy
	}
	if !mayRetire(c, actor, tenant, access.ManageNetwork) {
		return n, access.ErrDenied
	}
	if b.Phase == BridgeClosing {
		return n, access.ErrConflict
	}
	q, err := n.clone()
	if err != nil {
		return n, err
	}
	if b.Phase == BridgePending {
		delete(q.bridges, key(owner, id))
		return q, nil
	}
	b = ownBridge(b)
	b.Phase, b.Revision, b.Closures = BridgeClosing, q.revision, nil
	q.bridges[key(owner, id)] = b
	q.settleBridges()
	return q, nil
}

// BridgeServers are the servers that carry a bridge: the members of both
// networks, each once, sorted.
func (n Networks) BridgeServers(b VirtualBridge) []string {
	var out []string
	for _, e := range []BridgeEnd{b.A, b.B} {
		for _, v := range n.logicalMembers(e) {
			if !slices.Contains(out, v.Node) {
				out = append(out, v.Node)
			}
		}
	}
	slices.Sort(out)
	return out
}

// memberKey is the node key of the server's member of either network.
func (n Networks) memberKey(b VirtualBridge, node string) ([32]byte, bool) {
	for _, e := range []BridgeEnd{b.A, b.B} {
		for _, v := range n.logicalMembers(e) {
			if v.Node == node {
				return v.Owner, true
			}
		}
	}
	return [32]byte{}, false
}

// ObserveBridgeClosed takes one member server's signed report for a closing
// bridge. It needs no user: the bridge was already closed by one. The bridge
// goes away once every current member server of both networks reported.
func (n Networks) ObserveBridgeClosed(p BridgeClosure) (Networks, error) {
	b, ok := n.bridges[key(p.Owner, p.ID)]
	if !ok || b.Phase != BridgeClosing || !verifyBridgeClosure(n.cluster, b, p) {
		return n, ErrPolicy
	}
	if k, member := n.memberKey(b, p.Node); !member || k != p.Key {
		return n, ErrPolicy
	}
	if slices.ContainsFunc(b.Closures, func(old BridgeClosure) bool { return old.Node == p.Node }) {
		return n, access.ErrConflict
	}
	q, err := n.clone()
	if err != nil {
		return n, err
	}
	b = ownBridge(b)
	p.Signature = slices.Clone(p.Signature)
	b.Closures = append(b.Closures, p)
	slices.SortFunc(b.Closures, func(x, y BridgeClosure) int { return strings.Compare(x.Node, y.Node) })
	q.bridges[key(p.Owner, p.ID)] = b
	q.settleBridges()
	return q, nil
}

// settleBridges removes every closing bridge whose current member servers
// all reported. A server that left meanwhile owes nothing.
func (q *Networks) settleBridges() {
	for k, b := range q.bridges {
		if b.Phase != BridgeClosing {
			continue
		}
		done := true
		for _, node := range q.BridgeServers(b) {
			if !slices.ContainsFunc(b.Closures, func(p BridgeClosure) bool { return p.Node == node }) {
				done = false
			}
		}
		if done {
			delete(q.bridges, k)
		}
	}
}

// lastMemberBridged: removing v would leave a bridge without its network.
func (n Networks) lastMemberBridged(v Network) bool {
	if v.System || v.Logical == "" {
		return false
	}
	e := BridgeEnd{v.Tenant, v.Logical}
	return len(n.logicalMembers(e)) == 1 && len(n.BridgesOf(e)) != 0
}

// validBridges: every bridge is well formed and both its networks exist.
func (n Networks) validBridges() bool {
	if len(n.bridges) > maxBridges {
		return false
	}
	for k, b := range n.bridges {
		if k != key(b.A.Tenant, b.ID) || !validBridge(n.cluster, b) || len(n.logicalMembers(b.A)) == 0 || len(n.logicalMembers(b.B)) == 0 {
			return false
		}
	}
	return true
}

// IsBridgeRefusal reports whether err is one of the bridge refusals that
// have their own result reason.
func IsBridgeRefusal(err error) bool {
	var r bridgeRefusal
	return errors.As(err, &r)
}
