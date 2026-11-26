// SPDX-License-Identifier: Apache-2.0

package tenancy

import (
	"net/netip"
	"slices"

	"github.com/jay94ks/mydcd/internal/access"
)

// DefaultSystemRange is the system network's address range until a cluster
// administrator sets another one (while the network has no members).
var DefaultSystemRange = netip.MustParsePrefix("10.254.0.0/16")

// SystemMTU is the system network's MTU: it spans every work server.
const SystemMTU = 1280

// SystemPolicy is the cluster's system network setting. Range is where its
// addresses come from: the first /24 holds the tunnel addresses, and each
// member gets the next free /24 as its pool. Users are the servers that run
// node apps (sorted); while there are none, the members leave.
type SystemPolicy struct {
	Range netip.Prefix `json:",omitempty"`
	Users []string     `json:",omitempty"`
}

func (p SystemPolicy) empty() bool { return !p.Range.IsValid() && len(p.Users) == 0 }

// RangeOrDefault is the range in use.
func (p SystemPolicy) RangeOrDefault() netip.Prefix {
	if p.Range.IsValid() {
		return p.Range
	}
	return DefaultSystemRange
}

func validSystemRange(r netip.Prefix) bool {
	return r.IsValid() && r.Addr().Is4() && r == r.Masked() && r.Bits() >= 8 && r.Bits() <= 22
}

func validSystemPolicy(p SystemPolicy) bool {
	if p.Range.IsValid() && (!validSystemRange(p.Range) || p.Range == DefaultSystemRange) || len(p.Users) > maxNetworks {
		return false
	}
	for i, u := range p.Users {
		if !validID(u) || i > 0 && p.Users[i-1] >= u {
			return false
		}
	}
	return true
}

// SystemPolicy is the current system network setting.
func (n Networks) SystemPolicy() SystemPolicy {
	return SystemPolicy{Range: n.system.Range, Users: slices.Clone(n.system.Users)}
}

// SystemMembers are the system network's members, sorted by node.
func (n Networks) SystemMembers() []Network {
	var out []Network
	for _, v := range n.networks {
		if v.System {
			out = append(out, ownNetwork(v))
		}
	}
	slices.SortFunc(out, func(a, b Network) int {
		switch {
		case a.Node < b.Node:
			return -1
		case a.Node > b.Node:
			return 1
		}
		return 0
	})
	return out
}

// SetSystemUse records whether a server runs node apps. Setting the value
// it already has is a conflict, so a repeated report changes nothing.
func (n Networks) SetSystemUse(node string, on bool) (Networks, error) {
	if !validID(node) {
		return n, ErrPolicy
	}
	if slices.Contains(n.system.Users, node) == on {
		return n, access.ErrConflict
	}
	q, err := n.clone()
	if err != nil {
		return n, err
	}
	users := slices.Clone(n.system.Users)
	if on {
		users = append(users, node)
		slices.Sort(users)
	} else {
		users = slices.DeleteFunc(users, func(u string) bool { return u == node })
	}
	q.system = SystemPolicy{Range: n.system.Range, Users: users}
	return q, nil
}

// SetSystemRange changes the address range. Only while the network has no
// members, so no member's addresses move.
func (n Networks) SetSystemRange(expected uint64, r netip.Prefix) (Networks, error) {
	if expected != n.revision {
		return n, access.ErrConflict
	}
	if !validSystemRange(r) || len(n.SystemMembers()) != 0 {
		return n, ErrPolicy
	}
	// The new range must be free of every tenant network and change target.
	probe := n
	probe.system = SystemPolicy{Range: r}
	for _, v := range n.networks {
		if probe.overlapsSystemRange(v) {
			return n, ErrPolicy
		}
	}
	for _, c := range n.changes {
		if changeActive(c) && probe.overlapsSystemRange(c.Target) {
			return n, ErrPolicy
		}
	}
	if r == n.system.RangeOrDefault() {
		return n, access.ErrConflict
	}
	q, err := n.clone()
	if err != nil {
		return n, err
	}
	q.system = SystemPolicy{Range: r, Users: slices.Clone(n.system.Users)}
	if r == DefaultSystemRange {
		q.system.Range = netip.Prefix{}
	}
	return q, nil
}

// NextSystemMember picks a new member's pool and tunnel address: the first
// /24 of the range after the tunnel /24 that no network reserves, and the
// first tunnel address no member holds. owner is the node's key.
func (n Networks) NextSystemMember(node string, owner [32]byte) (TUNNode, error) {
	r := n.system.RangeOrDefault()
	members := n.SystemMembers()
	tunnels := netip.PrefixFrom(r.Addr(), 24)
	var tunnel netip.Addr
	for a := tunnels.Addr().Next(); tunnels.Contains(a) && a != lastAddr(tunnels); a = a.Next() {
		if !slices.ContainsFunc(members, func(m Network) bool { return slices.Contains(m.TunnelAddresses, netip.PrefixFrom(a, 32)) }) {
			tunnel = a
			break
		}
	}
	if !tunnel.IsValid() {
		return TUNNode{}, ErrPolicy
	}
	for p := nextBlock(tunnels); p.IsValid() && r.Contains(p.Addr()); p = nextBlock(p) {
		pool := Subnet{ID: "main", Prefix: p, Gateway: p.Addr().Next(), MTU: SystemMTU}
		candidate := Network{Tenant: "", ID: logicalMemberID("", SystemNetwork, node), Node: node, Owner: owner, Logical: SystemNetwork, System: true, Pools: []Subnet{pool}, TunnelAddresses: []netip.Prefix{netip.PrefixFrom(tunnel, 32)}}
		if !n.reservedOverlap(candidate, "") {
			return TUNNode{Node: node, Owner: owner, Pools: []Subnet{pool}, Addresses: []netip.Prefix{netip.PrefixFrom(tunnel, 32)}}, nil
		}
	}
	return TUNNode{}, ErrPolicy
}

// nextBlock is the /24 after p (invalid past the end of IPv4).
func nextBlock(p netip.Prefix) netip.Prefix {
	a := p.Addr().As4()
	if a[0] == 255 && a[1] == 255 && a[2] == 255 {
		return netip.Prefix{}
	}
	v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8
	v += 1 << 8
	return netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), 0}), 24)
}

func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().As4()
	bits := p.Bits()
	v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	v |= ^uint32(0) >> bits
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// overlapsSystemRange reports whether v's pools or tunnel addresses overlap
// the system range.
func (n Networks) overlapsSystemRange(v Network) bool {
	r := n.system.RangeOrDefault()
	for _, p := range reservationPrefixes(v) {
		if p.Overlaps(r) {
			return true
		}
	}
	return false
}

// OverlapsSystemRange reports whether a workspace network with these
// subnets and tunnel addresses would overlap the system range.
func (n Networks) OverlapsSystemRange(prefixes []netip.Prefix) bool {
	r := n.system.RangeOrDefault()
	return slices.ContainsFunc(prefixes, func(p netip.Prefix) bool { return p.Overlaps(r) })
}
