// SPDX-License-Identifier: Apache-2.0

package tenancy

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/network"
)

// SystemMTU is the system network's MTU: it spans every work server.
const SystemMTU = 1280

// SystemPolicy is the cluster's system network setting. Its addresses come
// from the fixed network.SystemRange: each member gets the first free /24
// between network.ClusterBlock and network.ServerBlock as its pool, and its tunnel address is the
// server's own (membership). Users are the servers that run cluster apps
// (sorted); while there are none, the members leave.
type SystemPolicy struct {
	Users []string `json:",omitempty"`
	// Runners: the one server that runs each cluster app (sorted by app).
	// A cluster app runs on one server in the cluster: another server that
	// turns it on is refused while its runner still uses the network
	// (Jay 2026-11-26). There is no automatic move.
	Runners []ClusterAppRunner `json:",omitempty"`
}

// ClusterAppRunner is the server that runs App.
type ClusterAppRunner struct {
	App, Node string
}

func (p SystemPolicy) empty() bool { return len(p.Users) == 0 && len(p.Runners) == 0 }

func (p SystemPolicy) clone() SystemPolicy {
	return SystemPolicy{Users: slices.Clone(p.Users), Runners: slices.Clone(p.Runners)}
}

func validSystemPolicy(p SystemPolicy) bool {
	if len(p.Users) > maxNetworks {
		return false
	}
	for i, u := range p.Users {
		if !validID(u) || i > 0 && p.Users[i-1] >= u {
			return false
		}
	}
	if len(p.Runners) > maxNetworks {
		return false
	}
	for i, r := range p.Runners {
		if !validID(r.App) || !validID(r.Node) || i > 0 && p.Runners[i-1].App >= r.App {
			return false
		}
	}
	return true
}

// WithServers gives the view the servers' fixed addresses (membership's
// ServerAddresses, by node). Every TUN member's tunnel address is its
// server's; the view checks and fills it from this. It is not stored.
func (n Networks) WithServers(addresses map[string]netip.Addr) Networks {
	n.servers = addresses
	return n
}

// TunnelAddressesInUse are the tunnel addresses of every network member and
// active change target. A removed server's address is not handed to a new
// server while one of them still holds it.
func (n Networks) TunnelAddressesInUse() map[netip.Addr]bool {
	out := map[netip.Addr]bool{}
	for _, v := range n.networks {
		for _, p := range v.TunnelAddresses {
			out[p.Addr()] = true
		}
	}
	for _, c := range n.changes {
		if changeActive(c) {
			for _, p := range c.Target.TunnelAddresses {
				out[p.Addr()] = true
			}
		}
	}
	return out
}

// NodeAddress is a server's fixed address, if the view knows it.
func (n Networks) NodeAddress(node string) (netip.Addr, bool) {
	a, ok := n.servers[node]
	return a, ok && network.ValidServerAddress(a)
}

// SystemPolicy is the current system network setting.
func (n Networks) SystemPolicy() SystemPolicy {
	return n.system.clone()
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

// SetSystemUse records whether a server runs cluster apps. Setting the value
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
	q.system = n.system.clone()
	q.system.Users = users
	if !on {
		// a server that stops running cluster apps runs none
		q.system.Runners = slices.DeleteFunc(q.system.Runners, func(r ClusterAppRunner) bool { return r.Node == node })
	}
	return q, nil
}

// ClaimClusterApp makes node the server that runs app. It must use the
// network and be a member that is not draining; users are the servers that
// use it now (control.Policy.SystemNetworkUsers). Another current user that
// runs app already keeps it: the claim is refused (ErrConflict), as is a
// claim for what node runs already. A runner that is no longer a user (it
// stopped using the network, or left the cluster) gives way.
func (n Networks) ClaimClusterApp(expected uint64, node, app string, users []string) (Networks, error) {
	if expected != n.revision {
		return n, access.ErrConflict
	}
	if !validID(node) || !validID(app) || !slices.Contains(users, node) {
		return n, ErrPolicy
	}
	if !slices.ContainsFunc(n.SystemMembers(), func(m Network) bool { return m.Node == node && !m.Draining }) {
		return n, ErrPolicy
	}
	if r, ok := n.system.runner(app); ok && (r == node || slices.Contains(users, r)) {
		return n, access.ErrConflict
	}
	q, err := n.clone()
	if err != nil {
		return n, err
	}
	q.system = n.system.clone()
	q.system.Runners = append(slices.DeleteFunc(q.system.Runners, func(r ClusterAppRunner) bool { return r.App == app }), ClusterAppRunner{App: app, Node: node})
	slices.SortFunc(q.system.Runners, func(a, b ClusterAppRunner) int { return strings.Compare(a.App, b.App) })
	return q, nil
}

func (p SystemPolicy) runner(app string) (string, bool) {
	for _, r := range p.Runners {
		if r.App == app {
			return r.Node, true
		}
	}
	return "", false
}

// ClusterAppRunner is the server that runs app now: its runner, while the
// runner still uses the network (users).
func (n Networks) ClusterAppRunner(app string, users []string) (string, bool) {
	r, ok := n.system.runner(app)
	return r, ok && slices.Contains(users, r)
}

// ClusterAppAddress is where app listens: its cluster-wide address
// (network.ClusterAppAddress), on the server that runs it now. Every server
// computes the same; nothing is reported.
func (n Networks) ClusterAppAddress(app string, users []string) (node string, addr netip.Addr, ok bool) {
	node, _, ok = n.ClusterAppPoolAddress(app, users)
	if !ok {
		return "", netip.Addr{}, false
	}
	addr, ok = network.ClusterAppAddress(app)
	return node, addr, ok
}

// ClusterAppPoolAddress is app's container address: its fixed host in the
// system pool of the server that runs it (network.ClusterAppPoolAddress).
func (n Networks) ClusterAppPoolAddress(app string, users []string) (node string, addr netip.Addr, ok bool) {
	node, ok = n.ClusterAppRunner(app, users)
	if !ok {
		return "", netip.Addr{}, false
	}
	for _, m := range n.SystemMembers() {
		if m.Node == node && len(m.Pools) != 0 {
			addr, ok = network.ClusterAppPoolAddress(m.Pools[0].Prefix, app)
			return node, addr, ok
		}
	}
	return "", netip.Addr{}, false
}

// ClusterAppHosts are the cluster-wide addresses each system member
// carries: those of the apps it is recorded to run, while it is a member
// that is not draining. The other members' TUNs route them to it
// (TUNSources), and the packet policy lets them through to it. This reads
// only the networks record, so a runner that stopped using the network
// keeps its routes until it reports so (SetSystemUse clears its record).
func (n Networks) ClusterAppHosts() map[string][]netip.Addr {
	out := map[string][]netip.Addr{}
	for _, r := range n.system.Runners {
		if !slices.ContainsFunc(n.SystemMembers(), func(m Network) bool { return m.Node == r.Node && !m.Draining }) {
			continue
		}
		if a, ok := network.ClusterAppAddress(r.App); ok {
			out[r.Node] = append(out[r.Node], a)
		}
	}
	return out
}

// NextSystemMember picks a new member's pool: the first /24 between the
// cluster block and the server block that no network reserves. Its tunnel address is
// the server's own, filled in when it joins. owner is the node's key.
func (n Networks) NextSystemMember(node string, owner [32]byte) (TUNNode, error) {
	if _, ok := n.NodeAddress(node); !ok {
		return TUNNode{}, ErrPolicy
	}
	for p := nextBlock(network.ClusterBlock); p.IsValid() && !p.Overlaps(network.ServerBlock); p = nextBlock(p) {
		// Docker hands out only the upper half; the lower half holds the
		// gateway and the cluster apps' fixed addresses.
		a := p.Addr().As4()
		a[3] = 128
		pool := Subnet{ID: "main", Prefix: p, Gateway: p.Addr().Next(), MTU: SystemMTU, IPAM: network.PoolIPAM{Dynamic: netip.PrefixFrom(netip.AddrFrom4(a), 25)}}
		candidate := Network{Tenant: "", ID: logicalMemberID("", SystemNetwork, node), Node: node, Owner: owner, Logical: SystemNetwork, System: true, Pools: []Subnet{pool}}
		if !n.reservedOverlap(candidate, "") {
			return TUNNode{Node: node, Owner: owner, Pools: []Subnet{pool}}, nil
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

// overlapsSystemRange reports whether v's pools overlap the system range.
// Tunnel addresses are server addresses inside it by design.
func overlapsSystemRange(v Network) bool {
	return slices.ContainsFunc(reservationPrefixes(v), func(p netip.Prefix) bool { return p.Overlaps(network.SystemRange) })
}

// OverlapsSystemRange reports whether a workspace network with these
// subnets would overlap the system range.
func OverlapsSystemRange(prefixes []netip.Prefix) bool {
	return slices.ContainsFunc(prefixes, func(p netip.Prefix) bool { return p.Overlaps(network.SystemRange) })
}
