// SPDX-License-Identifier: Apache-2.0

package desired

import (
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/network"
	"net/netip"
)

func (g Graph) validateTunnels(addresses map[string]int) error {
	owners := map[string]bool{}
	reserved := map[netip.Addr]bool{}
	for _, key := range Sorted(g.Tunnels) {
		t := g.Tunnels[key]
		if t.Lifecycle.Released() {
			continue
		}
		n, known := g.Nodes[t.Owner]
		if !known || owners[t.Owner] || n.PacketQueuePackets == 0 || n.PacketQueueBytes < t.MTU+120 {
			return ErrPolicy
		}
		owners[t.Owner] = true
		for _, address := range t.Addresses {
			a := address.Addr()
			if reserved[a] {
				return ErrPolicy
			}
			for _, b := range g.Bridges {
				if b.Lifecycle.Released() {
					continue
				}
				for _, pool := range b.Pools {
					if pool.Prefix.Contains(a) {
						return ErrPolicy
					}
				}
			}
			reserved[a] = true
			addresses[t.Owner]++
			if addresses[t.Owner] > n.MaxEndpoints {
				return ErrPolicy
			}
		}
	}
	return nil
}

// TunnelPeers is the activation dependency check, not a registration gate.
// Each route must name an entire remote committed pool or a host endpoint.
// Pending opposite intents may be committed in either order without a cycle.
func (g Graph) TunnelPeers(key string) ([]string, error) {
	topology := network.TunnelTopology{Tunnels: g.Tunnels}
	for _, b := range g.Bridges {
		if b.Lifecycle.Released() {
			continue
		}
		for _, pool := range b.Pools {
			topology.Pools = append(topology.Pools, network.RoutePool{Network: b.Network, Owner: b.Owner, Prefix: pool.Prefix})
		}
	}
	return topology.Peers(key)
}

func (p Policy) PacketPolicy(s state.State, g Graph) (network.PacketPolicy, error) {
	var endpoints []network.Endpoint
	add := func(key, owner, name string, a netip.Addr) {
		endpoints = append(endpoints, network.Endpoint{Owner: p.Owners[owner], Network: network.NetworkID(p.Cluster, name), ID: network.EndpointID(p.Cluster, name, owner, key, s.Object(key).Generation, a), Address: a})
	}
	for _, key := range Sorted(g.Tunnels) {
		t := g.Tunnels[key]
		if t.Lifecycle.Released() {
			continue
		}
		for _, a := range t.Addresses {
			add(key, t.Owner, t.Network, a.Addr())
		}
	}
	for _, key := range Sorted(g.Bridges) {
		b := g.Bridges[key]
		if b.Lifecycle.Released() {
			continue
		}
		for _, pool := range b.Pools {
			add(key, b.Owner, b.Network, pool.Gateway)
		}
	}
	for _, key := range Sorted(g.Tasks) {
		t := g.Tasks[key]
		if t.Lifecycle.Released() {
			continue
		}
		for _, a := range []netip.Addr{t.IPv4, t.IPv6} {
			if a.IsValid() {
				add(key, t.Node, g.Bridges[t.Bridge].Network, a)
			}
		}
	}
	return network.NewPacketPolicy(endpoints)
}
