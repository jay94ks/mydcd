// SPDX-License-Identifier: Apache-2.0

package network

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestClusterAppAddressIsFixedInThePool(t *testing.T) {
	if a, ok := ClusterAppAddress("web"); !ok || a != netip.MustParseAddr("10.254.0.2") {
		t.Fatal(a, ok)
	}
	if a, ok := ClusterAppAddress("nope"); ok {
		t.Fatal(a)
	}
	if a, ok := ClusterAppPoolAddress(netip.MustParsePrefix("10.254.7.0/24"), "web"); !ok || a != netip.MustParseAddr("10.254.7.2") {
		t.Fatal(a, ok)
	}
	for _, c := range []struct{ pool, app string }{{"10.254.7.0/24", "nope"}, {"10.30.0.0/24", "web"}, {"10.254.7.0/25", "web"}, {"10.254.0.0/24", "web"}, {"10.254.240.0/24", "web"}} {
		if a, ok := ClusterAppPoolAddress(netip.MustParsePrefix(c.pool), c.app); ok {
			t.Fatal(c, a)
		}
	}
}

// A cluster app's address is the runner's like its pool: another member's
// TUN that routes it finds the runner as its peer, and the packet policy
// lets a packet from that member's address through to it and back.
func TestClusterAddressRoutesToItsRunner(t *testing.T) {
	cluster, _ := ClusterAppAddress("web")
	a, b := "cluster/a", "cluster/b"
	tunA := TunnelSpec{Schema: 1, Owner: a, Network: "sfc-system", Addresses: []netip.Prefix{netip.MustParsePrefix("10.254.240.1/32")},
		Routes: []netip.Prefix{netip.MustParsePrefix("10.254.0.2/32"), netip.MustParsePrefix("10.254.2.0/24"), netip.MustParsePrefix("10.254.240.2/32")}}
	tunB := TunnelSpec{Schema: 1, Owner: b, Network: "sfc-system", Addresses: []netip.Prefix{netip.MustParsePrefix("10.254.240.2/32")},
		Routes: []netip.Prefix{netip.MustParsePrefix("10.254.1.0/24"), netip.MustParsePrefix("10.254.240.1/32")}}
	g := TunnelTopology{Tunnels: map[string]TunnelSpec{"tun/a": tunA, "tun/b": tunB}, Pools: []RoutePool{
		{Network: "sfc-system", Owner: a, Prefix: netip.MustParsePrefix("10.254.1.0/24")},
		{Network: "sfc-system", Owner: b, Prefix: netip.MustParsePrefix("10.254.2.0/24")},
		{Network: "sfc-system", Owner: b, Prefix: netip.PrefixFrom(cluster, 32)},
	}}
	if peers, err := g.Peers("tun/a"); err != nil || len(peers) != 1 || peers[0] != b {
		t.Fatal(peers, err)
	}
	id := NetworkID([32]byte{9}, "sfc-system")
	ownerA, ownerB := [32]byte{1}, [32]byte{2}
	endpoint := func(owner [32]byte, key, addr string) Endpoint {
		a := netip.MustParseAddr(addr)
		return Endpoint{Owner: owner, Network: id, ID: EndpointID([32]byte{9}, "sfc-system", key, key, 1, a), Address: a}
	}
	p, err := NewPacketPolicy([]Endpoint{endpoint(ownerA, "tun/a", "10.254.240.1"), endpoint(ownerB, "bridge/b", "10.254.2.1"), endpoint(ownerB, "bridge/b", cluster.String())})
	if err != nil {
		t.Fatal(err)
	}
	out, err := p.Outbound(ownerA, id, 1280, ipv4Packet(netip.MustParseAddr("10.254.240.1"), cluster))
	if err != nil || out.Owner != ownerB || out.Address != cluster {
		t.Fatal(out, err)
	}
	if err = p.Inbound(ownerB, ownerA, id, out.ID, 1280, ipv4Packet(netip.MustParseAddr("10.254.240.1"), cluster)); err != nil {
		t.Fatal(err)
	}
	if back, err := p.Outbound(ownerB, id, 1280, ipv4Packet(cluster, netip.MustParseAddr("10.254.240.1"))); err != nil || back.Owner != ownerA {
		t.Fatal("reply", back, err)
	}
}

func ipv4Packet(src, dst netip.Addr) []byte {
	b := make([]byte, 40)
	b[0], b[9] = 0x45, 6
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	copy(b[12:16], src.AsSlice())
	copy(b[16:20], dst.AsSlice())
	return b
}
