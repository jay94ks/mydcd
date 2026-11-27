// SPDX-License-Identifier: Apache-2.0

package desired

import (
	"crypto/ed25519"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/schema"
	"net/netip"
	"testing"
)

func TestTunnelCommittedReservationsAndActivationDependencies(t *testing.T) {
	f := newFixture(t)
	node := NodeSpec{Schema: 1, Owner: f.owner, CPU: 1000000000, Memory: 128 << 20, MaxBridges: 2, MaxContainers: 4, MaxEndpoints: 4, MaxConsumers: 8, PacketQueuePackets: 8, PacketQueueBytes: 16 << 10}
	f.apply(NodePrefix+"a", node, state.Applied)
	seed := make([]byte, 32)
	seed[0] = 2
	otherPrivate := ed25519.NewKeyFromSeed(seed)
	otherPub := [32]byte(otherPrivate.Public().(ed25519.PublicKey))
	other := Owner(f.p.Cluster, otherPub)
	f.p.Owners[other] = otherPub
	node.Owner = other
	f.apply(NodePrefix+"b", node, state.Applied)
	a := network.TunnelSpec{Schema: 1, Owner: f.owner, Network: "net", MTU: 1280, RouteMetric: 100, Addresses: []netip.Prefix{netip.MustParsePrefix("10.249.24.1/32")}, Routes: []netip.Prefix{netip.MustParsePrefix("10.249.24.2/32")}}
	f.apply(TunnelPrefix+"a", a, state.Applied)
	originalGeneration := f.s.Object(TunnelPrefix + "a").Generation
	g, err := f.p.Project(f.s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = g.TunnelPeers(TunnelPrefix + "a"); err == nil {
		t.Fatal("activated absent opposite intent")
	}
	b := a
	b.Owner = other
	b.Addresses, b.Routes = a.Routes, a.Addresses
	f.apply(TunnelPrefix+"b", b, state.Applied)
	g, err = f.p.Project(f.s)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{TunnelPrefix + "a", TunnelPrefix + "b"} {
		if peers, err := g.TunnelPeers(key); err != nil || len(peers) != 1 {
			t.Fatal("sequential registration deadlocked", key, peers, err)
		}
	}
	policy, err := f.p.PacketPolicy(f.s, g)
	if err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 20)
	packet[0], packet[3] = 0x45, 20
	copy(packet[12:16], a.Addresses[0].Addr().AsSlice())
	copy(packet[16:20], b.Addresses[0].Addr().AsSlice())
	target, err := policy.Outbound(f.p.Owners[f.owner], network.NetworkID(f.p.Cluster, "net"), 1280, packet)
	if err != nil || target.Owner != otherPub {
		t.Fatal("committed endpoint routing", target, err)
	}
	f.apply(TunnelPrefix+"duplicate", a, state.Invalid)
	changed := a
	changed.MTU++
	f.apply(TunnelPrefix+"a", changed, state.Invalid)
	changed = a
	changed.Owner = other
	changed.Addresses = []netip.Prefix{netip.MustParsePrefix("10.251.240.3/32")}
	f.apply(TunnelPrefix+"overlap", changed, state.Invalid)
	f.apply(TunnelPrefix+"a", nil, state.Invalid)
	drain := a
	drain.Lifecycle = schema.Lifecycle{Drain: true, Nonce: [16]byte{1}}
	f.apply(TunnelPrefix+"a", drain, state.Applied)
	f.apply(TunnelPrefix+"duplicate", a, state.Invalid)
	drain.Lifecycle.Proof = f.proof(TunnelPrefix+"a", drain)
	f.apply(TunnelPrefix+"a", drain, state.Applied)
	f.apply(TunnelPrefix+"a", nil, state.Applied)
	f.apply(TunnelPrefix+"a", a, state.Applied)
	if f.s.Object(TunnelPrefix+"a").Generation <= originalGeneration {
		t.Fatal("recreated TUN reused generation")
	}
	g, _ = f.p.Project(f.s)
	updated, err := f.p.PacketPolicy(f.s, g)
	if err != nil {
		t.Fatal(err)
	}
	// The recreated address has a different source incarnation too. Reverse
	// the packet and require the new destination endpoint identifier.
	copy(packet[12:16], b.Addresses[0].Addr().AsSlice())
	copy(packet[16:20], a.Addresses[0].Addr().AsSlice())
	oldID := network.EndpointID(f.p.Cluster, "net", f.owner, TunnelPrefix+"a", originalGeneration, a.Addresses[0].Addr())
	if updated.Inbound(f.p.Owners[f.owner], otherPub, target.Network, oldID, 1280, packet) == nil {
		t.Fatal("old incarnation accepted")
	}
}
