// SPDX-License-Identifier: Apache-2.0

package network

import (
	"net/netip"
	"testing"
)

func TestRetargetKeepsThePlaneForARouteSetChangeOnly(t *testing.T) {
	local, id := [32]byte{91}, [16]byte{92}
	spec := TunnelSpec{Schema: 1, Owner: "owner", Network: "tenant/a/network/n", MTU: 1280, RouteMetric: 100,
		Addresses: []netip.Prefix{netip.MustParsePrefix("10.9.0.1/32")}, Routes: []netip.Prefix{netip.MustParsePrefix("10.9.1.0/24")}}
	p, err := NewPacketPlane(t.Context(), local, id, spec, newRouteMemoryIO(), PacketLimits{QueuePackets: 2, QueueBytes: 4096}, PacketPlan{})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Stop()
	joined := spec.Clone()
	joined.Routes = append(joined.Routes, netip.MustParsePrefix("10.9.2.0/24"))
	if p.routed(ipv4To("10.9.2.5")) {
		t.Fatal("a peer's prefix routed before it joined")
	}
	if !p.Retargetable() || p.Retarget(joined, PacketPlan{}) != nil || !p.routed(ipv4To("10.9.2.5")) || !p.routed(ipv4To("10.9.1.5")) {
		t.Fatal("a joining member did not retarget the serving plane")
	}
	mtu := joined.Clone()
	mtu.MTU = 1380
	if p.Retarget(mtu, PacketPlan{}) == nil {
		t.Fatal("an MTU change retargeted instead of a new plane")
	}
	policy, err := NewPacketPlane(t.Context(), local, id, routeTunnelSpec(false), newRouteMemoryIO(), PacketLimits{QueuePackets: 2, QueueBytes: 4096}, PacketPlan{Gate: fixedRouteBindingGate{}})
	if err != nil {
		t.Fatal(err)
	}
	defer policy.Stop()
	if policy.Retargetable() {
		t.Fatal("a route policy plane is retargetable")
	}
}

func ipv4To(dst string) []byte {
	b := make([]byte, 20)
	b[0], b[3] = 0x45, 20
	copy(b[12:16], netip.MustParseAddr("10.9.0.1").AsSlice())
	copy(b[16:20], netip.MustParseAddr(dst).AsSlice())
	return b
}
