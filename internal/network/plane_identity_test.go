// SPDX-License-Identifier: Apache-2.0

package network

import (
	"bytes"
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/sfcp"
)

func TestPacketPlanRetainsOriginalEndpointPolicyWithCurrentLocalRelay(t *testing.T) {
	originalA, originalB, current := [32]byte{211}, [32]byte{212}, [32]byte{213}
	id, token := [16]byte{214}, [16]byte{215}
	source := Endpoint{Owner: originalA, Network: id, ID: [16]byte{216}, Address: netip.MustParseAddr("10.1.0.10")}
	target := Endpoint{Owner: originalB, Network: id, ID: [16]byte{217}, Address: netip.MustParseAddr("10.2.0.10")}
	policy, err := NewPacketPolicy([]Endpoint{source, target})
	if err != nil {
		t.Fatal(err)
	}
	packet := transportPacket(4, 6)
	aliases := map[[32]byte]bool{originalA: true, originalB: true}
	sourcePlane := &PacketPlane{ctx: t.Context(), local: originalA, network: id, spec: routeTunnelSpec(true)}
	sourcePlane.SetPlan(PacketPlan{WireKey: current, LocalOwners: aliases, Policy: policy, Gate: fixedRouteBindingGate{PacketBinding{token, target}}, Relay: func(Endpoint, [16]byte, []byte) error { return nil }})
	endpoint, local, err := sourcePlane.outboundTarget(sourcePlane.plan.Load(), packet)
	if err != nil || !local || endpoint != target {
		t.Fatal("same current node lost original distinct-owner route", err)
	}
	delete(aliases, originalA)
	delete(aliases, originalB)
	if !sourcePlane.plan.Load().LocalOwners[originalB] {
		t.Fatal("published owner mapping aliased caller map")
	}
	io := newRouteMemoryIO()
	destination, err := NewPacketPlane(t.Context(), originalB, id, routeTunnelSpec(false), io, PacketLimits{QueuePackets: 4, QueueBytes: 4096}, PacketPlan{WireKey: current, LocalOwners: map[[32]byte]bool{originalA: true}, Policy: policy, Gate: fixedRouteBindingGate{PacketBinding{token, target}}})
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Stop()
	if err := destination.ReceiveLocal(token, packet); err != nil {
		t.Fatal("original source/endpoint/token did not reach retained local native", err)
	}
	select {
	case got := <-io.written:
		if !bytes.Equal(got, packet) {
			t.Fatal("original packet bytes changed")
		}
	case <-time.After(time.Second):
		t.Fatal("retained local native write missing")
	}
	// Losing current same-node ownership must fence both new and queued bytes.
	destination.SetPlan(PacketPlan{WireKey: current, Policy: policy, Gate: fixedRouteBindingGate{PacketBinding{token, target}}})
	if err := destination.ReceiveLocal(token, packet); err != sfcp.ErrAdmission {
		t.Fatal("removed current mapping admitted an old original local source", err)
	}
	if policy.Inbound(originalB, current, id, target.ID, 1280, packet) == nil {
		t.Fatal("wire identity was substituted for original endpoint owner")
	}
}

func TestPacketPlanDefaultWireIdentityPreservesOriginalLocalContract(t *testing.T) {
	original, id := [32]byte{221}, [16]byte{222}
	target := Endpoint{Owner: original, Network: id, ID: [16]byte{223}, Address: netip.MustParseAddr("10.2.0.10")}
	policy, err := NewPacketPolicy([]Endpoint{{Owner: original, Network: id, ID: [16]byte{224}, Address: netip.MustParseAddr("10.1.0.10")}, target})
	if err != nil {
		t.Fatal(err)
	}
	p := &PacketPlane{ctx: context.Background(), local: original, network: id, spec: routeTunnelSpec(false)}
	token := [16]byte{225}
	p.SetPlan(PacketPlan{Policy: policy, Gate: fixedRouteBindingGate{PacketBinding{token, target}}})
	packet := transportPacket(4, 6)
	frame := sfcp.Frame{Purpose: sfcp.Packet, Kind: 2, Fields: []sfcp.Field{{Tag: 1, Required: true, Value: original[:]}, {Tag: 2, Required: true, Value: id[:]}, {Tag: 3, Required: true, Value: token[:]}, {Tag: 4, Required: true, Value: packet}}}
	if !p.admittedLocal(frame) || p.plan.Load().WireKey != ([32]byte{}) || len(p.plan.Load().LocalOwners) != 0 {
		t.Fatal("zero mapping changed the original unrotated route contract")
	}
}
