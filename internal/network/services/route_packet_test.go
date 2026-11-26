// SPDX-License-Identifier: Apache-2.0

package services

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

// Explicit raw packet/model-native facts exercise the reused product core.
// These tests perform no kernel IO or peer authentication/native publication.
func routeTCPPacket(source, destination netip.Addr, sourcePort, destinationPort uint16, flags byte) []byte {
	packet := make([]byte, 40)
	packet[0], packet[9] = 0x45, 6
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[12:16], source.AsSlice())
	copy(packet[16:20], destination.AsSlice())
	binary.BigEndian.PutUint16(packet[20:22], sourcePort)
	binary.BigEndian.PutUint16(packet[22:24], destinationPort)
	packet[32], packet[33] = 0x50, flags
	return packet
}

func TestRoutePacketBoundaryRetainsBothOriginalPinsForRetransmissionAndReply(t *testing.T) {
	r := routeBoth(t)
	packet := routeTCPPacket(r.tuple.Source.Address, r.tuple.Destination.Address, r.tuple.SourcePort, r.tuple.DestinationPort, 2)
	reply := routeTCPPacket(r.tuple.Destination.Address, r.tuple.Source.Address, r.tuple.DestinationPort, r.tuple.SourcePort, 0x12)
	aProof, err := r.a.AppliedProof(r.f.c, r.f.n, r.f.a)
	if err != nil {
		t.Fatal(err)
	}
	bProof, err := r.b.AppliedProof(r.f.c, r.f.n, r.f.a)
	if err != nil {
		t.Fatal(err)
	}
	a, aFlow, err := r.a.BorrowPacket(r.f.c, r.f.n, r.f.a, bProof, r.b.boot, pub(r.f.key), packet, routeClock(r.a, 150))
	if err != nil {
		t.Fatal("source raw packet could not enter original flow algorithm", err)
	}
	b, bFlow, err := r.b.BorrowPacket(r.f.c, r.f.n, r.f.a, aProof, r.a.boot, pub(r.f.key), packet, routeClock(r.b, 150))
	if err != nil {
		t.Fatal("destination raw packet could not enter original flow algorithm", err)
	}
	if aFlow.Tuple() != r.tuple || bFlow.Tuple() != r.tuple || len(a.flows) != 1 || len(b.flows) != 1 || len(r.a.flows) != 0 || len(r.b.flows) != 0 {
		t.Fatal("packet boundary copied/recreated the original flow algorithm")
	}
	for _, side := range []struct {
		current RouteRuntime
		flow    RouteFlow
		peer    [32]byte
	}{{a, aFlow, b.boot}, {b, bFlow, a.boot}} {
		raw := routeRaw(t, side.current)
		restored, err := DecodeRouteRuntime(raw)
		if err != nil {
			t.Fatal(err)
		}
		for i, input := range [][]byte{packet, reply} {
			sender := pub(r.f.key)
			if i == 1 {
				sender = pub(r.keyB)
			}
			flow, err := restored.ExistingPacket(r.f.c, r.f.n, r.f.a, side.peer, sender, input, routeClock(restored, 151))
			if err != nil || flow.Lease() != side.flow.Lease() || !restored.AllowsPacketBytes(r.f.c, r.f.n, r.f.a, flow, side.peer, sender, input, routeClock(restored, 151)) {
				t.Fatal("reply/retransmission did not retain original durable pin", err)
			}
		}
		if !bytes.Equal(raw, routeRaw(t, restored)) {
			t.Fatal("packet lookup changed the checkpoint")
		}
	}
}

func TestRoutePacketBoundaryRejectsSpoofedUnknownReverseAndRetiredTraffic(t *testing.T) {
	r := routeBoth(t)
	proof, _ := r.b.AppliedProof(r.f.c, r.f.n, r.f.a)
	packet := routeTCPPacket(r.tuple.Source.Address, r.tuple.Destination.Address, r.tuple.SourcePort, r.tuple.DestinationPort, 2)
	raw := routeRaw(t, r.a)
	for label, input := range map[string][]byte{
		"unknown-address": routeTCPPacket(addr("10.42.0.99"), r.tuple.Destination.Address, r.tuple.SourcePort, r.tuple.DestinationPort, 2),
		"wrong-port":      routeTCPPacket(r.tuple.Source.Address, r.tuple.Destination.Address, r.tuple.SourcePort, 3307, 2),
		"new-ack":         routeTCPPacket(r.tuple.Source.Address, r.tuple.Destination.Address, r.tuple.SourcePort, r.tuple.DestinationPort, 0x10),
		"reverse-new":     routeTCPPacket(r.tuple.Destination.Address, r.tuple.Source.Address, r.tuple.DestinationPort, r.tuple.SourcePort, 2),
	} {
		if _, _, err := r.a.BorrowPacket(r.f.c, r.f.n, r.f.a, proof, r.b.boot, pub(r.f.key), input, routeClock(r.a, 150)); err == nil || !bytes.Equal(raw, routeRaw(t, r.a)) {
			t.Fatal("unapproved packet created a pin", label, err)
		}
	}
	if _, _, err := r.a.BorrowPacket(r.f.c, r.f.n, r.f.a, proof, r.b.boot, pub(r.keyB), packet, routeClock(r.a, 150)); err == nil {
		t.Fatal("sender spoof acquired a source flow")
	}
	a, flow, err := r.a.BorrowPacket(r.f.c, r.f.n, r.f.a, proof, r.b.boot, pub(r.f.key), packet, routeClock(r.a, 150))
	if err != nil {
		t.Fatal(err)
	}
	r.a = a
	if _, err := r.a.ExistingPacket(r.f.c, r.f.n, r.f.a, [32]byte{99}, pub(r.f.key), packet, routeClock(r.a, 151)); err == nil {
		t.Fatal("different peer boot adopted old pin")
	}
	r = routeWithdraw(t, r)
	if r.a.AllowsPacketBytes(r.f.c, r.f.n, r.f.a, flow, r.b.boot, pub(r.f.key), packet, routeClock(r.a, 152)) || len(r.a.flows) != 1 {
		t.Fatal("withdraw forwarded traffic or erased its original pin before native close")
	}
}
