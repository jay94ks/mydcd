// SPDX-License-Identifier: Apache-2.0

package services

import (
	"encoding/binary"
	"testing"

	"github.com/jay94ks/seafield/internal/network"
)

// Only native/store facts are modeled. Packet parsing, allocation authority,
// bilateral receipts, checkpointing and token derivation use the product core.
func coordinatedRouteFixture(t *testing.T, r routeFixture) (routeFixture, RouteFlow, RouteFlow) {
	t.Helper()
	r, source, destination := routeBorrow(t, r)
	var err error
	r.b, err = r.b.RecordPeerFlow(r.f.c, r.f.n, r.f.a, destination, signedRouteFlowReceipt(t, r.a, source, r.f.key), routeClock(r.b, 151))
	if err != nil {
		t.Fatal(err)
	}
	r.a, err = r.a.RecordPeerFlow(r.f.c, r.f.n, r.f.a, source, signedRouteFlowReceipt(t, r.b, destination, r.keyB), routeClock(r.a, 152))
	if err != nil {
		t.Fatal(err)
	}
	return r, source, destination
}

func routeBindingPacket(tuple RouteTuple) []byte {
	packet := routeTCPPacket(tuple.Source.Address, tuple.Destination.Address, tuple.SourcePort, tuple.DestinationPort, 2)
	if tuple.Protocol == 17 {
		packet = packet[:28]
		packet[9] = 17
		binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
		binary.BigEndian.PutUint16(packet[24:26], 8)
	}
	return packet
}

func TestRoutePacketBindingUsesSameBilateralIncarnationForBothDirections(t *testing.T) {
	for _, protocol := range []uint8{6, 17} {
		t.Run(map[uint8]string{6: "TCP", 17: "UDP"}[protocol], func(t *testing.T) {
			r := routeCoreFixtureProtocol(t, protocol)
			r.a = routeInstall(t, r.a, r.f.key)
			r.b = routeInstall(t, r.b, r.keyB)
			if _, ok := r.a.PacketBinding(r.f.c, r.f.n, r.f.a, pub(r.f.key), routeBindingPacket(r.tuple), routeClock(r.a, 150)); ok {
				t.Fatal("uncoordinated flow acquired a packet token")
			}
			r, _, _ = coordinatedRouteFixture(t, r)
			var token [16]byte
			for _, core := range []RouteRuntime{r.a, r.b} {
				restored, err := DecodeRouteRuntime(routeRaw(t, core))
				if err != nil {
					t.Fatal(err)
				}
				for direction, tuple := range []RouteTuple{r.tuple, reverseTuple(r.tuple)} {
					sender, owner := pub(r.f.key), pub(r.keyB)
					if direction == 1 {
						sender, owner = owner, sender
					}
					packet := routeBindingPacket(tuple)
					binding, ok := restored.PacketBinding(r.f.c, r.f.n, r.f.a, sender, packet, routeClock(restored, 153))
					name := routePacketNetwork(core.consumer)
					want := network.Endpoint{Owner: owner, Network: network.NetworkID(core.consumer.Local.Cluster, name), ID: network.EndpointID(core.consumer.Local.Cluster, name, tuple.Destination.Owner, tuple.Destination.Endpoint, tuple.Destination.Generation, tuple.Destination.Address), Address: tuple.Destination.Address}
					if !ok || binding.Token == ([16]byte{}) || binding.Endpoint != want {
						t.Fatal("binding did not preserve the exact destination allocation", binding, ok)
					}
					if token == ([16]byte{}) {
						token = binding.Token
					} else if binding.Token != token {
						t.Fatal("owners/directions/checkpoint derived different flow tokens")
					}
					if _, ok := restored.PacketBinding(r.f.c, r.f.n, r.f.a, [32]byte{99}, packet, routeClock(restored, 154)); ok {
						t.Fatal("foreign sender acquired a packet binding")
					}
				}
				other, err := restored.ResumeBoot([32]byte{77})
				if err != nil {
					t.Fatal(err)
				}
				if _, ok := other.PacketBinding(r.f.c, r.f.n, r.f.a, pub(r.f.key), routeBindingPacket(r.tuple), routeClock(other, 154)); ok {
					t.Fatal("new boot adopted an old bilateral flow")
				}
			}
			r = routeWithdraw(t, r)
			if _, ok := r.a.PacketBinding(r.f.c, r.f.n, r.f.a, pub(r.f.key), routeBindingPacket(r.tuple), routeClock(r.a, 154)); ok {
				t.Fatal("old token bypassed current withdrawal")
			}
		})
	}
}

func TestRoutePacketBindingChangesWhenClosedTupleIsReused(t *testing.T) {
	r, source, destination := coordinatedRouteFixture(t, routeBoth(t))
	packet := routeBindingPacket(r.tuple)
	old, ok := r.a.PacketBinding(r.f.c, r.f.n, r.f.a, pub(r.f.key), packet, routeClock(r.a, 153))
	if !ok {
		t.Fatal("missing original bilateral binding")
	}
	var err error
	r.a, err = r.a.ReleaseFlow(source, routeFlowProof(r.a, source, r.f.key))
	if err != nil {
		t.Fatal(err)
	}
	r.b, err = r.b.ReleaseFlow(destination, routeFlowProof(r.b, destination, r.keyB))
	if err != nil {
		t.Fatal(err)
	}
	r, freshSource, freshDestination := coordinatedRouteFixture(t, r)
	fresh, ok := r.b.PacketBinding(r.f.c, r.f.n, r.f.a, pub(r.f.key), packet, routeClock(r.b, 153))
	if !ok || fresh.Token == old.Token || fresh.Endpoint != old.Endpoint || source == freshSource || destination == freshDestination {
		t.Fatal("same tuple reused a returned packet incarnation")
	}
	// Each identity input is significant even when endpoints/ports are unchanged.
	flow := r.a.flows[freshSource.Lease().Token]
	for _, mutate := range []func(*RouteRuntime, *routeFlowState){
		func(_ *RouteRuntime, f *routeFlowState) { f.Boot[0]++ },
		func(_ *RouteRuntime, f *routeFlowState) { f.Peer.Boot[0]++ },
		func(_ *RouteRuntime, f *routeFlowState) { f.Pin.Token++ },
		func(_ *RouteRuntime, f *routeFlowState) { f.Remote.Pin.Token++ },
		func(_ *RouteRuntime, f *routeFlowState) { f.Peer.Reference.Lifetime.Token++ },
		func(_ *RouteRuntime, f *routeFlowState) { f.Tuple.Destination.Generation++ },
		func(m *RouteRuntime, _ *routeFlowState) { m.consumer.Local.Cluster[0]++ },
	} {
		core := r.a.clone()
		changed := core.flows[flow.Pin.Token]
		mutate(&core, &changed)
		if core.packetToken(changed) == fresh.Token {
			t.Fatal("identity substitution preserved the packet token")
		}
	}
}
