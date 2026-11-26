// SPDX-License-Identifier: Apache-2.0

package services

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"
)

func signedRouteFlowReceipt(t *testing.T, core RouteRuntime, flow RouteFlow, key ed25519.PrivateKey) RouteFlowReceipt {
	t.Helper()
	p, err := core.FlowReceiptFacts(flow)
	if err != nil || p.JournalSynced || len(p.Signature) != 0 {
		t.Fatal("facts claimed an adapter store write or signature", err)
	}
	// Model the adapter's completed store write. This is not native/RPC proof.
	routeRaw(t, core)
	p.JournalSynced = true
	p.Signature = ed25519.Sign(key, RouteFlowReceiptBytes(p))
	return p
}

func TestRouteFlowReceiptBindsBothDurablePinsBeforePacketAdmission(t *testing.T) {
	r, a, b := routeBorrow(t, routeBoth(t))
	packet := routeTCPPacket(r.tuple.Source.Address, r.tuple.Destination.Address, r.tuple.SourcePort, r.tuple.DestinationPort, 2)
	if r.a.AllowsCoordinatedPacketBytes(r.f.c, r.f.n, r.f.a, a, r.b.boot, pub(r.f.key), packet, routeClock(r.a, 150)) {
		t.Fatal("one-sided source pin admitted a packet")
	}
	if _, err := r.b.FlowReceiptFacts(b); err == nil {
		t.Fatal("destination invented a source pin before receipt")
	}
	source := signedRouteFlowReceipt(t, r.a, a, r.f.key)
	var err error
	r.b, err = r.b.RecordPeerFlow(r.f.c, r.f.n, r.f.a, b, source, routeClock(r.b, 151))
	if err != nil {
		t.Fatal(err)
	}
	destination := signedRouteFlowReceipt(t, r.b, b, r.keyB)
	if destination.PeerPin != a.Lease() || source.PeerPin.Token != 0 {
		t.Fatal("destination did not acknowledge the exact original source pin")
	}
	wrongAck := ownRouteFlowReceipt(destination)
	wrongAck.PeerPin.Token++
	wrongAck.Signature = ed25519.Sign(r.keyB, RouteFlowReceiptBytes(wrongAck))
	if _, err := r.a.RecordPeerFlow(r.f.c, r.f.n, r.f.a, a, wrongAck, routeClock(r.a, 152)); err == nil {
		t.Fatal("destination receipt acknowledged a different source pin")
	}
	r.a, err = r.a.RecordPeerFlow(r.f.c, r.f.n, r.f.a, a, destination, routeClock(r.a, 152))
	if err != nil {
		t.Fatal(err)
	}
	for _, side := range []struct {
		core RouteRuntime
		flow RouteFlow
		peer [32]byte
	}{{r.a, a, r.b.boot}, {r.b, b, r.a.boot}} {
		raw := routeRaw(t, side.core)
		restored, err := DecodeRouteRuntime(raw)
		if err != nil {
			t.Fatal(err)
		}
		handle, found := restored.OriginalFlow(r.tuple)
		if !found || handle != side.flow || !restored.AllowsCoordinatedPacketBytes(r.f.c, r.f.n, r.f.a, handle, side.peer, pub(r.f.key), packet, routeClock(restored, 153)) {
			t.Fatal("same checkpoint did not preserve both pins", err)
		}
		other, err := restored.ResumeBoot([32]byte{77})
		if err != nil || other.FlowCount() != 1 || other.AllowsCoordinatedPacketBytes(r.f.c, r.f.n, r.f.a, handle, side.peer, pub(r.f.key), packet, routeClock(other, 154)) {
			t.Fatal("reboot erased original pins or admitted an old receipt", err)
		}
		routeRaw(t, other)
		if _, err := other.FlowReceiptFacts(handle); err == nil {
			t.Fatal("reboot signed a new receipt for an old flow")
		}
	}
	before := routeRaw(t, r.a)
	again, err := r.a.RecordPeerFlow(r.f.c, r.f.n, r.f.a, a, destination, routeClock(r.a, 153))
	if err != nil || !bytes.Equal(before, routeRaw(t, again)) {
		t.Fatal("lost response replay replaced the original pins", err)
	}
	// Input ownership cannot mutate the accepted checkpoint.
	destination.Signature[0] ^= 1
	if !bytes.Equal(before, routeRaw(t, r.a)) {
		t.Fatal("receipt signature aliased caller memory")
	}
	r = routeWithdraw(t, r)
	if r.a.AllowsCoordinatedPacketBytes(r.f.c, r.f.n, r.f.a, a, r.b.boot, pub(r.f.key), packet, routeClock(r.a, 154)) {
		t.Fatal("old receipt bypassed current withdrawal")
	}
}

func TestRouteFlowReceiptRejectsForeignFactsAndCheckpointSubstitution(t *testing.T) {
	r, a, b := routeBorrow(t, routeBoth(t))
	source := signedRouteFlowReceipt(t, r.a, a, r.f.key)
	before := routeRaw(t, r.b)
	for _, mutate := range []func(*RouteFlowReceipt){
		func(p *RouteFlowReceipt) { p.Cluster[0]++ },
		func(p *RouteFlowReceipt) { p.Reference.Lifetime.Token++ },
		func(p *RouteFlowReceipt) { p.Pin.Generation++ },
		func(p *RouteFlowReceipt) { p.Pin.Token = 0 },
		func(p *RouteFlowReceipt) { p.Boot[0]++ },
		func(p *RouteFlowReceipt) { p.Tuple[0]++ },
		func(p *RouteFlowReceipt) { p.Peer.Consumer[0]++ },
		func(p *RouteFlowReceipt) { p.PeerBoot[0]++ },
		func(p *RouteFlowReceipt) { p.PeerPin = b.Lease() },
		func(p *RouteFlowReceipt) { p.JournalSynced = false },
	} {
		bad := ownRouteFlowReceipt(source)
		mutate(&bad)
		bad.Signature = ed25519.Sign(r.f.key, RouteFlowReceiptBytes(bad))
		if _, err := r.b.RecordPeerFlow(r.f.c, r.f.n, r.f.a, b, bad, routeClock(r.b, 151)); err == nil {
			t.Fatal("foreign or incomplete receipt was accepted")
		}
	}
	badSignature := ownRouteFlowReceipt(source)
	badSignature.Signature[0] ^= 1
	if _, err := r.b.RecordPeerFlow(r.f.c, r.f.n, r.f.a, b, badSignature, routeClock(r.b, 151)); err == nil || !bytes.Equal(before, routeRaw(t, r.b)) {
		t.Fatal("rejected receipt changed the original checkpoint")
	}
	next, err := r.b.RecordPeerFlow(r.f.c, r.f.n, r.f.a, b, source, routeClock(r.b, 151))
	if err != nil {
		t.Fatal(err)
	}
	otherPin := ownRouteFlowReceipt(source)
	otherPin.Pin.Token++
	otherPin.Signature = ed25519.Sign(r.f.key, RouteFlowReceiptBytes(otherPin))
	if _, err := next.RecordPeerFlow(r.f.c, r.f.n, r.f.a, b, otherPin, routeClock(next, 152)); err == nil {
		t.Fatal("new source pin replaced an accepted receipt")
	}
	snapshot, err := next.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Flows[0].Remote.PeerBoot[0]++
	corrupt, _ := json.Marshal(snapshot)
	if _, err := DecodeRouteRuntime(corrupt); err == nil {
		t.Fatal("checkpoint decoder accepted a substituted receipt")
	}
	routeRaw(t, next)
}

func TestLegacyOneSidedRouteFlowCheckpointDoesNotAcquirePeerReceipt(t *testing.T) {
	r, a, _ := routeBorrow(t, routeBoth(t))
	legacy := r.a.clone()
	f := legacy.flows[a.Lease().Token]
	f.Boot = [32]byte{}
	legacy.flows[a.Lease().Token] = f
	raw := routeRaw(t, legacy)
	if bytes.Contains(raw, []byte(`"Remote":`)) {
		t.Fatal("legacy omission bytes were changed")
	}
	restored, err := DecodeRouteRuntime(raw)
	if err != nil || !bytes.Equal(raw, routeRaw(t, restored)) {
		t.Fatal("legacy checkpoint did not preserve its original encoding", err)
	}
	if _, err := restored.FlowReceiptFacts(a); err == nil {
		t.Fatal("legacy one-sided pin acquired a current signed receipt")
	}
	packet := routeTCPPacket(r.tuple.Source.Address, r.tuple.Destination.Address, r.tuple.SourcePort, r.tuple.DestinationPort, 2)
	if restored.AllowsCoordinatedPacketBytes(r.f.c, r.f.n, r.f.a, a, r.b.boot, pub(r.f.key), packet, routeClock(restored, 151)) {
		t.Fatal("legacy one-sided pin bypassed the two-sided gate")
	}
}
