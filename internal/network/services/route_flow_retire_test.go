// SPDX-License-Identifier: Apache-2.0

package services

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func signedClosingRouteClaim(t *testing.T, core RouteRuntime, flow RouteFlow, key ed25519.PrivateKey) RouteFlowReceipt {
	t.Helper()
	claim, err := core.ClosingSourceClaimFacts(flow)
	if err != nil || claim.JournalSynced || len(claim.Signature) != 0 {
		t.Fatal("core invented stored source claim facts", err)
	}
	routeRaw(t, core) // Model adapter sync, not a native/real store success.
	claim.JournalSynced = true
	claim.Signature = ed25519.Sign(key, RouteFlowReceiptBytes(claim))
	return claim
}

func signedPeerRouteClose(t *testing.T, core RouteRuntime, a Authority, claim RouteFlowReceipt, tuple RouteTuple, key ed25519.PrivateKey) RoutePeerFlowClose {
	t.Helper()
	proof, err := core.PeerFlowCloseFacts(a, claim, tuple)
	if err != nil || proof.JournalSynced || proof.Stopped || proof.NoPending || proof.Tombstoned || len(proof.Signature) != 0 {
		t.Fatal("core invented native/store closure", err)
	}
	routeRaw(t, core)
	proof.JournalSynced, proof.Stopped, proof.NoPending, proof.Tombstoned = true, true, true, true
	proof.Signature = ed25519.Sign(key, RoutePeerFlowCloseBytes(proof))
	return proof
}

func closingRouteSource(t *testing.T, r routeFixture, flow RouteFlow) routeFixture {
	t.Helper()
	var err error
	r.a, err = r.a.TrackFlow(flow)
	if err != nil {
		t.Fatal(err)
	}
	r.a, err = r.a.BeginFlowClose(flow)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestBilateralRouteFlowCloseRetainsSourceUntilPeerTombstoneAndReplaysAcrossBoot(t *testing.T) {
	r, source, destination := coordinatedRouteFixture(t, routeBoth(t))
	r = closingRouteSource(t, r, source)
	claim := signedClosingRouteClaim(t, r.a, source, r.f.key)
	if _, err := r.b.PeerFlowCloseFacts(r.f.a, claim, r.tuple); err == nil {
		t.Fatal("live destination invented a tombstone")
	}
	var err error
	var original RouteFlow
	r.b, original, err = r.b.BeginPeerFlowClose(r.f.a, claim, r.tuple)
	if err != nil || original != destination || r.b.FlowCount() != 1 || r.a.FlowCount() != 1 {
		t.Fatal("begin close returned/substituted a pin", err)
	}
	r.b, err = DecodeRouteRuntime(routeRaw(t, r.b))
	if err != nil {
		t.Fatal(err)
	}
	before := routeRaw(t, r.b)
	again, original, err := r.b.BeginPeerFlowClose(r.f.a, claim, r.tuple)
	if err != nil || original != destination || !bytes.Equal(before, routeRaw(t, again)) {
		t.Fatal("lost stop response changed the original Closing pin", err)
	}
	unsigned, err := r.b.FlowCloseFacts(destination)
	if err != nil || unsigned.Stopped || unsigned.NoPending || unsigned.JournalSynced {
		t.Fatal("facts supplied native IO closure", err)
	}
	if _, err := r.b.FinishPeerFlowClose(r.f.a, destination, claim, unsigned); err == nil {
		t.Fatal("unsigned local facts returned a live destination pin")
	}
	r.b, err = r.b.FinishPeerFlowClose(r.f.a, destination, claim, routeFlowProof(r.b, destination, r.keyB))
	if err != nil || r.b.FlowCount() != 0 || r.a.FlowCount() != 1 {
		t.Fatal("peer close returned the source pin", err)
	}
	proof := signedPeerRouteClose(t, r.b, r.f.a, claim, r.tuple, r.keyB)
	for _, mutate := range []func(*RoutePeerFlowClose){
		func(p *RoutePeerFlowClose) { p.JournalSynced = false },
		func(p *RoutePeerFlowClose) { p.Tombstoned = false },
		func(p *RoutePeerFlowClose) { p.NoPending = false },
		func(p *RoutePeerFlowClose) { p.Stopped = false },
		func(p *RoutePeerFlowClose) { p.Reference.Lifetime.Token++ },
		func(p *RoutePeerFlowClose) { p.Boot[0]++ },
		func(p *RoutePeerFlowClose) { p.Claim.Pin.Token++ },
	} {
		bad := proof
		bad.Claim = ownRouteFlowReceipt(proof.Claim)
		mutate(&bad)
		bad.Signature = ed25519.Sign(r.keyB, RoutePeerFlowCloseBytes(bad))
		if _, err := r.a.FinishSourceFlowClose(source, routeFlowProof(r.a, source, r.f.key), bad); err == nil {
			t.Fatal("incomplete/foreign peer closure returned source pin")
		}
	}
	r.a, err = r.a.FinishSourceFlowClose(source, routeFlowProof(r.a, source, r.f.key), proof)
	if err != nil || r.a.FlowCount() != 0 {
		t.Fatal("complete bilateral closure did not return source pin", err)
	}
	reopened, err := DecodeRouteRuntime(routeRaw(t, r.b))
	if err != nil {
		t.Fatal(err)
	}
	reopened, err = reopened.ResumeBoot([32]byte{79})
	if err != nil {
		t.Fatal(err)
	}
	replayed, handle, err := reopened.BeginPeerFlowClose(r.f.a, claim, r.tuple)
	if err != nil || handle.Lease().Token != 0 {
		t.Fatal("closed claim recreated a destination pin after boot", err)
	}
	receipt := signedPeerRouteClose(t, replayed, r.f.a, claim, r.tuple, r.keyB)
	if !bytes.Equal(RoutePeerFlowCloseBytes(proof), RoutePeerFlowCloseBytes(receipt)) || !bytes.Equal(proof.Signature, receipt.Signature) {
		t.Fatal("same durable tombstone created new boot/signature facts")
	}
	originalNative, err := r.a.AppliedProof(r.f.c, r.f.n, r.f.a)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.b.AcceptPeerFlow(r.f.c, r.f.n, r.f.a, originalNative, claim, r.tuple, routeClock(r.b, 154)); err == nil {
		t.Fatal("late source admission reopened a returned destination pin")
	}
	oldClaim := claim
	r, _, freshDestination := coordinatedRouteFixture(t, r)
	unchanged, oldHandle, err := r.b.BeginPeerFlowClose(r.f.a, oldClaim, r.tuple)
	if err != nil || oldHandle.Lease().Token != 0 || !bytes.Equal(routeRaw(t, r.b), routeRaw(t, unchanged)) || unchanged.FlowCount() != 1 || unchanged.Flows()[0] != freshDestination {
		t.Fatal("delayed old close touched the new same-tuple lifetime", err)
	}
}

func TestRouteFlowCloseBeforeDestinationAdmissionSealsLateClaimWithoutPin(t *testing.T) {
	r := routeBoth(t)
	aProof, err := r.a.AppliedProof(r.f.c, r.f.n, r.f.a)
	if err != nil {
		t.Fatal(err)
	}
	bProof, err := r.b.AppliedProof(r.f.c, r.f.n, r.f.a)
	if err != nil {
		t.Fatal(err)
	}
	var source RouteFlow
	r.a, source, err = r.a.BorrowFlow(r.f.c, r.f.n, r.f.a, bProof, r.b.boot, r.tuple, routeClock(r.a, 150))
	if err != nil {
		t.Fatal(err)
	}
	r = closingRouteSource(t, r, source)
	claim := signedClosingRouteClaim(t, r.a, source, r.f.key)
	nextToken := r.b.pins.Next
	var handle RouteFlow
	r.b, handle, err = r.b.BeginPeerFlowClose(r.f.a, claim, r.tuple)
	if err != nil || handle.Lease().Token != 0 || r.b.pins.Next != nextToken || r.b.FlowCount() != 0 {
		t.Fatal("never-admitted claim manufactured a destination pin", err)
	}
	r.b, err = DecodeRouteRuntime(routeRaw(t, r.b))
	if err != nil {
		t.Fatal(err)
	}
	proof := signedPeerRouteClose(t, r.b, r.f.a, claim, r.tuple, r.keyB)
	r.a, err = r.a.FinishSourceFlowClose(source, routeFlowProof(r.a, source, r.f.key), proof)
	if err != nil || r.a.FlowCount() != 0 {
		t.Fatal("durable no-admission closure did not settle pending source", err)
	}
	if _, _, err := r.b.AcceptPeerFlow(r.f.c, r.f.n, r.f.a, aProof, claim, r.tuple, routeClock(r.b, 154)); err == nil {
		t.Fatal("late claim escaped its never-admitted tombstone")
	}
}

func TestRoutePeerCloseRejectsClaimSubstitutionAndPreservesUnknownLegacy(t *testing.T) {
	r, source, _ := coordinatedRouteFixture(t, routeBoth(t))
	r = closingRouteSource(t, r, source)
	claim := signedClosingRouteClaim(t, r.a, source, r.f.key)
	before := routeRaw(t, r.b)
	for _, mutate := range []func(*RouteFlowReceipt){
		func(p *RouteFlowReceipt) { p.Reference.Generation++ },
		func(p *RouteFlowReceipt) { p.Reference.Lifetime.Token++ },
		func(p *RouteFlowReceipt) { p.Peer.Lifetime.Token++ },
		func(p *RouteFlowReceipt) { p.Boot[0]++ },
		func(p *RouteFlowReceipt) { p.PeerBoot[0]++ },
		func(p *RouteFlowReceipt) { p.Pin.Token = 0 },
		func(p *RouteFlowReceipt) { p.Tuple[0]++ },
		func(p *RouteFlowReceipt) { p.PeerPin.Token = 1 },
		func(p *RouteFlowReceipt) { p.JournalSynced = false },
	} {
		bad := ownRouteFlowReceipt(claim)
		mutate(&bad)
		bad.Signature = ed25519.Sign(r.f.key, RouteFlowReceiptBytes(bad))
		if _, _, err := r.b.BeginPeerFlowClose(r.f.a, bad, r.tuple); err == nil {
			t.Fatal("foreign or substituted source claim closed a destination pin")
		}
	}
	if !bytes.Equal(before, routeRaw(t, r.b)) {
		t.Fatal("rejected claim changed destination checkpoint")
	}
	legacy, a, _ := routeBorrow(t, routeBoth(t))
	legacy = closingRouteSource(t, legacy, a)
	legacyClaim := signedClosingRouteClaim(t, legacy.a, a, legacy.f.key)
	if _, _, err := legacy.b.BeginPeerFlowClose(legacy.f.a, legacyClaim, legacy.tuple); err == nil {
		t.Fatal("uncoordinated legacy destination was treated as never-admitted")
	}
}

func TestPermanentRoutePacketClosureSettlesLateUnadmittedClaimWithoutChangingReceipt(t *testing.T) {
	r := routeBoth(t)
	aProof, err := r.a.AppliedProof(r.f.c, r.f.n, r.f.a)
	if err != nil {
		t.Fatal(err)
	}
	bProof, err := r.b.AppliedProof(r.f.c, r.f.n, r.f.a)
	if err != nil {
		t.Fatal(err)
	}
	var source RouteFlow
	r.a, source, err = r.a.BorrowFlow(r.f.c, r.f.n, r.f.a, bProof, r.b.boot, r.tuple, routeClock(r.a, 150))
	if err != nil {
		t.Fatal(err)
	}
	r = closingRouteSource(t, r, source)
	claim := signedClosingRouteClaim(t, r.a, source, r.f.key)
	r = routeWithdraw(t, r)
	r.b, err = r.b.ClosePackets(modelRoutePacketsClosed(t, r.b, r.keyB))
	if err != nil {
		t.Fatal(err)
	}
	before := routeRaw(t, r.b)
	again, handle, err := r.b.BeginPeerFlowClose(r.f.a, claim, r.tuple)
	if err != nil || handle.Lease().Token != 0 || !bytes.Equal(before, routeRaw(t, again)) {
		t.Fatal("late claim changed a permanent packet closure", err)
	}
	proof := signedPeerRouteClose(t, again, r.f.a, claim, r.tuple, r.keyB)
	r.a, err = r.a.FinishSourceFlowClose(source, routeFlowProof(r.a, source, r.f.key), proof)
	if err != nil || r.a.FlowCount() != 0 {
		t.Fatal("permanent peer closure did not settle original source", err)
	}
	if _, _, err := again.AcceptPeerFlow(r.f.c, r.f.n, r.f.a, aProof, claim, r.tuple, routeClock(again, 154)); err == nil {
		t.Fatal("late admission escaped permanent instance closure")
	}
}
