// SPDX-License-Identifier: Apache-2.0

package services

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"math"
	"slices"
	"testing"
)

func TestPeerRouteFlowAdmissionResumesOriginalPinAndRejectsClosedClaim(t *testing.T) {
	r := routeBoth(t)
	pa, _ := r.a.AppliedProof(r.f.c, r.f.n, r.f.a)
	pb, _ := r.b.AppliedProof(r.f.c, r.f.n, r.f.a)
	var source RouteFlow
	var err error
	r.a, source, err = r.a.BorrowFlow(r.f.c, r.f.n, r.f.a, pb, r.b.boot, r.tuple, routeClock(r.a, 150))
	if err != nil {
		t.Fatal(err)
	}
	claim := signedRouteFlowReceipt(t, r.a, source, r.f.key)
	before := routeRaw(t, r.b)
	next, destination, err := r.b.AcceptPeerFlow(r.f.c, r.f.n, r.f.a, pa, claim, r.tuple, routeClock(r.b, 151))
	if err != nil || next.FlowCount() != 1 || r.b.FlowCount() != 0 || !bytes.Equal(before, routeRaw(t, r.b)) {
		t.Fatal("destination admission did not remain one immutable candidate", err)
	}
	raw := routeRaw(t, next)
	restored, err := DecodeRouteRuntime(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, original, err := restored.AcceptPeerFlow(r.f.c, r.f.n, r.f.a, pa, claim, r.tuple, routeClock(restored, 152))
	if err != nil || original != destination || !bytes.Equal(raw, routeRaw(t, again)) {
		t.Fatal("unknown delivery replaced the destination pin", err)
	}
	otherTuple := r.tuple
	otherTuple.SourcePort++
	otherClaim := ownRouteFlowReceipt(claim)
	otherClaim.Tuple = tupleHash(otherTuple)
	otherClaim.Signature = ed25519.Sign(r.f.key, RouteFlowReceiptBytes(otherClaim))
	if _, _, err := again.AcceptPeerFlow(r.f.c, r.f.n, r.f.a, pa, otherClaim, otherTuple, routeClock(again, 153)); err == nil {
		t.Fatal("one source pin authorized two different tuples")
	}
	closed, err := again.ReleaseFlow(destination, routeFlowProof(again, destination, r.keyB))
	if err != nil {
		t.Fatal(err)
	}
	closed, err = DecodeRouteRuntime(routeRaw(t, closed))
	if err != nil || !closedRoutePin(closed.closedPeers, claim.Pin.Token) {
		t.Fatal("same DB lost the closed source pin", err)
	}
	if _, _, err := closed.AcceptPeerFlow(r.f.c, r.f.n, r.f.a, pa, claim, r.tuple, routeClock(closed, 154)); err == nil {
		t.Fatal("delayed original claim reentered after destination close")
	}
	// Explicit source closure then a fresh pin is a distinct flow lifetime.
	r.a, err = r.a.ReleaseFlow(source, routeFlowProof(r.a, source, r.f.key))
	if err != nil {
		t.Fatal(err)
	}
	r.a, source, err = r.a.BorrowFlow(r.f.c, r.f.n, r.f.a, pb, r.b.boot, r.tuple, routeClock(r.a, 155))
	if err != nil {
		t.Fatal(err)
	}
	freshClaim := signedRouteFlowReceipt(t, r.a, source, r.f.key)
	newer, fresh, err := closed.AcceptPeerFlow(r.f.c, r.f.n, r.f.a, pa, freshClaim, r.tuple, routeClock(closed, 156))
	if err != nil || fresh == destination || !closedRoutePin(newer.closedPeers, claim.Pin.Token) {
		t.Fatal("new lifetime lost the original closed pin or reused its receipt", err)
	}
	routeRaw(t, newer)
}

func TestRouteClosedPeerPinRangesRetainHolesAndCanonicalCheckpoint(t *testing.T) {
	var ranges []routePinRange
	for _, token := range []uint64{5, 1, 3, 5, 4, 2, math.MaxUint64, math.MaxUint64 - 1} {
		ranges = closeRoutePin(ranges, token)
		if !validRoutePinRanges(ranges) {
			t.Fatal("retirement did not produce canonical disjoint ranges", ranges)
		}
	}
	want := []routePinRange{{1, 5}, {math.MaxUint64 - 1, math.MaxUint64}}
	if !slices.Equal(ranges, want) || closedRoutePin(ranges, 0) || closedRoutePin(ranges, 6) || !closedRoutePin(ranges, math.MaxUint64) {
		t.Fatal("range compression forgot a hole or overflowed", ranges)
	}
	for _, invalid := range [][]routePinRange{{{0, 1}}, {{3, 2}}, {{1, 2}, {2, 3}}, {{1, 2}, {3, 4}}, {{4, 5}, {1, 2}}} {
		if validRoutePinRanges(invalid) {
			t.Fatal("accepted noncanonical closed tokens", invalid)
		}
	}
	r := routeBoth(t)
	r.a.closedPeers = ranges
	raw := routeRaw(t, r.a)
	restored, err := DecodeRouteRuntime(raw)
	if err != nil || !slices.Equal(restored.closedPeers, want) {
		t.Fatal("same checkpoint lost old peer token retirement", err)
	}
	snapshot, err := restored.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	snapshot.ClosedPeers = []routePinRange{{1, 2}, {3, 4}}
	bad, _ := json.Marshal(snapshot)
	if _, err := DecodeRouteRuntime(bad); err == nil {
		t.Fatal("checkpoint accepted adjacent unmerged retirement ranges")
	}
}
