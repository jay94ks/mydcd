// SPDX-License-Identifier: Apache-2.0

package services

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/network"
)

func TestRouteFlowCensusRequiresPositiveObservationAndRetainsOriginalPin(t *testing.T) {
	r, source, _ := coordinatedRouteFixture(t, routeBoth(t))
	before := routeRaw(t, r.a)
	if _, _, err := r.a.ObserveConntrack(nil); err == nil {
		t.Fatal("failed/absent census was accepted as empty")
	}
	unseen, changed, err := r.a.ObserveConntrack(map[network.TransportPacket]bool{})
	if err != nil || changed || !bytes.Equal(before, routeRaw(t, unseen)) {
		t.Fatal("unseen conntrack row implied closure", err)
	}
	if _, err := r.a.BeginFlowClose(source); err == nil {
		t.Fatal("unobserved source flow began expiry")
	}
	if bytes.Contains(before, []byte(`"Tracked"`)) || bytes.Contains(before, []byte(`"Closing"`)) {
		t.Fatal("legacy omission bytes changed")
	}
	tracked, changed, err := r.a.ObserveConntrack(map[network.TransportPacket]bool{r.tuple.Transport(): true})
	if err != nil || !changed {
		t.Fatal("positive census did not become durable core state", err)
	}
	tracked, err = DecodeRouteRuntime(routeRaw(t, tracked))
	if err != nil {
		t.Fatal(err)
	}
	closing, changed, err := tracked.ObserveConntrack(map[network.TransportPacket]bool{})
	if err != nil || !changed {
		t.Fatal("observed then absent flow did not begin closure", err)
	}
	seen, stopped, exists := closing.FlowLifetime(source)
	if !seen || !stopped || !exists || closing.FlowCount() != 1 || closing.Flows()[0] != source {
		t.Fatal("expiry returned or substituted the original pin")
	}
	again, changed, err := closing.ObserveConntrack(map[network.TransportPacket]bool{r.tuple.Transport(): true})
	if err != nil || changed || !bytes.Equal(routeRaw(t, closing), routeRaw(t, again)) {
		t.Fatal("reappearing kernel tuple reopened a closing lifetime", err)
	}
	if _, _, err := r.b.ObserveConntrack(map[network.TransportPacket]bool{}); err == nil {
		t.Fatal("destination absence initiated source expiry")
	}
	snapshot, err := closing.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Flows[0].Tracked = false
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeRouteRuntime(raw); err == nil {
		t.Fatal("checkpoint accepted Closing without original tracking")
	}
}

func TestClosingRouteFlowRejectsLateAdmissionAndKeepsOtherFlow(t *testing.T) {
	r, source, destination := coordinatedRouteFixture(t, routeBoth(t))
	originalTuple := r.tuple
	originalReceipt := signedRouteFlowReceipt(t, r.b, destination, r.keyB)
	r.tuple.SourcePort++
	r, other, _ := coordinatedRouteFixture(t, r)
	var err error
	r.a, err = r.a.TrackFlow(source)
	if err != nil {
		t.Fatal(err)
	}
	r.a, err = r.a.BeginFlowClose(source)
	if err != nil {
		t.Fatal(err)
	}
	r.a, err = DecodeRouteRuntime(routeRaw(t, r.a))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := r.a.PacketBinding(r.f.c, r.f.n, r.f.a, pub(r.f.key), routeBindingPacket(originalTuple), routeClock(r.a, 153)); ok {
		t.Fatal("closing flow still supplied a packet token")
	}
	if _, ok := r.a.PacketBinding(r.f.c, r.f.n, r.f.a, pub(r.f.key), routeBindingPacket(other.Tuple()), routeClock(r.a, 153)); !ok {
		t.Fatal("closing one flow stopped another coordinated flow")
	}
	if _, err := r.a.RecordPeerFlow(r.f.c, r.f.n, r.f.a, source, originalReceipt, routeClock(r.a, 153)); err == nil {
		t.Fatal("late receipt reopened a closing lifetime")
	}
	proof, err := r.b.AppliedProof(r.f.c, r.f.n, r.f.a)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.a.BorrowFlow(r.f.c, r.f.n, r.f.a, proof, r.b.boot, originalTuple, routeClock(r.a, 153)); err == nil {
		t.Fatal("closing tuple acquired a replacement pin")
	}
	if r.a.FlowCount() != 2 {
		t.Fatal("closing a flow returned its pin before real cleanup")
	}
}
