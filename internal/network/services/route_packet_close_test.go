// SPDX-License-Identifier: Apache-2.0

package services

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"
)

func modelRoutePacketsClosed(t *testing.T, core RouteRuntime, key ed25519.PrivateKey) RoutePacketClose {
	t.Helper()
	proof, err := core.PacketCloseFacts()
	if err != nil || proof.JournalSynced || proof.ReadersStopped || proof.QueueEmpty || proof.AdmissionsStopped || proof.ConntrackEmpty {
		t.Fatal("core invented adapter closure evidence", err)
	}
	proof.JournalSynced, proof.ReadersStopped, proof.QueueEmpty = true, true, true
	proof.AdmissionsStopped, proof.ConntrackEmpty = true, true
	proof.Signature = ed25519.Sign(key, RoutePacketCloseBytes(proof))
	return proof
}

func TestRoutePacketClosureReturnsOriginalLocalPinsWithoutClosingPeerOrNative(t *testing.T) {
	r, _, _ := routeBorrow(t, routeBoth(t))
	if _, err := r.a.PacketCloseFacts(); err == nil {
		t.Fatal("active instance generated permanent closure facts")
	}
	if _, err := r.a.Pause().PacketCloseFacts(); err == nil {
		t.Fatal("temporary daemon pause became permanent packet retirement")
	}
	r = routeWithdraw(t, r)
	core, err := r.a.Sync(r.f.c, r.f.n, r.f.a)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := core.Plan(); err == nil {
		t.Fatal("native Remove passed original active A3 flow")
	}
	before := routeRaw(t, core)
	proof := modelRoutePacketsClosed(t, core, r.f.key)
	closed, err := core.ClosePackets(proof)
	if err != nil || closed.FlowCount() != 0 || !closed.Journal().Applied.Present || closed.Journal().Pending != nil || r.b.FlowCount() != 1 || !bytes.Equal(before, routeRaw(t, core)) {
		t.Fatal("local packet close changed native/peer/original state", err)
	}
	for _, consumer := range r.f.a.RouteReferences() {
		if consumer.Closed != nil {
			t.Fatal("local packet stop fabricated shared instance close")
		}
	}
	if _, err := closed.ReferenceFacts(r.f.a, [32]byte{}, routeClock(closed, 154)); err == nil {
		t.Fatal("packet close fabricated native Gone or whole instance retirement")
	}
	_, operation, err := closed.Plan()
	if err != nil || operation == nil {
		t.Fatal("actual local flow closure did not unblock original native retirement", err)
	}
	raw := routeRaw(t, closed)
	restored, err := DecodeRouteRuntime(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, err := restored.ClosePackets(proof)
	if err != nil || !bytes.Equal(raw, routeRaw(t, again)) {
		t.Fatal("same DB/ACK replay replaced original close evidence", err)
	}
	resumed, err := restored.ResumeBoot([32]byte{77})
	if err != nil {
		t.Fatal(err)
	}
	old, found := resumed.PacketClosure()
	if !found || old.Boot != proof.Boot || old.FlowDigest != proof.FlowDigest || old.Flows != 1 {
		t.Fatal("new boot rewrote original packet history")
	}
	routeRaw(t, resumed)
	proof.Signature[0] ^= 1
	if !bytes.Equal(raw, routeRaw(t, closed)) {
		t.Fatal("close evidence aliased caller memory")
	}
}

func TestRoutePacketClosureRejectsIncompleteForeignAndReplacedEvidence(t *testing.T) {
	r, _, _ := routeBorrow(t, routeBoth(t))
	r = routeWithdraw(t, r)
	core, err := r.a.Sync(r.f.c, r.f.n, r.f.a)
	if err != nil {
		t.Fatal(err)
	}
	proof := modelRoutePacketsClosed(t, core, r.f.key)
	for _, mutate := range []func(*RoutePacketClose){
		func(p *RoutePacketClose) { p.Reference.Lifetime.Token++ },
		func(p *RoutePacketClose) { p.Boot[0]++ },
		func(p *RoutePacketClose) { p.Spec += "changed" },
		func(p *RoutePacketClose) { p.Flows = 0 },
		func(p *RoutePacketClose) { p.FlowDigest[0]++ },
		func(p *RoutePacketClose) { p.JournalSynced = false },
		func(p *RoutePacketClose) { p.ReadersStopped = false },
		func(p *RoutePacketClose) { p.QueueEmpty = false },
		func(p *RoutePacketClose) { p.AdmissionsStopped = false },
		func(p *RoutePacketClose) { p.ConntrackEmpty = false },
	} {
		bad := ownRoutePacketClose(proof)
		mutate(&bad)
		bad.Signature = ed25519.Sign(r.f.key, RoutePacketCloseBytes(bad))
		if _, err := core.ClosePackets(bad); err == nil {
			t.Fatal("incomplete/foreign evidence returned an original flow pin")
		}
	}
	closed, err := core.ClosePackets(proof)
	if err != nil {
		t.Fatal(err)
	}
	changed := ownRoutePacketClose(proof)
	changed.FlowDigest[0]++
	changed.Signature = ed25519.Sign(r.f.key, RoutePacketCloseBytes(changed))
	if _, err := closed.ClosePackets(changed); err == nil {
		t.Fatal("new close replaced original permanent evidence")
	}
	snapshot, err := closed.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	// Even a correctly signed historical count cannot exceed the preserved
	// last-issued token. Do not bump the floor to manufacture acceptance.
	overflow := snapshot
	tooMany := ownRoutePacketClose(*snapshot.PacketClose)
	tooMany.Flows = snapshot.Pins.Next + 1
	tooMany.Signature = ed25519.Sign(r.f.key, RoutePacketCloseBytes(tooMany))
	overflow.PacketClose = &tooMany
	bad, _ := json.Marshal(overflow)
	if _, err := DecodeRouteRuntime(bad); err == nil {
		t.Fatal("checkpoint accepted signed flow count above original token floor")
	}
	snapshot.PacketClose.FlowDigest[0]++
	bad, _ = json.Marshal(snapshot)
	if _, err := DecodeRouteRuntime(bad); err == nil {
		t.Fatal("checkpoint accepted modified signed packet history")
	}
}
