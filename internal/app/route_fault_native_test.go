// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// Construct an IPv4 UDP reply for an actual, durably admitted Book tuple.
// This supplies test bytes, never a different packet/flow authority algorithm.
func routeFaultReply(tuple services.RouteTuple) []byte {
	payload := []byte("retained-original-route-frame")
	packet := make([]byte, 28+len(payload))
	packet[0], packet[8], packet[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[12:16], tuple.Destination.Address.AsSlice())
	copy(packet[16:20], tuple.Source.Address.AsSlice())
	binary.BigEndian.PutUint16(packet[20:22], tuple.DestinationPort)
	binary.BigEndian.PutUint16(packet[22:24], tuple.SourcePort)
	binary.BigEndian.PutUint16(packet[24:26], uint16(8+len(payload)))
	copy(packet[28:], payload)
	var checksum uint32
	for i := 0; i < 20; i += 2 {
		checksum += uint32(binary.BigEndian.Uint16(packet[i : i+2]))
	}
	for checksum > 0xffff {
		checksum = (checksum & 0xffff) + (checksum >> 16)
	}
	binary.BigEndian.PutUint16(packet[10:12], ^uint16(checksum))
	return packet
}

func testManagedRouteFaults(t *testing.T, ctx context.Context, a *Runtime, root, manifest string, read func() cluster.View, ref, peer services.ReferenceConsumer, original services.RouteFlow, claim services.RouteFlowReceipt, tuple services.RouteTuple, probe, ready, stopB, startB func()) {
	t.Helper()
	wait := func(label string, check func() bool) {
		t.Helper()
		t.Log("route fault boundary", label)
		for !check() {
			select {
			case <-ctx.Done():
				t.Fatal(label, ctx.Err())
			case <-time.After(40 * time.Millisecond):
			}
		}
	}
	load := func() (routeOwnerRecord, services.RouteRuntime) {
		t.Helper()
		a.routeMu.Lock()
		defer a.routeMu.Unlock()
		record, found, err := a.loadRouteOwner(ref)
		if err != nil || !found {
			t.Fatal("original route fault owner", err)
		}
		core, err := services.DecodeRouteRuntime(record.Core)
		if err != nil {
			t.Fatal(err)
		}
		return record, core
	}
	packet := routeFaultReply(tuple)
	a.routeMu.Lock()
	gate := a.routeGate(ref.ID)
	a.routeMu.Unlock()
	oldBinding, ok := gate.PacketBinding(peer.Local.Owner, packet)
	if !ok {
		t.Fatal("actual original bilateral reply binding missing")
	}
	localNative, err := a.callRouteFlow(ctx, ref, routeFlowRequest{Schema: 1, Reference: ref.ID})
	if err != nil {
		t.Fatal(err)
	}
	// A positively joined peer process outage leaves the original source pin
	// intact. Expire only its exact owned kernel conntrack tuple, as the kernel
	// can do independently of the owner; let the PRODUCT census/collector close it.
	stopB()
	record, core := load()
	resource, err := originalRouteResource(ref, record)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.nativeRouteDriver().DrainRouteFlow(ctx, ref.RouteNativeKey(), resource, tuple.Transport()); err != nil {
		t.Fatal("owned conntrack expiry injection", err)
	}
	wait("original Closing pin retained while its peer is unavailable", func() bool {
		_, core := load()
		current, exists := core.OriginalFlow(tuple)
		if !exists || current != original {
			return false
		}
		_, closing, known := core.FlowLifetime(current)
		return known && closing
	})
	startB()
	ready()
	wait("same original source pin settles after actual peer recovery", func() bool { _, core := load(); _, exists := core.OriginalFlow(tuple); return !exists })
	reply, err := a.callRouteFlow(ctx, peer, routeFlowRequest{Schema: 1, Reference: peer.ID, Tuple: &tuple, Close: &claim, CloseQuery: true})
	if err != nil || reply.Closed == nil || !reply.Closed.Tombstoned {
		t.Fatal("actual peer omitted its original flow tombstone", err)
	}
	probe()
	record, core = load()
	fresh, exists := core.OriginalFlow(tuple)
	if !exists || fresh == original {
		t.Fatal("same tuple did not acquire a new original bilateral flow")
	}
	newBinding, ok := gate.PacketBinding(peer.Local.Owner, packet)
	if !ok || newBinding.Token == oldBinding.Token || newBinding.Endpoint != oldBinding.Endpoint {
		t.Fatal("same tuple reused the old packet incarnation")
	}
	beforePeer, err := a.callRouteFlow(ctx, peer, routeFlowRequest{Schema: 1, Reference: peer.ID, Tuple: &tuple})
	if err != nil || beforePeer.Flow == nil {
		t.Fatal("new exact peer pin missing", err)
	}
	// A delayed legitimate OLD admission claim cannot attach to a new flow
	// with the same tuple. The original authenticated SFCP endpoint decides.
	if _, err := a.callRouteFlow(ctx, peer, routeFlowRequest{Schema: 1, Reference: peer.ID, Tuple: &tuple, Receipt: &claim, Native: &localNative.Native}); err == nil {
		t.Fatal("late original flow claim entered a new same-tuple lifetime")
	}
	afterPeer, err := a.callRouteFlow(ctx, peer, routeFlowRequest{Schema: 1, Reference: peer.ID, Tuple: &tuple})
	if err != nil || afterPeer.Flow == nil || afterPeer.Flow.Pin != beforePeer.Flow.Pin || afterPeer.Flow.PeerPin != beforePeer.Flow.PeerPin {
		t.Fatal("late claim replaced or erased the current peer pin", err)
	}
	// Use the actual installed PacketPlane, authenticated original peer session,
	// current path/Book/native and product gate. Replaying a retained decoded
	// frame is deterministic; no transport absence is used to infer rejection.
	getPlane := func() (*tunnelInstance, *network.PacketPlane, *sfcp.Session) {
		t.Helper()
		a.tunnel.mu.Lock()
		instance := a.tunnel.routes[ref.ID]
		a.tunnel.mu.Unlock()
		if instance == nil {
			t.Fatal("actual route instance missing")
		}
		instance.mu.Lock()
		path := instance.paths[peer.Local.Owner]
		instance.mu.Unlock()
		plane := instance.serving.Load()
		if plane == nil || path.Session == nil {
			t.Fatal("actual serving route path missing")
		}
		return instance, plane, path.Session
	}
	_, plane, session := getPlane()
	work, err := a.controlPolicy.RouteWork(read().State, a.Identity.Public, control.RouteWorkRequest{Reference: ref.ID})
	if err != nil {
		t.Fatal(err)
	}
	networkID := network.NetworkID(ref.Local.Cluster, work.Tunnel.Network)
	frame := sfcp.Frame{Purpose: sfcp.Packet, Kind: 2, Fields: []sfcp.Field{{Tag: 1, Required: true, Value: peer.Local.Owner[:]}, {Tag: 2, Required: true, Value: networkID[:]}, {Tag: 3, Required: true, Value: oldBinding.Token[:]}, {Tag: 4, Required: true, Value: packet}}}
	if err := plane.Receive(session, frame); err == nil {
		t.Fatal("old bilateral token entered actual receive queue after tuple reuse")
	}
	frame.Fields[2].Value = newBinding.Token[:]
	// Freeze only the owner's existing effect lock. The actual immutable gate
	// must expire on wall time and reject WITHOUT waiting for that lock.
	func() {
		a.routeMu.Lock()
		defer a.routeMu.Unlock()
		view := gate.view.Load()
		if view == nil {
			t.Fatal("current route view missing before expiry")
		}
		timer := time.NewTimer(max(time.Millisecond, time.Until(view.until)+time.Millisecond))
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		done := make(chan error, 1)
		go func() { done <- plane.Receive(session, frame) }()
		select {
		case e := <-done:
			if e == nil {
				t.Fatal("expired actual gate admitted packet")
			}
		case <-ctx.Done():
			t.Fatal("packet admission waited for route owner lock", ctx.Err())
		}
	}()
	ready()
	probe()
	_, current := load()
	same, exists := current.OriginalFlow(tuple)
	if !exists || same != fresh {
		t.Fatal("gate expiry replaced the original retained flow")
	}
	// Both packet owners are positively stopped in one interval: the peer's
	// original process Stop/Wait and this exact PacketPlane.Stop/join. Holding
	// its existing instance lock prevents the normal reconciler racing the cut.
	instance, _, _ := getPlane()
	func() {
		instance.mu.Lock()
		defer instance.mu.Unlock()
		stopB()
		if err := instance.stopPlane(); err != nil {
			t.Fatal("original source packet Stop/Wait", err)
		}
		if instance.routeReading.Load() || instance.serving.Load() != nil {
			t.Fatal("source packet reader survived joined pause")
		}
		startB()
	}()
	ready()
	probe()
	_, current = load()
	same, exists = current.OriginalFlow(tuple)
	if !exists || same != fresh {
		t.Fatal("bilateral pause/resume replaced the current original flow")
	}
	var report map[string]any
	raw, err := os.ReadFile(manifest)
	if err != nil || json.Unmarshal(raw, &report) != nil {
		t.Fatal("original fault manifest", err)
	}
	report["route_faults"] = map[string]any{"source_reference": ref.ID, "peer_reference": peer.ID, "old_pin": original.Lease(), "new_pin": fresh.Lease(), "old_token": oldBinding.Token, "new_token": newBinding.Token, "same_tuple": tuple, "offline_closing_pin_retained": true, "actual_peer_tombstone": reply.Closed, "late_claim_rejected_without_replacing_pin": true, "actual_receive_old_token_rejected": true, "actual_new_token_socket_echo": true, "actual_gate_expired_while_owner_lock_held": true, "both_packet_owners_joined_and_resumed": true, "scope": "Actual authenticated session/path, Book, owner journal/native/receive queue. Constructed retained reply input; existing same writePacket queued-recheck core is reused, not a claim of scheduled kernel queue fault injection."}
	raw, err = json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(manifest, raw, 0644); err != nil {
		t.Fatal(err)
	}
	t.Log(fmt.Sprintf("actual original route fault boundaries complete; %s", root))
}
