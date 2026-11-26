// SPDX-License-Identifier: Apache-2.0

package network

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/mydcp"
)

// Only the TUN bytes and durable-admission result are modeled. The actual
// PacketPlane goroutines, policy, callback, queue and stop/join run unchanged.
type routeMemoryIO struct {
	read, written chan []byte
	stop          chan struct{}
	once          sync.Once
}

func newRouteMemoryIO() *routeMemoryIO {
	return &routeMemoryIO{read: make(chan []byte, 4), written: make(chan []byte, 4), stop: make(chan struct{})}
}
func (m *routeMemoryIO) Read(b []byte) (int, error) {
	select {
	case <-m.stop:
		return 0, context.Canceled
	case packet := <-m.read:
		return copy(b, packet), nil
	}
}
func (m *routeMemoryIO) Write(b []byte) (int, error) {
	select {
	case <-m.stop:
		return 0, context.Canceled
	case m.written <- bytes.Clone(b):
		return len(b), nil
	}
}
func (m *routeMemoryIO) SetReadDeadline(at time.Time) error {
	if !at.IsZero() && !at.After(time.Now()) {
		m.once.Do(func() { close(m.stop) })
	}
	return nil
}
func (m *routeMemoryIO) SetWriteDeadline(at time.Time) error { return m.SetReadDeadline(at) }

type routeBlockingWriteIO struct {
	*routeMemoryIO
	entered, release chan struct{}
	first            atomic.Bool
}

func (m *routeBlockingWriteIO) Write(b []byte) (int, error) {
	if m.first.CompareAndSwap(false, true) {
		close(m.entered)
		select {
		case <-m.release:
		case <-m.stop:
			return 0, context.Canceled
		}
	}
	return m.routeMemoryIO.Write(b)
}

type routeAtomicGate struct {
	allow   atomic.Bool
	policy  PacketPolicy
	network [16]byte
	token   [16]byte
}

func (g *routeAtomicGate) Allows([32]byte, []byte) bool { return g.allow.Load() }
func (g *routeAtomicGate) PacketBinding(sender [32]byte, packet []byte) (PacketBinding, bool) {
	if !g.allow.Load() {
		return PacketBinding{}, false
	}
	target, err := g.policy.LocalRoute(sender, g.network, 1280, packet)
	return PacketBinding{Token: g.token, Endpoint: target}, err == nil
}

type fixedRouteBindingGate struct{ binding PacketBinding }

func (g fixedRouteBindingGate) Allows([32]byte, []byte) bool { return true }
func (g fixedRouteBindingGate) PacketBinding([32]byte, []byte) (PacketBinding, bool) {
	return g.binding, true
}

func TestRouteForwardCannotExchangeCapturedTokenForNewSameTupleLifetime(t *testing.T) {
	local, id := [32]byte{101}, [16]byte{102}
	target := Endpoint{Owner: local, Network: id, ID: [16]byte{104}, Address: netip.MustParseAddr("10.2.0.10")}
	policy, err := NewPacketPolicy([]Endpoint{{Owner: local, Network: id, ID: [16]byte{103}, Address: netip.MustParseAddr("10.1.0.10")}, target})
	if err != nil {
		t.Fatal(err)
	}
	p := &PacketPlane{ctx: t.Context(), local: local, network: id, spec: routeTunnelSpec(true)}
	oldToken, newToken := [16]byte{105}, [16]byte{106}
	var sent [][16]byte
	plan := PacketPlan{Policy: policy, Gate: fixedRouteBindingGate{PacketBinding{oldToken, target}}, Relay: func(_ Endpoint, token [16]byte, _ []byte) error { sent = append(sent, token); return nil }}
	p.SetPlan(plan)
	packet := transportPacket(4, 6)
	original, allowed := p.outboundIdentity(p.plan.Load(), target, packet)
	if !allowed || original != oldToken {
		t.Fatal("initial admission did not capture the original flow")
	}
	plan.Gate = fixedRouteBindingGate{PacketBinding{newToken, target}}
	p.SetPlan(plan)
	p.forwardPacket(target, true, original, packet)
	if len(sent) != 0 {
		t.Fatal("old admitted packet was relabeled with a new pin")
	}
	fresh, allowed := p.outboundIdentity(p.plan.Load(), target, packet)
	if !allowed {
		t.Fatal("new lifetime did not admit a fresh packet")
	}
	p.forwardPacket(target, true, fresh, packet)
	if len(sent) != 1 || sent[0] != newToken {
		t.Fatal("fresh admission lost its current original token")
	}
}

func TestRoutePacketBarrierWaitsForOriginalWriteAndKeepsOtherFlowServing(t *testing.T) {
	local, id := [32]byte{81}, [16]byte{82}
	destination := Endpoint{Owner: local, Network: id, ID: [16]byte{84}, Address: netip.MustParseAddr("10.2.0.10")}
	policy, err := NewPacketPolicy([]Endpoint{{Owner: local, Network: id, ID: [16]byte{83}, Address: netip.MustParseAddr("10.1.0.10")}, destination})
	if err != nil {
		t.Fatal(err)
	}
	device := &routeBlockingWriteIO{routeMemoryIO: newRouteMemoryIO(), entered: make(chan struct{}), release: make(chan struct{})}
	oldToken, otherToken := [16]byte{85}, [16]byte{86}
	p, err := NewPacketPlane(t.Context(), local, id, routeTunnelSpec(false), device, PacketLimits{QueuePackets: 4, QueueBytes: 4096}, PacketPlan{Policy: policy, Gate: fixedRouteBindingGate{PacketBinding{oldToken, destination}}})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Stop()
	packet := transportPacket(4, 6)
	if err := p.ReceiveLocal(oldToken, packet); err != nil {
		t.Fatal(err)
	}
	select {
	case <-device.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("original write never started")
	}
	// Model the already-synced Closing view. The unrelated flow retains its
	// own token; it does not acquire the original flow's endpoint authority.
	p.SetPlan(PacketPlan{Policy: policy, Gate: fixedRouteBindingGate{PacketBinding{otherToken, destination}}})
	short, cancel := context.WithTimeout(t.Context(), 25*time.Millisecond)
	err = p.PacketBarrier(short)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("barrier claimed closure while original IO was still running", err)
	}
	if err := p.ReceiveLocal(oldToken, packet); !errors.Is(err, mydcp.ErrAdmission) {
		t.Fatal("closing gate accepted more original packets", err)
	}
	close(device.release)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := p.PacketBarrier(ctx); err != nil {
		t.Fatal("joined original IO did not settle its barrier", err)
	}
	select {
	case <-device.written:
	case <-ctx.Done():
		t.Fatal("original in-flight write did not finish")
	}
	other := bytes.Clone(packet)
	other[21]++
	if err := p.ReceiveLocal(otherToken, other); err != nil {
		t.Fatal("barrier stopped the unrelated flow", err)
	}
	select {
	case got := <-device.written:
		if !bytes.Equal(got, other) {
			t.Fatal("unrelated flow bytes changed")
		}
	case <-ctx.Done():
		t.Fatal("plane did not keep serving another flow")
	}
	if err := (&PacketPlane{}).PacketBarrier(ctx); !errors.Is(err, ErrPolicy) {
		t.Fatal("ordinary plane accepted route closure barrier", err)
	}
}

func TestRoutePacketPlaneRejectsOldFlowTokenOnReceiveAndQueuedRecheck(t *testing.T) {
	local, id := [32]byte{71}, [16]byte{72}
	destination := Endpoint{Owner: local, Network: id, ID: [16]byte{74}, Address: netip.MustParseAddr("10.2.0.10")}
	policy, err := NewPacketPolicy([]Endpoint{{Owner: local, Network: id, ID: [16]byte{73}, Address: netip.MustParseAddr("10.1.0.10")}, destination})
	if err != nil {
		t.Fatal(err)
	}
	// No modeled packet algorithm: this calls the actual receive/write admission
	// function with a retained decoded frame across a committed plan replacement.
	p := &PacketPlane{local: local, network: id, spec: routeTunnelSpec(false)}
	oldToken, freshToken := [16]byte{75}, [16]byte{76}
	p.SetPlan(PacketPlan{Policy: policy, Gate: fixedRouteBindingGate{PacketBinding{oldToken, destination}}})
	packet := transportPacket(4, 6)
	frame := mydcp.Frame{Purpose: mydcp.Packet, Kind: 2, Fields: []mydcp.Field{{Tag: 1, Required: true, Value: local[:]}, {Tag: 2, Required: true, Value: id[:]}, {Tag: 3, Required: true, Value: oldToken[:]}, {Tag: 4, Required: true, Value: packet}}}
	wire, err := mydcp.Encode(frame)
	if err != nil {
		t.Fatal(err)
	}
	decoder, _ := mydcp.NewDecoder(mydcp.MaxBody)
	queued, _, err := decoder.Feed(wire)
	if err != nil || queued == nil || !p.admittedLocal(*queued) {
		t.Fatal("original flow was not admitted", err)
	}
	p.SetPlan(PacketPlan{Policy: policy, Gate: fixedRouteBindingGate{PacketBinding{freshToken, destination}}})
	if p.admittedLocal(*queued) {
		t.Fatal("queued old datagram entered a new lifetime with the same endpoints/tuple")
	}
	frame.Fields[2].Value = freshToken[:]
	if !p.admittedLocal(frame) {
		t.Fatal("fresh bilateral token did not enter its original endpoint")
	}
	// A matching token cannot substitute the normal endpoint/Book authority.
	foreign := destination
	foreign.ID[0]++
	p.SetPlan(PacketPlan{Policy: policy, Gate: fixedRouteBindingGate{PacketBinding{freshToken, foreign}}})
	if p.admittedLocal(frame) {
		t.Fatal("flow gate bypassed the policy's endpoint incarnation")
	}
	p.SetPlan(PacketPlan{Policy: policy, Gate: fixedRouteBindingGate{PacketBinding{freshToken, destination}}})
	frame.Kind = 1
	if _, ok := p.packetEndpoint(p.plan.Load(), local, frame); ok {
		t.Fatal("ordinary packet kind bypassed route binding")
	}
	ordinary := &PacketPlane{local: local, network: id}
	frame.Kind = 2
	if _, ok := ordinary.packetEndpoint(&PacketPlan{Policy: policy}, local, frame); ok {
		t.Fatal("route packet kind entered an ordinary TUN")
	}
	frame.Kind = 1
	frame.Fields[2].Value = destination.ID[:]
	if endpoint, ok := ordinary.packetEndpoint(&PacketPlan{Policy: policy}, local, frame); !ok || endpoint != destination.ID {
		t.Fatal("ordinary endpoint encoding changed")
	}
}

func TestRoutePacketPlaneLocalRelayWaitsForBilateralAdmissionAndKeepsReceiveReadonly(t *testing.T) {
	local, networkID := [32]byte{51}, [16]byte{52}
	endpoints := []Endpoint{{Owner: local, Network: networkID, ID: [16]byte{53}, Address: netip.MustParseAddr("10.1.0.10")}, {Owner: local, Network: networkID, ID: [16]byte{54}, Address: netip.MustParseAddr("10.2.0.10")}}
	policy, err := NewPacketPolicy(endpoints)
	if err != nil {
		t.Fatal(err)
	}
	packet := transportPacket(4, 6)
	if _, err := policy.Outbound(local, networkID, 1280, packet); err == nil || policy.Inbound(local, local, networkID, endpoints[1].ID, 1280, packet) == nil {
		t.Fatal("ordinary packet policy implicitly enabled same-node relay")
	}
	leftIO, rightIO := newRouteMemoryIO(), newRouteMemoryIO()
	leftGate, rightGate := &routeAtomicGate{policy: policy, network: networkID, token: [16]byte{55}}, &routeAtomicGate{policy: policy, network: networkID, token: [16]byte{55}}
	var incomingAdmits atomic.Int32
	right, err := NewPacketPlane(t.Context(), local, networkID, routeTunnelSpec(false), rightIO, PacketLimits{QueuePackets: 2, QueueBytes: 4096}, PacketPlan{Policy: policy, Gate: rightGate, Admit: func(context.Context, []byte) error {
		incomingAdmits.Add(1)
		return errors.New("incoming packets cannot acquire pins")
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer right.Stop()
	entered, approve := make(chan struct{}), make(chan struct{})
	var sourceAdmits atomic.Int32
	left, err := NewPacketPlane(t.Context(), local, networkID, routeTunnelSpec(true), leftIO, PacketLimits{QueuePackets: 2, QueueBytes: 4096}, PacketPlan{Policy: policy, Gate: leftGate, Admit: func(ctx context.Context, input []byte) error {
		if !bytes.Equal(input, packet) {
			t.Error("unapproved port/direction reached new-flow admission")
		}
		if sourceAdmits.Add(1) == 1 {
			close(entered)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-approve:
			leftGate.allow.Store(true)
			rightGate.allow.Store(true)
			return nil
		}
	}, Relay: func(target Endpoint, token [16]byte, input []byte) error { return right.ReceiveLocal(token, input) }})
	if err != nil {
		t.Fatal(err)
	}
	defer left.Stop()
	bad := bytes.Clone(packet)
	bad[23]++
	leftIO.read <- bad
	leftIO.read <- packet
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("source reader did not reach its actual admission callback")
	}
	select {
	case <-rightIO.written:
		t.Fatal("first packet escaped before both durable pins were approved")
	default:
	}
	close(approve)
	for i := 0; i < 2; i++ {
		if i == 1 {
			leftIO.read <- packet
		}
		select {
		case got := <-rightIO.written:
			if !bytes.Equal(got, packet) {
				t.Fatal("relay changed the approved original packet")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("approved packet did not reach destination TUN queue")
		}
	}
	if sourceAdmits.Load() != 1 || incomingAdmits.Load() != 0 {
		t.Fatal("retransmission or receive created another admission")
	}
	rightGate.allow.Store(false)
	if err := right.ReceiveLocal(rightGate.token, packet); !errors.Is(err, mydcp.ErrAdmission) || incomingAdmits.Load() != 0 {
		t.Fatal("revoked receive waited for new pin/control IO", err)
	}
	if err := right.Receive(nil, mydcp.Frame{}); !errors.Is(err, mydcp.ErrAdmission) {
		t.Fatal("remote receive acquired local relay provenance", err)
	}
}

func TestRoutePacketPlaneStopCancelsAndJoinsPendingAdmission(t *testing.T) {
	local, id := [32]byte{61}, [16]byte{62}
	policy, err := NewPacketPolicy([]Endpoint{{Owner: local, Network: id, ID: [16]byte{63}, Address: netip.MustParseAddr("10.1.0.10")}, {Owner: local, Network: id, ID: [16]byte{64}, Address: netip.MustParseAddr("10.2.0.10")}})
	if err != nil {
		t.Fatal(err)
	}
	device, entered, exited := newRouteMemoryIO(), make(chan struct{}), make(chan struct{})
	p, err := NewPacketPlane(t.Context(), local, id, routeTunnelSpec(true), device, PacketLimits{QueuePackets: 1, QueueBytes: 4096}, PacketPlan{Policy: policy, Gate: &routeAtomicGate{}, Admit: func(ctx context.Context, _ []byte) error {
		close(entered)
		<-ctx.Done()
		close(exited)
		return ctx.Err()
	}, Relay: func(Endpoint, [16]byte, []byte) error { t.Error("unconfirmed packet was relayed"); return nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Stop()
	if !p.PathReady() {
		t.Fatal("running same-node IO plan was not observable")
	}
	device.read <- transportPacket(4, 6)
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("admission did not start")
	}
	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}
	if p.PathReady() {
		t.Fatal("stopped packet IO was published as ready")
	}
	select {
	case <-exited:
	default:
		t.Fatal("Stop returned before the pending original admission joined")
	}
}

// The gate models two original flows; the PacketPlane reader, ownership,
// forwarding and stop paths are the real product implementation.
type splitRouteGate struct {
	policy  PacketPolicy
	network [16]byte
	pending atomic.Bool
}

func (g *splitRouteGate) Allows(sender [32]byte, packet []byte) bool {
	_, ok := g.PacketBinding(sender, packet)
	return ok
}
func (g *splitRouteGate) PacketBinding(sender [32]byte, packet []byte) (PacketBinding, bool) {
	tuple, err := PacketTransport(packet)
	if err != nil {
		return PacketBinding{}, false
	}
	if tuple.SourcePort != 49001 && !(tuple.SourcePort == 3306 && tuple.DestinationPort == 49001) && (tuple.SourcePort != 49000 || !g.pending.Load()) {
		return PacketBinding{}, false
	}
	target, err := g.policy.LocalRoute(sender, g.network, 1280, packet)
	return PacketBinding{Token: [16]byte{151}, Endpoint: target}, err == nil
}

func TestRouteBlockedAdmissionKeepsExistingOutboundFlowServing(t *testing.T) {
	local, id := [32]byte{141}, [16]byte{142}
	policy, err := NewPacketPolicy([]Endpoint{{Owner: local, Network: id, ID: [16]byte{143}, Address: netip.MustParseAddr("10.1.0.10")}, {Owner: local, Network: id, ID: [16]byte{144}, Address: netip.MustParseAddr("10.2.0.10")}})
	if err != nil {
		t.Fatal(err)
	}
	device := newRouteMemoryIO()
	gate := &splitRouteGate{policy: policy, network: id}
	pending := transportPacket(4, 6)
	existing := bytes.Clone(pending)
	existing[21]++
	entered, approve := make(chan struct{}), make(chan struct{})
	sent := make(chan []byte, 4)
	var calls atomic.Int32
	p, err := NewPacketPlane(t.Context(), local, id, routeTunnelSpec(true), device, PacketLimits{QueuePackets: 2, QueueBytes: 4096}, PacketPlan{Policy: policy, Gate: gate, Admit: func(ctx context.Context, packet []byte) error {
		if calls.Add(1) == 1 {
			close(entered)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-approve:
		}
		if !bytes.Equal(packet, pending) {
			t.Error("reader reused the pending candidate buffer")
		}
		gate.pending.Store(true)
		return nil
	}, Relay: func(_ Endpoint, _ [16]byte, packet []byte) error { sent <- bytes.Clone(packet); return nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Stop()
	device.read <- pending
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("original admission did not enter")
	}
	// This is a fixed logical barrier: admission remains blocked until after
	// the other original flow has been delivered, rather than a latency SLA.
	otherPending := bytes.Clone(pending)
	otherPending[21] += 2
	device.read <- otherPending // no second pending slot or native callback
	device.read <- existing
	select {
	case got := <-sent:
		if !bytes.Equal(got, existing) {
			t.Fatal("unapproved pending packet escaped")
		}
	case <-time.After(time.Second):
		t.Fatal("blocked admission stalled an already permitted outbound flow")
	}
	if used := p.bytes.Load(); used != int64(len(pending)) {
		t.Fatal("pending candidate has no bounded byte ownership", used)
	}
	close(approve)
	select {
	case got := <-sent:
		if !bytes.Equal(got, pending) {
			t.Fatal("approved original candidate changed")
		}
	case <-time.After(time.Second):
		t.Fatal("approved pending candidate was not forwarded")
	}
	if calls.Load() != 1 {
		t.Fatal("existing traffic triggered another admission", calls.Load())
	}
	if err = p.Stop(); err != nil {
		t.Fatal(err)
	}
	if p.bytes.Load() != 0 {
		t.Fatal("pending bytes survived stop")
	}
}

func TestRouteAdmissionLateSuccessCannotBypassWithdrawnGate(t *testing.T) {
	local, id := [32]byte{161}, [16]byte{162}
	policy, err := NewPacketPolicy([]Endpoint{{Owner: local, Network: id, ID: [16]byte{163}, Address: netip.MustParseAddr("10.1.0.10")}, {Owner: local, Network: id, ID: [16]byte{164}, Address: netip.MustParseAddr("10.2.0.10")}})
	if err != nil {
		t.Fatal(err)
	}
	device := newRouteMemoryIO()
	oldGate := &routeAtomicGate{policy: policy, network: id, token: [16]byte{165}}
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	sent := make(chan struct{}, 1)
	plan := PacketPlan{Policy: policy, Gate: oldGate, Admit: func(ctx context.Context, _ []byte) error {
		close(entered)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-release:
		}
		oldGate.allow.Store(true)
		close(finished)
		return nil
	}, Relay: func(Endpoint, [16]byte, []byte) error { sent <- struct{}{}; return nil }}
	p, err := NewPacketPlane(t.Context(), local, id, routeTunnelSpec(true), device, PacketLimits{QueuePackets: 2, QueueBytes: 4096}, plan)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Stop()
	device.read <- transportPacket(4, 6)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("admission did not enter")
	}
	plan.Gate = &routeAtomicGate{policy: policy, network: id, token: [16]byte{166}}
	p.SetPlan(plan) // model the committed withdrawal while native IO is pending
	close(release)
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("original callback did not finish")
	}
	if err = p.Stop(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-sent:
		t.Fatal("old successful callback forwarded under a withdrawn gate")
	default:
	}
	if p.bytes.Load() != 0 {
		t.Fatal("withdrawn candidate bytes survived Stop")
	}
}

func TestRouteAdmissionUsesExistingByteBudgetAndStopReturnsCandidate(t *testing.T) {
	local, id := [32]byte{171}, [16]byte{172}
	policy, err := NewPacketPolicy([]Endpoint{{Owner: local, Network: id, ID: [16]byte{173}, Address: netip.MustParseAddr("10.1.0.10")}, {Owner: local, Network: id, ID: [16]byte{174}, Address: netip.MustParseAddr("10.2.0.10")}})
	if err != nil {
		t.Fatal(err)
	}
	device := newRouteMemoryIO()
	gate := &splitRouteGate{policy: policy, network: id}
	entered, exited := make(chan struct{}), make(chan struct{})
	packet := append(transportPacket(4, 6), make([]byte, 1160)...)
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	p, err := NewPacketPlane(t.Context(), local, id, routeTunnelSpec(true), device, PacketLimits{QueuePackets: 1, QueueBytes: 1280}, PacketPlan{Policy: policy, Gate: gate, Admit: func(ctx context.Context, _ []byte) error {
		close(entered)
		<-ctx.Done()
		close(exited)
		return ctx.Err()
	}, Relay: func(Endpoint, [16]byte, []byte) error { t.Error("unconfirmed budget candidate forwarded"); return nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Stop()
	device.read <- packet
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("candidate did not enter")
	}
	reply := transportPacket(4, 6)
	copy(reply[12:16], netip.MustParseAddr("10.2.0.10").AsSlice())
	copy(reply[16:20], netip.MustParseAddr("10.1.0.10").AsSlice())
	binary.BigEndian.PutUint16(reply[20:22], 3306)
	binary.BigEndian.PutUint16(reply[22:24], 49001)
	if err = p.ReceiveLocal([16]byte{151}, reply); !errors.Is(err, mydcp.ErrBudget) {
		t.Fatal("receive bypassed pending candidate byte ownership", err)
	}
	if p.bytes.Load() != 1200 {
		t.Fatal("budget rejection changed the original candidate", p.bytes.Load())
	}
	if err = p.Stop(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-exited:
	default:
		t.Fatal("Stop did not join admission")
	}
	if p.bytes.Load() != 0 || p.admitting.Load() {
		t.Fatal("Stop retained pending candidate ownership")
	}
}

func TestRouteOppositeRelaysStopWithoutReceiveLockCycle(t *testing.T) {
	local, id := [32]byte{181}, [16]byte{182}
	policy, err := NewPacketPolicy([]Endpoint{{Owner: local, Network: id, ID: [16]byte{183}, Address: netip.MustParseAddr("10.1.0.10")}, {Owner: local, Network: id, ID: [16]byte{184}, Address: netip.MustParseAddr("10.2.0.10")}})
	if err != nil {
		t.Fatal(err)
	}
	gate := &routeAtomicGate{policy: policy, network: id, token: [16]byte{185}}
	gate.allow.Store(true)
	devices := [2]*routeMemoryIO{newRouteMemoryIO(), newRouteMemoryIO()}
	var planes [2]*PacketPlane
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	for i := range planes {
		other := 1 - i
		planes[i], err = NewPacketPlane(t.Context(), local, id, routeTunnelSpec(true), devices[i], PacketLimits{QueuePackets: 2, QueueBytes: 4096}, PacketPlan{Policy: policy, Gate: gate, Relay: func(_ Endpoint, token [16]byte, packet []byte) error {
			entered <- struct{}{}
			<-release
			return planes[other].ReceiveLocal(token, packet)
		}})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range devices {
		d.read <- transportPacket(4, 6)
	}
	for range planes {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("opposite relay did not enter")
		}
	}
	stopped := make(chan error, 2)
	for _, p := range planes {
		go func() { stopped <- p.Stop() }()
	}
	for _, p := range planes {
		select {
		case <-p.ctx.Done():
		case <-time.After(time.Second):
			t.Fatal("Stop did not cancel plane")
		}
	}
	close(release)
	for range planes {
		select {
		case err := <-stopped:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("Stop held a receive lock while joining an opposite relay")
		}
	}
}
