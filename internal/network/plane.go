// SPDX-License-Identifier: Apache-2.0

package network

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/netip"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/schema"
)

type PacketPeer struct {
	// WireKey is the current authenticated key for this original resource owner.
	// Zero preserves the original unrotated owner/session contract.
	WireKey [32]byte
	Session *mydcp.Session
	Path    mydcp.PathPair
}
type PacketPlan struct {
	// WireKey changes transport authentication, never endpoint ownership.
	WireKey [32]byte
	// LocalOwners contains only original owners resolved to this current node
	// by the same committed view, for the existing local route relay.
	LocalOwners map[[32]byte]bool
	Policy      PacketPolicy
	Peers       map[[32]byte]PacketPeer
	Gate        PacketGate
	// Admit runs on the plane's one bounded local-admission worker. The TUN
	// reader and receive/write paths keep serving already admitted traffic.
	Admit func(context.Context, []byte) error
	Relay func(Endpoint, [16]byte, []byte) error
}

// PacketGate only reads an already published, durably coordinated flow view.
// It must not perform control/native IO or wait for an owner's effect lock:
// Receive runs inside the bounded MYDCP packet handler. New-flow coordination
// belongs to the surrounding route owner, before these bytes can be forwarded.
type PacketGate interface {
	Allows(sender [32]byte, packet []byte) bool
}

// Route kind2 carries Token in its existing 16-byte tag3. Endpoint is derived
// from the same original flow and current Book, then checked against Policy.
type PacketBinding struct {
	Token    [16]byte
	Endpoint Endpoint
}
type PacketBindingGate interface {
	PacketBinding(sender [32]byte, packet []byte) (PacketBinding, bool)
}
type PacketLimits struct{ QueuePackets, QueueBytes int }

// PacketPlane borrows one TUN FD. Stop joins IO and the local admission worker;
// only the surrounding journal owner may return its pin or close the FD.
type PacketPlane struct {
	local     [32]byte
	network   [16]byte
	spec      TunnelSpec
	io        PacketIO
	plan      atomic.Pointer[PacketPlan]
	routes    atomic.Pointer[[]netip.Prefix]
	ctx       context.Context
	cancel    context.CancelFunc
	stop      sync.Once
	wg        sync.WaitGroup
	queue     chan queuedPacket
	admission chan routeAdmissionCandidate
	admitting atomic.Bool
	limit     int64
	bytes     atomic.Int64
	mu        sync.Mutex
	receiving sync.RWMutex
	flowIO    sync.RWMutex
	err       error
}

// Plans are copied on publication. A committed source change atomically
// replaces endpoint authority; queued incoming bytes are validated again.
func (p *PacketPlane) SetPlan(plan PacketPlan) {
	copy := PacketPlan{WireKey: plan.WireKey, LocalOwners: make(map[[32]byte]bool, len(plan.LocalOwners)), Policy: plan.Policy, Peers: make(map[[32]byte]PacketPeer, len(plan.Peers)), Gate: plan.Gate, Admit: plan.Admit, Relay: plan.Relay}
	for key, peer := range plan.Peers {
		copy.Peers[key] = peer
	}
	for key, local := range plan.LocalOwners {
		copy.LocalOwners[key] = local
	}
	p.plan.Store(&copy)
	if _, bound := plan.Gate.(PacketBindingGate); p.spec.RoutePolicy != nil && (plan.Gate == nil || !bound) {
		p.fail(ErrPolicy)
	}
}

// Retargetable: a plane without a route policy that is still serving.
func (p *PacketPlane) Retargetable() bool { return p.spec.RoutePolicy == nil && p.Err() == nil }

// Retarget follows a member joining or leaving a TUN network without stopping
// the plane: the new route set and peer plan replace the old ones atomically
// while the same TUN FD keeps serving. Anything else in the spec, or a route
// policy, still needs a new plane.
func (p *PacketPlane) Retarget(spec TunnelSpec, plan PacketPlan) error {
	if p.spec.RoutePolicy != nil || spec.RoutePolicy != nil || p.Err() != nil {
		return ErrPolicy
	}
	a, b := p.spec.Clone(), spec.Clone()
	a.Routes, b.Routes = nil, nil
	a.Lifecycle, b.Lifecycle = schema.Lifecycle{}, schema.Lifecycle{}
	if !reflect.DeepEqual(a, b) {
		return ErrPolicy
	}
	routes := slices.Clone(spec.Routes)
	p.SetPlan(plan)
	p.routes.Store(&routes)
	return nil
}

func NewPacketPlane(ctx context.Context, local [32]byte, network [16]byte, spec TunnelSpec, io PacketIO, limits PacketLimits, plan PacketPlan) (*PacketPlane, error) {
	if ctx.Err() != nil || local == [32]byte{} || network == [16]byte{} || io == nil || spec.MTU < 1280 || spec.MTU > 65535 || limits.QueuePackets < 1 || limits.QueuePackets > 65536 || limits.QueueBytes < spec.MTU || limits.QueueBytes > 64<<20 {
		return nil, ErrPolicy
	}
	if spec.RoutePolicy != nil && (!spec.RoutePolicy.valid(spec) || plan.Gate == nil) {
		return nil, ErrPolicy
	}
	if _, bound := plan.Gate.(PacketBindingGate); spec.RoutePolicy != nil && !bound {
		return nil, ErrPolicy
	}
	if err := io.SetReadDeadline(time.Time{}); err != nil {
		return nil, err
	}
	if err := io.SetWriteDeadline(time.Time{}); err != nil {
		return nil, err
	}
	c, cancel := context.WithCancel(ctx)
	spec = spec.Clone()
	p := &PacketPlane{local: local, network: network, spec: spec, io: io, ctx: c, cancel: cancel, queue: make(chan queuedPacket, limits.QueuePackets), limit: int64(limits.QueueBytes)}
	if spec.RoutePolicy != nil {
		p.admission = make(chan routeAdmissionCandidate, 1)
	}
	routes := slices.Clone(spec.Routes)
	p.routes.Store(&routes)
	p.SetPlan(plan)
	p.wg.Add(3)
	go func() {
		defer p.wg.Done()
		<-c.Done()
		_ = io.SetReadDeadline(time.Now())
		_ = io.SetWriteDeadline(time.Now())
	}()
	go func() { defer p.wg.Done(); p.read() }()
	go func() { defer p.wg.Done(); p.write() }()
	if spec.RoutePolicy != nil {
		p.wg.Add(1)
		go func() { defer p.wg.Done(); p.admit() }()
	}
	return p, nil
}
func (p *PacketPlane) fail(err error) {
	if p.ctx.Err() != nil {
		return
	}
	p.mu.Lock()
	p.err = errors.Join(p.err, err)
	p.mu.Unlock()
	p.cancel()
}
func (p *PacketPlane) Err() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

// PathReady observes the actual running IO plan, never flow admission, native
// authorization, quorum, service health or successful packet transmission.
func (p *PacketPlane) PathReady() bool {
	if p == nil || p.ctx == nil || p.ctx.Err() != nil {
		return false
	}
	plan := p.plan.Load()
	if plan == nil {
		return false
	}
	if len(plan.Peers) == 0 {
		return p.spec.RoutePolicy != nil && plan.Relay != nil
	}
	for _, peer := range plan.Peers {
		if peer.Session == nil || peer.Path.MTU() < p.spec.MTU || !peer.Session.PathCurrent(peer.Path) {
			return false
		}
	}
	return true
}
func (p *PacketPlane) Stop() error {
	p.stop.Do(func() {
		p.cancel()
		// A local relay can enter another plane's receive path. Do not hold
		// the receive lock while joining workers; two stopping peers could
		// otherwise wait on one another. Cancellation rejects new receives.
		p.wg.Wait()
		p.receiving.Lock()
		defer p.receiving.Unlock()
		for {
			select {
			case b := <-p.queue:
				p.bytes.Add(-b.size)
			case candidate := <-p.admission:
				p.releaseAdmission(candidate)
			default:
				return
			}
		}
	})
	return p.Err()
}
func (p *PacketPlane) routed(address []byte) bool {
	_, dst, err := PacketAddresses(address)
	if err != nil {
		return false
	}
	for _, route := range *p.routes.Load() {
		if route.Contains(dst) {
			return true
		}
	}
	return false
}

func (p *PacketPlane) permitted(plan *PacketPlan, sender [32]byte, localPacket bool, packet []byte) bool {
	if p.spec.RoutePolicy != nil && (!p.spec.RoutePolicy.allows(localPacket, packet) || plan.Gate == nil) {
		return false
	}
	return plan.Gate == nil || plan.Gate.Allows(sender, packet)
}

// Accepts is a read-only dispatch predicate. Receive and final native write
// recheck the same current plan, gate and authenticated Session afterwards.
func (p *PacketPlane) Accepts(s *mydcp.Session, f mydcp.Frame) bool {
	return p != nil && p.ctx != nil && p.ctx.Err() == nil && p.admitted(s, f)
}

func (p *PacketPlane) outboundTarget(plan *PacketPlan, packet []byte) (Endpoint, bool, error) {
	target, err := plan.Policy.Outbound(p.local, p.network, p.spec.MTU, packet)
	local := false
	if p.spec.RoutePolicy != nil && plan.Relay != nil {
		if err != nil {
			target, err = plan.Policy.LocalRoute(p.local, p.network, p.spec.MTU, packet)
			local = err == nil
		} else {
			local = plan.LocalOwners[target.Owner]
		}
	}
	return target, local, err
}

func (p *PacketPlane) read() {
	b := make([]byte, 65536)
	for p.ctx.Err() == nil {
		n, err := p.io.Read(b)
		if err != nil {
			p.fail(err)
			return
		}
		if n == 0 {
			p.fail(io.ErrNoProgress)
			return
		}
		plan := p.plan.Load()
		target, local, err := p.outboundTarget(plan, b[:n])
		if err != nil || !p.routed(b[:n]) {
			continue
		}
		peer, known := plan.Peers[target.Owner]
		if !local && (!known || peer.Session == nil || peer.Path.MTU() < p.spec.MTU || !peer.Session.PathCurrent(peer.Path)) {
			continue
		}
		identity, allowed := p.outboundIdentity(plan, target, b[:n])
		if !allowed {
			p.offerAdmission(plan, target, local, b[:n])
			continue
		}
		p.forwardPacket(target, local, identity, b[:n])
	}
}

// One candidate is either waiting or executing for this plane. Additional
// unadmitted packets are dropped, never queued into another native operation.
// Its bytes belong to this worker, not the reader's next TUN buffer.
type routeAdmissionCandidate struct {
	plan   *PacketPlan
	target Endpoint
	local  bool
	packet []byte
}

func (p *PacketPlane) reserveBytes(size int64) bool {
	for {
		used := p.bytes.Load()
		if size > p.limit-used {
			return false
		}
		if p.bytes.CompareAndSwap(used, used+size) {
			return true
		}
	}
}

func (p *PacketPlane) offerAdmission(plan *PacketPlan, target Endpoint, local bool, packet []byte) {
	if p.admission == nil || !p.spec.RoutePolicy.allows(true, packet) || plan.Admit == nil || !p.admitting.CompareAndSwap(false, true) {
		return
	}
	if !p.reserveBytes(int64(len(packet))) {
		p.admitting.Store(false)
		return
	}
	candidate := routeAdmissionCandidate{plan: plan, target: target, local: local, packet: bytes.Clone(packet)}
	select {
	case <-p.ctx.Done():
		p.releaseAdmission(candidate)
	case p.admission <- candidate:
	default:
		p.releaseAdmission(candidate)
	}
}

func (p *PacketPlane) releaseAdmission(candidate routeAdmissionCandidate) {
	p.bytes.Add(-int64(len(candidate.packet)))
	p.admitting.Store(false)
}

func (p *PacketPlane) admit() {
	for {
		select {
		case <-p.ctx.Done():
			return
		case candidate := <-p.admission:
			p.runAdmission(candidate)
			p.releaseAdmission(candidate)
		}
	}
}

func (p *PacketPlane) runAdmission(candidate routeAdmissionCandidate) {
	if p.ctx.Err() != nil || candidate.plan.Admit(p.ctx, candidate.packet) != nil {
		return
	}
	// Native/quorum IO can cross policy or path changes. Use the current
	// gate and original target; final IO checks the captured token again.
	plan := p.plan.Load()
	current, local, err := p.outboundTarget(plan, candidate.packet)
	if local != candidate.local {
		return
	}
	identity, allowed := p.outboundIdentity(plan, candidate.target, candidate.packet)
	if err != nil || current != candidate.target || !allowed {
		return
	}
	p.forwardPacket(candidate.target, candidate.local, identity, candidate.packet)
}

// Capture permission and its incarnation from ONE gate view. A final send
// cannot exchange an already admitted packet's old token for a new lifetime.
func (p *PacketPlane) outboundIdentity(plan *PacketPlan, target Endpoint, packet []byte) ([16]byte, bool) {
	if p.spec.RoutePolicy == nil {
		return target.ID, p.permitted(plan, p.local, true, packet)
	}
	if !p.spec.RoutePolicy.allows(true, packet) {
		return [16]byte{}, false
	}
	gate, bound := plan.Gate.(PacketBindingGate)
	if !bound {
		return [16]byte{}, false
	}
	binding, valid := gate.PacketBinding(p.local, packet)
	return binding.Token, valid && binding.Token != ([16]byte{}) && binding.Endpoint == target
}

// Admission/control IO happens before this lock. A Closing gate publication
// followed by PacketBarrier joins all previously admitted final IO without
// stopping this plane or the policy's unrelated flows.
func (p *PacketPlane) forwardPacket(target Endpoint, local bool, original [16]byte, packet []byte) {
	p.flowIO.RLock()
	defer p.flowIO.RUnlock()
	plan := p.plan.Load()
	identity, allowed := p.outboundIdentity(plan, target, packet)
	if p.ctx.Err() != nil || !allowed || identity != original {
		return
	}
	current, currentLocal, err := p.outboundTarget(plan, packet)
	if currentLocal != local {
		return
	}
	if err != nil || current != target {
		return
	}
	kind := uint8(1)
	if p.spec.RoutePolicy != nil {
		kind = 2
	}
	if local {
		_ = plan.Relay(target, identity, packet)
		return
	}
	peer, known := plan.Peers[target.Owner]
	if !known || peer.Session == nil || peer.Path.MTU() < p.spec.MTU || !peer.Session.PathCurrent(peer.Path) {
		return
	}
	wire := plan.WireKey
	if wire == ([32]byte{}) {
		wire = p.local
	}
	frame := mydcp.Frame{Purpose: mydcp.Packet, Kind: kind, Fields: []mydcp.Field{{Tag: 1, Required: true, Value: wire[:]}, {Tag: 2, Required: true, Value: p.network[:]}, {Tag: 3, Required: true, Value: identity[:]}, {Tag: 4, Required: true, Value: packet}}}
	// Drop on failure; never retry packets or fall back to a reliable stream.
	_ = peer.Session.SendPacket(p.ctx, frame)
}

// PacketBarrier requires the caller to have durably closed the original flow
// and published its denying gate. Old queued bytes are harmless only because
// every final write checks that gate again under this same lock.
func (p *PacketPlane) PacketBarrier(ctx context.Context) error {
	if p.spec.RoutePolicy == nil {
		return ErrPolicy
	}
	timer := time.NewTicker(2 * time.Millisecond)
	defer timer.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if p.flowIO.TryLock() {
			p.flowIO.Unlock()
			return ctx.Err()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
}

type queuedPacket struct {
	session *mydcp.Session
	frame   mydcp.Frame
	size    int64
	local   bool
}

func (p *PacketPlane) admitted(s *mydcp.Session, f mydcp.Frame) bool {
	if s == nil || f.Purpose != mydcp.Packet || len(f.Fields) < 4 || len(f.Fields[0].Value) != 32 || len(f.Fields[1].Value) != 16 || len(f.Fields[2].Value) != 16 {
		return false
	}
	plan := p.plan.Load()
	if plan == nil {
		return false
	}
	wire := [32]byte(s.Peer().Key)
	src, _, err := PacketAddresses(f.Fields[3].Value)
	source, exists := plan.Policy.byAddress[src]
	if err != nil || !exists || source.Network != p.network {
		return false
	}
	owner := source.Owner
	peer, known := plan.Peers[owner]
	expectedWire := peer.WireKey
	if expectedWire == ([32]byte{}) {
		expectedWire = owner
	}
	endpoint, valid := p.packetEndpoint(plan, owner, f)
	return valid && known && expectedWire == wire && peer.Session == s && peer.Path.MTU() >= p.spec.MTU && peer.Session.PathCurrent(peer.Path) && [32]byte(f.Fields[0].Value) == wire && [16]byte(f.Fields[1].Value) == p.network && plan.Policy.Inbound(p.local, owner, p.network, endpoint, p.spec.MTU, f.Fields[3].Value) == nil && p.permitted(plan, owner, false, f.Fields[3].Value)
}

func (p *PacketPlane) packetEndpoint(plan *PacketPlan, sender [32]byte, f mydcp.Frame) ([16]byte, bool) {
	if p.spec.RoutePolicy == nil {
		return [16]byte(f.Fields[2].Value), f.Kind == 1
	}
	gate, bound := plan.Gate.(PacketBindingGate)
	if !bound || f.Kind != 2 {
		return [16]byte{}, false
	}
	binding, valid := gate.PacketBinding(sender, f.Fields[3].Value)
	if !valid || binding.Token == ([16]byte{}) || binding.Token != [16]byte(f.Fields[2].Value) || binding.Endpoint.Owner != p.local || binding.Endpoint.Network != p.network {
		return [16]byte{}, false
	}
	return binding.Endpoint.ID, true
}

// Receive never blocks a QUIC handler. Queue count and payload bytes have
// separate limits. The encoded frame retains the ordinary endpoint or bilateral
// route flow incarnation for revalidation after a committed plan replacement.
func (p *PacketPlane) Receive(s *mydcp.Session, f mydcp.Frame) error {
	return p.receive(s, f, false)
}

// ReceiveLocal is used solely by the other original route plane on this node.
// The same bounded queue and current endpoint/policy/flow gate apply. It cannot
// turn an authenticated remote packet into local provenance.
func (p *PacketPlane) ReceiveLocal(token [16]byte, packet []byte) error {
	if p.spec.RoutePolicy == nil {
		return mydcp.ErrAdmission
	}
	plan := p.plan.Load()
	src, _, err := PacketAddresses(packet)
	source, exists := plan.Policy.byAddress[src]
	if err != nil || !exists || source.Network != p.network || source.Owner != p.local && !plan.LocalOwners[source.Owner] {
		return mydcp.ErrAdmission
	}
	owner := source.Owner
	f := mydcp.Frame{Purpose: mydcp.Packet, Kind: 2, Fields: []mydcp.Field{{Tag: 1, Required: true, Value: owner[:]}, {Tag: 2, Required: true, Value: p.network[:]}, {Tag: 3, Required: true, Value: token[:]}, {Tag: 4, Required: true, Value: packet}}}
	return p.receive(nil, f, true)
}

func (p *PacketPlane) admittedLocal(f mydcp.Frame) bool {
	if p.spec.RoutePolicy == nil || f.Purpose != mydcp.Packet || f.Kind != 2 || len(f.Fields) < 4 || len(f.Fields[0].Value) != 32 || len(f.Fields[1].Value) != 16 || len(f.Fields[2].Value) != 16 || [16]byte(f.Fields[1].Value) != p.network {
		return false
	}
	plan := p.plan.Load()
	owner := [32]byte(f.Fields[0].Value)
	if owner != p.local && !plan.LocalOwners[owner] {
		return false
	}
	endpoint, valid := p.packetEndpoint(plan, owner, f)
	var err error
	if owner == p.local {
		err = plan.Policy.LocalInbound(p.local, p.network, endpoint, p.spec.MTU, f.Fields[3].Value)
	} else {
		err = plan.Policy.Inbound(p.local, owner, p.network, endpoint, p.spec.MTU, f.Fields[3].Value)
	}
	return valid && err == nil && p.permitted(plan, owner, false, f.Fields[3].Value)
}

func (p *PacketPlane) receive(s *mydcp.Session, f mydcp.Frame, local bool) error {
	p.receiving.RLock()
	defer p.receiving.RUnlock()
	if p.ctx.Err() != nil || local && !p.admittedLocal(f) || !local && !p.admitted(s, f) {
		return mydcp.ErrAdmission
	}
	b, err := mydcp.Encode(f)
	if err != nil {
		return err
	}
	d, _ := mydcp.NewDecoder(mydcp.MaxBody)
	owned, _, err := d.Feed(b)
	if err != nil || owned == nil {
		return mydcp.ErrFrame
	}
	if !p.reserveBytes(int64(len(b))) {
		return mydcp.ErrBudget
	}
	select {
	case p.queue <- queuedPacket{s, *owned, int64(len(b)), local}:
		return nil
	default:
		p.bytes.Add(-int64(len(b)))
		return mydcp.ErrBudget
	}
}
func (p *PacketPlane) write() {
	for {
		select {
		case <-p.ctx.Done():
			return
		case b := <-p.queue:
			p.bytes.Add(-b.size)
			if err := p.writePacket(b); err != nil {
				p.fail(err)
				return
			}
		}
	}
}

func (p *PacketPlane) writePacket(b queuedPacket) error {
	p.flowIO.RLock()
	defer p.flowIO.RUnlock()
	if b.local && !p.admittedLocal(b.frame) || !b.local && !p.admitted(b.session, b.frame) || p.ctx.Err() != nil {
		return nil
	}
	n, err := p.io.Write(b.frame.Fields[3].Value)
	if err != nil {
		return err
	}
	if n != len(b.frame.Fields[3].Value) {
		return io.ErrShortWrite
	}
	return nil
}
