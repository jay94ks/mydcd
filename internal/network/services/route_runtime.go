// SPDX-License-Identifier: Apache-2.0

package services

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/tenancy"
)

// RouteNativeProof is original native-journal evidence, not a control commit.
// NotApplied means positive evidence for that exact operation, never absence
// of a reply. A native collector signs after its own journal/worker checks.
type RouteNativeProof struct {
	Cluster                                    [32]byte
	Reference                                  ReferenceNeed
	Boot                                       [32]byte
	Native, Spec                               string
	Operation                                  uint64
	Kind                                       reconcile.Kind
	Outcome                                    reconcile.Outcome
	JournalSynced, Installed, Gone, NotApplied bool
	Signature                                  []byte
}

func RouteNativeBytes(p RouteNativeProof) []byte {
	p.Signature = nil
	raw, _ := json.Marshal(p)
	return append([]byte("sfc-route-native-1\x00"), raw...)
}
func ownRouteNative(p RouteNativeProof) RouteNativeProof {
	p.Signature = slices.Clone(p.Signature)
	return p
}
func routeNativeKey(c ReferenceConsumer) string { return "route/" + hex.EncodeToString(c.ID[:]) }
func routeSpec(c ReferenceConsumer) string      { return hex.EncodeToString(c.DesiredHash[:]) }
func validRouteNative(c ReferenceConsumer, p RouteNativeProof, boot [32]byte) bool {
	if !validRouteReference(c) || p.Cluster != c.Local.Cluster || !sameReference(p.Reference, referenceNeed(c)) || boot == ([32]byte{}) || p.Boot != boot || p.Native != routeNativeKey(c) || p.Spec != routeSpec(c) || p.Operation == 0 || !p.JournalSynced || p.Kind != reconcile.Apply && p.Kind != reconcile.Remove || p.Outcome != reconcile.EffectApplied && p.Outcome != reconcile.EffectNotApplied {
		return false
	}
	if p.Outcome == reconcile.EffectNotApplied {
		if !p.NotApplied || p.Installed || p.Gone {
			return false
		}
	} else if p.NotApplied || p.Kind == reconcile.Apply && (!p.Installed || p.Gone) || p.Kind == reconcile.Remove && (!p.Gone || p.Installed) {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(c.Local.Owner[:]), RouteNativeBytes(p), p.Signature)
}

// RouteTuple is canonical source->destination policy orientation. A return
// packet may use an existing pin but cannot create a reverse or transit flow.
type RouteTuple struct {
	Source, Destination         network.Allocation
	SourcePort, DestinationPort uint16
	Protocol                    uint8
}

func tupleHash(t RouteTuple) [32]byte {
	raw, _ := json.Marshal(t)
	return sha256.Sum256(append([]byte("sfc-route-flow-1\x00"), raw...))
}
func reverseTuple(t RouteTuple) RouteTuple {
	return RouteTuple{t.Destination, t.Source, t.DestinationPort, t.SourcePort, t.Protocol}
}

// RouteFlow is an opaque original local A3 receipt. The adapter syncs the
// returned candidate before a packet/native connection can use this receipt.
type RouteFlow struct {
	consumer [32]byte
	pin      reconcile.Lease
	tuple    RouteTuple
}

func (f RouteFlow) Lease() reconcile.Lease { return f.pin }
func (f RouteFlow) Tuple() RouteTuple      { return f.tuple }

type routeFlowState struct {
	Pin   reconcile.Lease
	Tuple RouteTuple
	Peer  RouteNativeProof
	// Zero is retained for legacy, one-sided model checkpoints. A newly
	// admitted flow records its original boot; ResumeBoot cannot reauthorize it.
	Boot    [32]byte          `json:",omitzero"`
	Remote  *RouteFlowReceipt `json:",omitempty"`
	Tracked bool              `json:",omitempty"`
	Closing bool              `json:",omitempty"`
}

type RouteFlowClose struct {
	Cluster                           [32]byte
	Reference                         ReferenceNeed
	Boot                              [32]byte
	Pin                               reconcile.Lease
	Tuple                             [32]byte
	Native                            string
	JournalSynced, Stopped, NoPending bool
	Signature                         []byte
}

func RouteFlowCloseBytes(p RouteFlowClose) []byte {
	p.Signature = nil
	raw, _ := json.Marshal(p)
	return append([]byte("sfc-route-flow-close-1\x00"), raw...)
}

// RouteRuntime owns one side's native journal and stateful flow references.
// Native state is node-local. Shared Authority only coordinates lifetime/fences.
// The native actor serializes and syncs every candidate before publication.
type RouteRuntime struct {
	consumer                                   ReferenceConsumer
	boot                                       [32]byte
	referenceFloor, networkFloor, catalogFloor uint64
	state                                      reconcile.State
	pins                                       reconcile.LeaseJournal
	flows                                      map[uint64]routeFlowState
	fenced                                     bool
	fences                                     map[[32]byte]localReferenceFence
	native                                     *RouteNativeProof
	closedPeers                                []routePinRange
	packetClose                                *RoutePacketClose
}

func NewRouteRuntime(c access.Catalog, n tenancy.Networks, a Authority, id, boot [32]byte, capacity int) (RouteRuntime, error) {
	ref, ok := a.ReferenceConsumer(id)
	if !ok || ref.Closed != nil || !validRouteReference(ref) || n.Cluster() != a.cluster || boot == ([32]byte{}) || capacity < 1 || capacity > maxRecords || !n.RouteAuthorized(c, ref.Route.Policy.Source.Tenant, ref.Route.Policy.ID) {
		return RouteRuntime{}, ErrLease
	}
	current, _ := n.Route(ref.Route.Policy.Source.Tenant, ref.Name)
	if current.Generation != ref.Route.Policy.Generation || current.Revision != ref.DesiredSource || a.references.Scopes[ref.Scope] != ref.ID {
		return RouteRuntime{}, ErrLease
	}
	return newRouteRuntime(c, n, a, ref, boot, capacity)
}

// NewUnstartedRouteRetirement relies on a COMMITTED withdrawal barrier and
// the immutable absence of any dispatch grant, not on missing local history.
// Its core is terminal and cannot dispatch native work or acquire flow pins.
func NewUnstartedRouteRetirement(c access.Catalog, n tenancy.Networks, a Authority, id, boot [32]byte) (RouteRuntime, error) {
	ref, exists := a.ReferenceConsumer(id)
	if !exists || ref.Closed != nil || ref.Dispatch != nil || ref.Native == nil || !validRouteReference(ref) || !a.CurrentRouteReference(id) || n.Cluster() != a.cluster || boot == ([32]byte{}) {
		return RouteRuntime{}, ErrLease
	}
	policy, exists := n.Route(ref.Route.Policy.Source.Tenant, ref.Name)
	if !exists || policy.Phase != tenancy.Revoking || policy.Generation != ref.Route.Policy.Generation {
		return RouteRuntime{}, ErrLease
	}
	core, err := newRouteRuntime(c, n, a, ref, boot, 1)
	if err != nil {
		return RouteRuntime{}, err
	}
	core, _, err = core.Plan()
	if err != nil {
		return RouteRuntime{}, err
	}
	return core.RetireNeverDispatched(c, n, a)
}

// RetireNeverDispatched preserves an already prepared private journal. A nil
// grant is decisive only under the committed withdrawal barrier; local
// disappearance or a generic permission failure cannot establish this fact.
func (m RouteRuntime) RetireNeverDispatched(c access.Catalog, n tenancy.Networks, a Authority) (RouteRuntime, error) {
	ref, exists := a.ReferenceConsumer(m.consumer.ID)
	policy, known := n.Route(m.consumer.Route.Policy.Source.Tenant, m.consumer.Name)
	if !exists || ref.Dispatch != nil || ref.Closed != nil || ref.Native == nil || !a.CurrentRouteReference(ref.ID) || !sameReference(referenceNeed(ref), referenceNeed(m.consumer)) || !known || policy.Generation != m.consumer.Route.Policy.Generation || policy.Phase != tenancy.Revoking || m.state.LastID != 1 || m.state.Applied.Present || m.native != nil || len(m.flows) != 0 || m.state.Pending == nil || m.state.Pending.ID != 1 || m.state.Pending.Kind != reconcile.Apply || m.state.Pending.Phase != reconcile.Prepared {
		return m, ErrLease
	}
	return m.Sync(c, n, a)
}

func newRouteRuntime(c access.Catalog, n tenancy.Networks, a Authority, ref ReferenceConsumer, boot [32]byte, capacity int) (RouteRuntime, error) {
	state, e := reconcile.SetDesired(reconcile.State{}, reconcile.Desired{Revision: 1, Resource: reconcile.Resource{Generation: ref.Generation, Present: true, Spec: routeSpec(ref)}})
	if e != nil {
		return RouteRuntime{}, e
	}
	pins, e := reconcile.NewLeases(ref.Generation, capacity)
	if e != nil {
		return RouteRuntime{}, e
	}
	return RouteRuntime{consumer: ref, boot: boot, referenceFloor: a.revision, networkFloor: n.Revision(), catalogFloor: c.Revision(), state: state, pins: pins.Checkpoint(), flows: map[uint64]routeFlowState{}, fences: map[[32]byte]localReferenceFence{}}, nil
}
func (m RouteRuntime) clone() RouteRuntime {
	q := m
	q.closedPeers = slices.Clone(m.closedPeers)
	if m.packetClose != nil {
		p := ownRoutePacketClose(*m.packetClose)
		q.packetClose = &p
	}
	q.consumer = ownReferenceConsumer(m.consumer)
	q.pins.Active = slices.Clone(m.pins.Active)
	if m.state.Pending != nil {
		p := *m.state.Pending
		q.state.Pending = &p
	}
	if m.native != nil {
		p := ownRouteNative(*m.native)
		q.native = &p
	}
	q.flows = map[uint64]routeFlowState{}
	for k, v := range m.flows {
		v.Peer = ownRouteNative(v.Peer)
		if v.Remote != nil {
			p := ownRouteFlowReceipt(*v.Remote)
			v.Remote = &p
		}
		q.flows[k] = v
	}
	q.fences = map[[32]byte]localReferenceFence{}
	for k, v := range m.fences {
		q.fences[k] = v
	}
	return q
}
func (m RouteRuntime) Journal() reconcile.State    { return m.clone().state }
func (m RouteRuntime) Consumer() ReferenceConsumer { return ownReferenceConsumer(m.consumer) }
func (m RouteRuntime) Boot() [32]byte              { return m.boot }
func (m RouteRuntime) FlowCount() int              { return len(m.flows) }
func (m RouteRuntime) NativeObservation() (RouteNativeProof, bool) {
	if m.native == nil {
		return RouteNativeProof{}, false
	}
	return ownRouteNative(*m.native), true
}
func (m RouteRuntime) fresh(c access.Catalog, n tenancy.Networks, a Authority) bool {
	return a.cluster == m.consumer.Local.Cluster && n.Cluster() == a.cluster && a.revision >= m.referenceFloor && n.Revision() >= m.networkFloor && c.Revision() >= m.catalogFloor
}
func (m RouteRuntime) policyActive(c access.Catalog, n tenancy.Networks, a Authority) bool {
	if !m.fresh(c, n, a) || m.fenced {
		return false
	}
	ref, ok := a.references.Consumers[m.consumer.ID]
	if !ok || ref.Closed != nil || a.references.Scopes[ref.Scope] != ref.ID || !sameReference(referenceNeed(ref), referenceNeed(m.consumer)) {
		return false
	}
	r, ok := n.Route(m.consumer.Route.Policy.Source.Tenant, m.consumer.Name)
	return ok && r.Generation == m.consumer.Route.Policy.Generation && r.Revision == m.consumer.DesiredSource && n.RouteAuthorized(c, r.Source.Tenant, r.ID)
}
func (m RouteRuntime) active(c access.Catalog, n tenancy.Networks, a Authority) bool {
	return !m.state.Stopped && m.policyActive(c, n, a)
}
func (m *RouteRuntime) floors(c access.Catalog, n tenancy.Networks, a Authority) {
	m.referenceFloor = a.revision
	m.networkFloor = n.Revision()
	m.catalogFloor = c.Revision()
}

// Sync never overwrites a dispatched old operation. Once this instance is
// fenced it cannot reopen; explicit reactivation uses a new shared lifetime.
func (m RouteRuntime) Sync(c access.Catalog, n tenancy.Networks, a Authority) (RouteRuntime, error) {
	if !m.fresh(c, n, a) {
		return m, ErrLease
	}
	q := m.clone()
	q.floors(c, n, a)
	if !m.policyActive(c, n, a) || m.fenced {
		q.fenced = true
		pins, e := reconcile.RestoreLeases(q.pins)
		if e != nil {
			return m, e
		}
		pins.Drain()
		q.pins = pins.Checkpoint()
		if q.state.Desired.Present {
			if q.state.Pending != nil && q.state.Pending.Kind == reconcile.Apply && q.state.Pending.Phase == reconcile.Prepared {
				q.state, e = reconcile.AbortPrepared(q.state, q.state.Pending.ID)
				if e != nil {
					return m, e
				}
			}
			if q.state.Desired.Revision == ^uint64(0) {
				return m, ErrLease
			}
			q.state, e = reconcile.SetDesired(q.state, reconcile.Desired{Revision: q.state.Desired.Revision + 1, Retiring: q.consumer.Generation})
			if e != nil {
				return m, e
			}
		}
	}
	return q, nil
}
func (m RouteRuntime) Pause() RouteRuntime {
	q := m.clone()
	q.state = reconcile.Stop(q.state)
	return q
}

// ResumeBoot preserves original pending work and flow pins. Old native proof
// cannot publish Ready in the new boot; original native read-back is required.
func (m RouteRuntime) ResumeBoot(boot [32]byte) (RouteRuntime, error) {
	if boot == ([32]byte{}) {
		return m, ErrLease
	}
	q := m.clone()
	q.boot = boot
	var e error
	q.state, e = reconcile.Resume(q.state)
	return q, e
}
func (m RouteRuntime) Plan() (RouteRuntime, *reconcile.Operation, error) {
	if !m.state.Desired.Present && len(m.flows) != 0 {
		return m, nil, reconcile.ErrPending
	}
	state, op, e := reconcile.Plan(m.state)
	if e != nil {
		return m, nil, e
	}
	q := m.clone()
	q.state = state
	return q, op, nil
}
func (m RouteRuntime) Dispatch(id uint64) (RouteRuntime, error) {
	if m.state.Pending != nil && m.state.Pending.Kind == reconcile.Apply && (m.fenced || !m.state.Desired.Present) {
		return m, ErrLease
	}
	s, e := reconcile.Dispatch(m.state, id)
	if e != nil {
		return m, e
	}
	q := m.clone()
	q.state = s
	return q, nil
}
func (m RouteRuntime) Unknown(id uint64) (RouteRuntime, error) {
	s, e := reconcile.Settle(m.state, id, reconcile.EffectUnknown)
	if e != nil {
		return m, e
	}
	q := m.clone()
	q.state = s
	return q, nil
}

// BeginNativeRetirement preserves an obsolete original Apply's identity and
// uncertain outcome while closing that exact target with the existing A2 core.
func (m RouteRuntime) BeginNativeRetirement() (RouteRuntime, error) {
	if !m.fenced || m.state.Pending == nil || len(m.flows) != 0 {
		return m, ErrLease
	}
	if m.state.Pending.Phase == reconcile.Retiring {
		return m, nil
	}
	state, err := reconcile.BeginRetirement(m.state, m.state.Pending.ID)
	if err != nil {
		return m, err
	}
	next := m.clone()
	next.state = state
	return next, nil
}

// FinishNativeRetirement consumes actual closure, never a reconstructed Apply
// result. A late success for the original Apply cannot reopen this instance.
func (m RouteRuntime) FinishNativeRetirement(proof RouteNativeProof) (RouteRuntime, error) {
	original := m.state.Pending
	if !m.fenced || len(m.flows) != 0 || original == nil || original.Kind != reconcile.Apply || original.Phase != reconcile.Retiring || original.ID != proof.Operation || original.Target.Spec != proof.Spec || proof.Kind != reconcile.Remove || proof.Outcome != reconcile.EffectApplied || !validRouteNative(m.consumer, proof, m.boot) {
		return m, ErrLease
	}
	state, err := reconcile.FinishRetirement(m.state, original.ID, true)
	if err != nil {
		return m, err
	}
	next := m.clone()
	next.state = state
	owned := ownRouteNative(proof)
	next.native = &owned
	return next, nil
}
func (m RouteRuntime) ObserveNative(p RouteNativeProof) (RouteRuntime, error) {
	op := m.state.Pending
	if op == nil || op.ID != p.Operation || op.Kind != p.Kind || op.Target.Spec != p.Spec || !validRouteNative(m.consumer, p, m.boot) {
		return m, ErrLease
	}
	s, e := reconcile.Settle(m.state, p.Operation, p.Outcome)
	if e != nil {
		return m, e
	}
	q := m.clone()
	q.state = s
	if p.Outcome == reconcile.EffectApplied {
		v := ownRouteNative(p)
		q.native = &v
	}
	return q, nil
}
func (m RouteRuntime) RevalidateNative(p RouteNativeProof) (RouteRuntime, error) {
	if m.native == nil || !m.state.Applied.Present || m.state.Pending != nil || p.Operation != m.native.Operation || p.Kind != reconcile.Apply || p.Outcome != reconcile.EffectApplied || !validRouteNative(m.consumer, p, m.boot) {
		return m, ErrLease
	}
	q := m.clone()
	v := ownRouteNative(p)
	q.native = &v
	return q, nil
}
func (m RouteRuntime) nativeReady() bool {
	return m.state.Pending == nil && !m.state.Stopped && m.state.Desired.Present && m.state.Applied == m.state.Desired.Resource && m.native != nil && m.native.Kind == reconcile.Apply && m.native.Outcome == reconcile.EffectApplied && validRouteNative(m.consumer, *m.native, m.boot)
}
func (m RouteRuntime) AppliedProof(c access.Catalog, n tenancy.Networks, a Authority) (RouteNativeProof, error) {
	if !m.active(c, n, a) || !m.nativeReady() {
		return RouteNativeProof{}, ErrLease
	}
	return ownRouteNative(*m.native), nil
}
func (m RouteRuntime) peer(a Authority, p RouteNativeProof, boot [32]byte) bool {
	ref, ok := a.references.Consumers[p.Reference.Consumer]
	if !ok || ref.Closed != nil || ref.Route == nil || ref.Route.Side == m.consumer.Route.Side || ref.Route.Policy.Source.Tenant != m.consumer.Route.Policy.Source.Tenant || ref.Route.Policy.ID != m.consumer.Name || ref.Route.Policy.Generation != m.consumer.Route.Policy.Generation || ref.Route.Policy.Revision != m.consumer.DesiredSource || a.references.Scopes[ref.Scope] != ref.ID {
		return false
	}
	return p.Kind == reconcile.Apply && p.Outcome == reconcile.EffectApplied && validRouteNative(ref, p, boot)
}
func (m RouteRuntime) blocked(a Authority, alloc network.Allocation) bool {
	if a.addressFenced(alloc) {
		return true
	}
	for _, f := range m.fences {
		if f.Target.Allocation == alloc {
			return true
		}
	}
	return false
}
func routeEndpoint(a Authority, s Source, alloc network.Allocation, now Clock) bool {
	current, ok := a.book.AllocationOf(alloc.Endpoint, alloc.Generation)
	pool, held := a.referencePool(alloc.Pool)
	if !ok || current != alloc || !held || pool.Draining || alloc.Owner != poolOwner(s) || alloc.Pool != fullPool(s) || !s.Prefix.Contains(alloc.Address) {
		return false
	}
	return true
}
func (m RouteRuntime) tupleAllowed(c access.Catalog, n tenancy.Networks, a Authority, t RouteTuple, now Clock) bool {
	r := m.consumer.Route
	return t.SourcePort != 0 && t.DestinationPort != 0 && !m.blocked(a, t.Source) && !m.blocked(a, t.Destination) && routeEndpoint(a, r.Source, t.Source, now) && routeEndpoint(a, r.Destination, t.Destination, now) && n.AllowsNewFlow(c, r.Policy.Source.Tenant, r.Policy.ID, t.Source.Address, t.Destination.Address, t.Protocol, t.DestinationPort)
}

// BorrowFlow is an admission plan, not endpoint/transport authentication. The
// native actor supplies the currently authenticated peer boot, verifies ingress
// provenance and syncs both owners' local pins before forwarding any packet.
func (m RouteRuntime) BorrowFlow(c access.Catalog, n tenancy.Networks, a Authority, p RouteNativeProof, peerBoot [32]byte, t RouteTuple, now Clock) (RouteRuntime, RouteFlow, error) {
	if !m.active(c, n, a) || !m.nativeReady() || !m.peer(a, p, peerBoot) || !m.tupleAllowed(c, n, a, t, now) {
		return m, RouteFlow{}, ErrLease
	}
	for _, f := range m.flows {
		if f.Tuple == t {
			return m, RouteFlow{}, ErrLease
		}
	}
	pins, e := reconcile.RestoreLeases(m.pins)
	if e != nil {
		return m, RouteFlow{}, e
	}
	pin, e := pins.Acquire()
	if e != nil {
		return m, RouteFlow{}, e
	}
	q := m.clone()
	q.floors(c, n, a)
	q.pins = pins.Checkpoint()
	q.flows[pin.Token] = routeFlowState{Pin: pin, Tuple: t, Peer: ownRouteNative(p), Boot: m.boot}
	return q, RouteFlow{m.consumer.ID, pin, t}, nil
}
func (m RouteRuntime) flow(h RouteFlow) (routeFlowState, bool) {
	f, ok := m.flows[h.pin.Token]
	return f, ok && h.consumer == m.consumer.ID && f.Pin == h.pin && f.Tuple == h.tuple
}
func (m RouteRuntime) AllowsPacket(c access.Catalog, n tenancy.Networks, a Authority, h RouteFlow, packet RouteTuple, peerBoot [32]byte, now Clock) bool {
	f, ok := m.flow(h)
	return ok && !f.Closing && m.active(c, n, a) && m.nativeReady() && m.peer(a, f.Peer, peerBoot) && m.tupleAllowed(c, n, a, f.Tuple, now) && (packet == f.Tuple || packet == reverseTuple(f.Tuple))
}
func (m RouteRuntime) ReleaseFlow(h RouteFlow, p RouteFlowClose) (RouteRuntime, error) {
	f, ok := m.flow(h)
	if !ok || p.Cluster != m.consumer.Local.Cluster || !sameReference(p.Reference, referenceNeed(m.consumer)) || p.Boot != m.boot || p.Pin != f.Pin || p.Tuple != tupleHash(f.Tuple) || p.Native != routeNativeKey(m.consumer)+"/flow/"+generationText(f.Pin.Token) || !p.JournalSynced || !p.Stopped || !p.NoPending || !ed25519.Verify(ed25519.PublicKey(m.consumer.Local.Owner[:]), RouteFlowCloseBytes(p), p.Signature) {
		return m, ErrLease
	}
	pins, e := reconcile.RestoreLeases(m.pins)
	if e != nil || pins.Release(f.Pin) != nil {
		return m, ErrLease
	}
	q := m.clone()
	q.pins = pins.Checkpoint()
	delete(q.flows, f.Pin.Token)
	if f.Remote != nil {
		q.closedPeers = closeRoutePin(q.closedPeers, f.Remote.Pin.Token)
		if len(q.closedPeers) > maxRecords {
			return m, ErrLease
		}
	}
	return q, nil
}
func (m RouteRuntime) Resize(capacity int) (RouteRuntime, error) {
	if capacity < 1 || capacity > maxRecords {
		return m, ErrLease
	}
	pins, e := reconcile.RestoreLeases(m.pins)
	if e != nil || pins.Resize(capacity) != nil {
		return m, ErrLease
	}
	q := m.clone()
	q.pins = pins.Checkpoint()
	return q, nil
}
func (m RouteRuntime) SyncReferenceFence(a Authority, target [32]byte) (RouteRuntime, error) {
	f, ok := a.references.Fences[target]
	if !ok || a.cluster != m.consumer.Local.Cluster || a.revision < m.referenceFloor {
		return m, ErrLease
	}
	found := false
	for _, n := range f.Required {
		if sameReference(n, referenceNeed(m.consumer)) {
			found = true
		}
	}
	if !found {
		return m, ErrLease
	}
	q := m.clone()
	q.referenceFloor = a.revision
	q.fences[target] = localReferenceFence{f.ID, f.Target, f.Epoch}
	return q, nil
}
func (m RouteRuntime) ReferenceFacts(a Authority, target [32]byte, now Clock) (ReferenceClose, error) {
	c, ok := a.ReferenceConsumer(m.consumer.ID)
	if !ok || !validClock(now) || now.Boot != m.boot || a.cluster != m.consumer.Local.Cluster || a.revision < m.referenceFloor || !sameReference(referenceNeed(c), referenceNeed(m.consumer)) {
		return ReferenceClose{}, ErrLease
	}
	p := ReferenceClose{Cluster: a.cluster, Consumer: c.ID, Generation: c.Generation, Lifetime: c.Lifetime, Owner: c.Local.Owner, Boot: m.boot, Target: target, At: now.Wall, Native: routeNativeKey(c), Fenced: true, TTLExpired: true}
	if target == ([32]byte{}) {
		if !m.fenced || m.state.Applied.Present || m.state.Pending != nil || len(m.flows) != 0 {
			return ReferenceClose{}, ErrLease
		}
		return p, nil
	}
	f, ok := a.references.Fences[target]
	local, known := m.fences[target]
	if !ok || !known || local.Target != f.Target || local.Epoch != f.Epoch {
		return ReferenceClose{}, ErrLease
	}
	for _, v := range m.flows {
		if v.Tuple.Source == f.Target.Allocation || v.Tuple.Destination == f.Target.Allocation {
			return ReferenceClose{}, ErrLease
		}
	}
	if m.state.Pending != nil {
		return ReferenceClose{}, ErrLease
	}
	p.Epoch = f.Epoch
	return p, nil
}

// RouteClosureFacts deliberately leaves NativeGone=false for the real native
// collector. Policy deletion must join this and ReferenceFacts atomically.
func (m RouteRuntime) RouteClosureFacts(n tenancy.Networks) (tenancy.RouteClosure, error) {
	r, ok := n.Route(m.consumer.Route.Policy.Source.Tenant, m.consumer.Name)
	if !ok || n.Cluster() != m.consumer.Local.Cluster || n.Revision() < m.networkFloor || r.Generation != m.consumer.Route.Policy.Generation || r.Phase != tenancy.Revoking || !m.fenced || m.state.Applied.Present || m.state.Pending != nil || len(m.flows) != 0 {
		return tenancy.RouteClosure{}, ErrLease
	}
	b := m.consumer.Local
	return tenancy.RouteClosure{Cluster: b.Cluster, SourceTenant: r.Source.Tenant, Route: r.ID, Tenant: m.consumer.Route.Side, Node: b.Node, Owner: b.Owner, Generation: r.Generation, Revision: r.Revision}, nil
}

// CompactReferenceFences drops only completed targets after the original
// allocation is gone; the persisted reference floor still rejects old roots.
func (m RouteRuntime) CompactReferenceFences(a Authority) (RouteRuntime, error) {
	if a.cluster != m.consumer.Local.Cluster || a.revision < m.referenceFloor {
		return m, ErrLease
	}
	q := m.clone()
	q.referenceFloor = a.revision
	for id, f := range q.fences {
		if _, held := a.references.Fences[id]; held {
			continue
		}
		alloc, held := a.book.AllocationOf(f.Target.Allocation.Endpoint, f.Target.Allocation.Generation)
		if a.revision > f.Epoch && (!held || alloc != f.Target.Allocation) {
			delete(q.fences, id)
		}
	}
	return q, nil
}
func peerProjection(local ReferenceConsumer, need ReferenceNeed) (ReferenceConsumer, bool) {
	if local.Route == nil {
		return ReferenceConsumer{}, false
	}
	r := ownRouteReference(*local.Route)
	if r.Side == r.Policy.Source.Tenant {
		r.Side = r.Policy.Destination.Tenant
	} else {
		r.Side = r.Policy.Source.Tenant
	}
	c := ReferenceConsumer{ID: need.Consumer, Scope: routeScope(r), Name: r.Policy.ID, Local: routeLocal(r), Generation: need.Generation, Lifetime: need.Lifetime, DesiredSource: r.Policy.Revision, DesiredHash: routeHash(r), Route: &r, Members: []ReferenceMember{{r.Source, need.Generation}, {r.Destination, need.Generation}}}
	sortReferenceMembers(c.Members)
	return c, need.Owner == c.Local.Owner && need.Generation > 0 && need.Consumer == referenceID(c.Scope, need.Generation) && need.Lifetime.Generation == 1 && need.Lifetime.Token > 0 && validRouteReference(c)
}
