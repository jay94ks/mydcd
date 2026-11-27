// SPDX-License-Identifier: Apache-2.0

package services

import (
	"bytes"
	"encoding/json"
	"slices"

	"github.com/jay94ks/seafield/internal/reconcile"
)

type routeRuntimeSnapshot struct {
	Schema                                     uint8
	Consumer                                   ReferenceConsumer
	Boot                                       [32]byte
	ReferenceFloor, NetworkFloor, CatalogFloor uint64
	State                                      reconcile.State
	Pins                                       reconcile.LeaseJournal
	Flows                                      []routeFlowState
	Fenced                                     bool
	Fences                                     []localReferenceFence
	Native                                     *RouteNativeProof
	ClosedPeers                                []routePinRange   `json:",omitempty"`
	PacketClose                                *RoutePacketClose `json:",omitempty"`
}

func (m RouteRuntime) snapshot() (routeRuntimeSnapshot, error) {
	c := m.consumer
	if !validRouteReference(c) || c.ID != referenceID(c.Scope, c.Generation) || c.Generation == 0 || c.Lifetime.Generation != 1 || c.Lifetime.Token == 0 || c.Closed != nil || c.ClosedRevision != 0 || m.boot == ([32]byte{}) || m.referenceFloor < c.Generation || m.networkFloor < c.DesiredSource || m.catalogFloor == 0 || reconcile.Validate(m.state) != nil || m.flows == nil || m.fences == nil || len(m.flows) > maxRecords || len(m.fences) > maxRecords {
		return routeRuntimeSnapshot{}, ErrLease
	}
	for _, a := range c.Route.Policy.Approvals {
		if m.catalogFloor < a.PolicyRevision {
			return routeRuntimeSnapshot{}, ErrLease
		}
	}
	if !validRoutePinRanges(m.closedPeers) {
		return routeRuntimeSnapshot{}, ErrLease
	}
	// Next is the last issued token, not the next unused token. A closure may
	// contain every issued flow, including zero flows before any issuance.
	if m.packetClose != nil && (!m.fenced || m.state.Desired.Present || len(m.flows) != 0 || len(m.pins.Active) != 0 || !validRoutePacketClose(c, *m.packetClose) || m.packetClose.Flows > m.pins.Next) {
		return routeRuntimeSnapshot{}, ErrLease
	}
	resource := reconcile.Resource{Generation: c.Generation, Present: true, Spec: routeSpec(c)}
	if m.state.Desired.Revision == 0 || m.state.GenerationFloor != c.Generation || m.state.Desired.Present && m.state.Desired.Resource != resource || !m.state.Desired.Present && m.state.Desired.Retiring != c.Generation || m.state.Applied.Present && m.state.Applied != resource || m.state.Pending != nil && m.state.Pending.Target != resource || m.fenced == m.state.Desired.Present {
		return routeRuntimeSnapshot{}, ErrLease
	}
	pins, e := reconcile.RestoreLeases(m.pins)
	if e != nil || m.pins.Generation != c.Generation || m.pins.Capacity > maxRecords || m.pins.Draining != m.fenced || pins.Count() != len(m.flows) {
		return routeRuntimeSnapshot{}, ErrLease
	}
	if m.native != nil && (!validRouteNative(c, *m.native, m.native.Boot) || m.native.Outcome != reconcile.EffectApplied || m.native.Operation > m.state.LastID || m.state.Applied.Present != (m.native.Kind == reconcile.Apply)) || m.state.Applied.Present && m.native == nil {
		return routeRuntimeSnapshot{}, ErrLease
	}
	s := routeRuntimeSnapshot{Schema: 1, Consumer: ownReferenceConsumer(c), Boot: m.boot, ReferenceFloor: m.referenceFloor, NetworkFloor: m.networkFloor, CatalogFloor: m.catalogFloor, State: m.Journal(), Pins: m.pins, Fenced: m.fenced}
	s.Pins.Active = slices.Clone(m.pins.Active)
	s.ClosedPeers = slices.Clone(m.closedPeers)
	if m.packetClose != nil {
		p := ownRoutePacketClose(*m.packetClose)
		s.PacketClose = &p
	}
	if m.native != nil {
		p := ownRouteNative(*m.native)
		s.Native = &p
	}
	for _, pin := range m.pins.Active {
		f, ok := m.flows[pin.Token]
		peer, valid := peerProjection(c, f.Peer.Reference)
		if !ok || f.Pin != pin || !valid || !validRouteNative(peer, f.Peer, f.Peer.Boot) || f.Peer.Kind != reconcile.Apply || f.Peer.Outcome != reconcile.EffectApplied || !validOriginalTuple(*c.Route, f.Tuple) {
			return routeRuntimeSnapshot{}, ErrLease
		}
		if f.Remote != nil && (!validPeerFlowReceipt(c, f, *f.Remote) || closedRoutePin(m.closedPeers, f.Remote.Pin.Token)) {
			return routeRuntimeSnapshot{}, ErrLease
		}
		if f.Tracked && (f.Boot == ([32]byte{}) || c.Route.Side != c.Route.Policy.Source.Tenant) || f.Closing && (c.Route.Side == c.Route.Policy.Source.Tenant && !f.Tracked || c.Route.Side != c.Route.Policy.Source.Tenant && f.Remote == nil) {
			return routeRuntimeSnapshot{}, ErrLease
		}
		for _, old := range s.Flows {
			if old.Tuple == f.Tuple {
				return routeRuntimeSnapshot{}, ErrLease
			}
		}
		f.Peer = ownRouteNative(f.Peer)
		if f.Remote != nil {
			p := ownRouteFlowReceipt(*f.Remote)
			f.Remote = &p
		}
		s.Flows = append(s.Flows, f)
	}
	for id, f := range m.fences {
		if id != f.ID || f.ID != ReferenceTargetID(f.Target) || f.Epoch < c.Generation || f.Epoch > m.referenceFloor || !consumerCovers(c, f.Target.Source, f.Epoch) || !validReferenceSource(f.Target.Source, c.Local.Cluster) || f.Target.Allocation.Generation == 0 || f.Target.Allocation.Endpoint == "" || f.Target.Allocation.Pool != fullPool(f.Target.Source) || f.Target.Allocation.Owner != poolOwner(f.Target.Source) || !f.Target.Source.Prefix.Contains(f.Target.Allocation.Address) {
			return routeRuntimeSnapshot{}, ErrLease
		}
		s.Fences = append(s.Fences, f)
	}
	slices.SortFunc(s.Fences, func(a, b localReferenceFence) int { return bytes.Compare(a.ID[:], b.ID[:]) })
	return s, nil
}
func validOriginalTuple(r RouteReference, t RouteTuple) bool {
	if t.Source.Generation == 0 || t.Destination.Generation == 0 || t.Source.Endpoint == "" || t.Destination.Endpoint == "" || t.Source.Pool != fullPool(r.Source) || t.Destination.Pool != fullPool(r.Destination) || t.Source.Owner != poolOwner(r.Source) || t.Destination.Owner != poolOwner(r.Destination) || !r.Source.Prefix.Contains(t.Source.Address) || !r.Destination.Prefix.Contains(t.Destination.Address) || t.SourcePort == 0 || t.Protocol != r.Policy.Protocol {
		return false
	}
	for _, p := range r.Policy.Ports {
		if t.DestinationPort >= p.First && t.DestinationPort <= p.Last {
			return true
		}
	}
	return false
}
func (m RouteRuntime) Encode() ([]byte, error) {
	s, e := m.snapshot()
	if e != nil {
		return nil, e
	}
	raw, e := json.Marshal(s)
	if e != nil || len(raw) > 32<<20 {
		return nil, ErrLease
	}
	return raw, nil
}
func DecodeRouteRuntime(raw []byte) (RouteRuntime, error) {
	var s routeRuntimeSnapshot
	if len(raw) > 32<<20 || json.Unmarshal(raw, &s) != nil || s.Schema != 1 || len(s.Flows) > maxRecords || len(s.Fences) > maxRecords {
		return RouteRuntime{}, ErrLease
	}
	m := RouteRuntime{consumer: ownReferenceConsumer(s.Consumer), boot: s.Boot, referenceFloor: s.ReferenceFloor, networkFloor: s.NetworkFloor, catalogFloor: s.CatalogFloor, state: s.State, pins: s.Pins, fenced: s.Fenced, native: s.Native, flows: map[uint64]routeFlowState{}, fences: map[[32]byte]localReferenceFence{}}
	m.closedPeers = slices.Clone(s.ClosedPeers)
	m.packetClose = s.PacketClose
	for _, f := range s.Flows {
		if _, dup := m.flows[f.Pin.Token]; dup {
			return RouteRuntime{}, ErrLease
		}
		m.flows[f.Pin.Token] = f
	}
	for _, f := range s.Fences {
		if _, dup := m.fences[f.ID]; dup {
			return RouteRuntime{}, ErrLease
		}
		m.fences[f.ID] = f
	}
	canonical, e := m.Encode()
	if e != nil || !bytes.Equal(canonical, raw) {
		return RouteRuntime{}, ErrLease
	}
	return m.clone(), nil
}
