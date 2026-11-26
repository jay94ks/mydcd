// SPDX-License-Identifier: Apache-2.0

package services

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"slices"

	"github.com/jay94ks/mydcd/internal/reconcile"
)

// RoutePacketClose proves local packet IO closure for one permanently fenced
// instance. It is not the peer's closure, native Gone, or a new admission grant.
type RoutePacketClose struct {
	Cluster                                                       [32]byte
	Reference                                                     ReferenceNeed
	Boot                                                          [32]byte
	Native, Spec                                                  string
	Flows                                                         uint64
	FlowDigest                                                    [32]byte
	JournalSynced                                                 bool
	ReadersStopped, QueueEmpty, AdmissionsStopped, ConntrackEmpty bool
	Signature                                                     []byte
}

func RoutePacketCloseBytes(p RoutePacketClose) []byte {
	p.Signature = nil
	raw, _ := json.Marshal(p)
	return append([]byte("mydc-route-packet-close-1\x00"), raw...)
}

func ownRoutePacketClose(p RoutePacketClose) RoutePacketClose {
	p.Signature = slices.Clone(p.Signature)
	return p
}

func validRoutePacketClose(c ReferenceConsumer, p RoutePacketClose) bool {
	return p.Cluster == c.Local.Cluster && sameReference(p.Reference, referenceNeed(c)) && p.Boot != ([32]byte{}) && p.Native == routeNativeKey(c) && p.Spec == routeSpec(c) && p.Flows <= maxRecords && p.FlowDigest != ([32]byte{}) && p.JournalSynced && p.ReadersStopped && p.QueueEmpty && p.AdmissionsStopped && p.ConntrackEmpty && ed25519.Verify(ed25519.PublicKey(c.Local.Owner[:]), RoutePacketCloseBytes(p), p.Signature)
}

func (m RouteRuntime) flowDigest() [32]byte {
	flows := make([]routeFlowState, 0, len(m.flows))
	for _, pin := range m.pins.Active {
		flows = append(flows, m.flows[pin.Token])
	}
	raw, _ := json.Marshal(flows)
	return sha256.Sum256(append([]byte("mydc-route-closed-flows-1\x00"), raw...))
}

// PacketCloseFacts supplies only original identity/digest. The actual owner
// sets closure flags and signs AFTER fence sync, reader join and kernel census.
func (m RouteRuntime) PacketCloseFacts() (RoutePacketClose, error) {
	if !m.fenced || m.state.Desired.Present || m.packetClose != nil {
		return RoutePacketClose{}, ErrLease
	}
	return RoutePacketClose{Cluster: m.consumer.Local.Cluster, Reference: referenceNeed(m.consumer), Boot: m.boot, Native: routeNativeKey(m.consumer), Spec: routeSpec(m.consumer), Flows: uint64(len(m.flows)), FlowDigest: m.flowDigest()}, nil
}

func (m RouteRuntime) PacketClosure() (RoutePacketClose, bool) {
	if m.packetClose == nil {
		return RoutePacketClose{}, false
	}
	return ownRoutePacketClose(*m.packetClose), true
}

// ClosePackets returns all ORIGINAL local A3 pins in one candidate. Shared
// instance/address coverage remains until native Gone and each owner's normal
// retirement report; no peer closure or global completion is synthesized here.
func (m RouteRuntime) ClosePackets(p RoutePacketClose) (RouteRuntime, error) {
	if !m.fenced || m.state.Desired.Present || !validRoutePacketClose(m.consumer, p) {
		return m, ErrLease
	}
	if m.packetClose != nil {
		if !bytes.Equal(RoutePacketCloseBytes(*m.packetClose), RoutePacketCloseBytes(p)) || !bytes.Equal(m.packetClose.Signature, p.Signature) {
			return m, ErrLease
		}
		return m.clone(), nil
	}
	if p.Boot != m.boot || p.Flows != uint64(len(m.flows)) || p.FlowDigest != m.flowDigest() {
		return m, ErrLease
	}
	pins, err := reconcile.RestoreLeases(m.pins)
	if err != nil {
		return m, err
	}
	q := m.clone()
	var retired []uint64
	for _, f := range m.flows {
		if err := pins.Release(f.Pin); err != nil {
			return m, err
		}
		if f.Remote != nil {
			retired = append(retired, f.Remote.Pin.Token)
		}
	}
	q.closedPeers = closeRoutePins(q.closedPeers, retired)
	if len(q.closedPeers) > maxRecords {
		return m, ErrLease
	}
	q.pins = pins.Checkpoint()
	q.flows = map[uint64]routeFlowState{}
	closed := ownRoutePacketClose(p)
	q.packetClose = &closed
	return q, nil
}
