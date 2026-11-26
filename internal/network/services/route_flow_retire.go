// SPDX-License-Identifier: Apache-2.0

package services

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
)

// RoutePeerFlowClose is a permanent tombstone for the exact original source
// claim. Boot identifies that claim's ORIGINAL destination boot, not the boot
// that happened to perform cleanup. A replay therefore signs identical facts.
type RoutePeerFlowClose struct {
	Cluster                                       [32]byte
	Reference                                     ReferenceNeed
	Boot                                          [32]byte
	Claim                                         RouteFlowReceipt
	JournalSynced, Stopped, NoPending, Tombstoned bool
	Signature                                     []byte
}

func RoutePeerFlowCloseBytes(p RoutePeerFlowClose) []byte {
	p.Signature = nil
	raw, _ := json.Marshal(p)
	return append([]byte("mydc-route-peer-flow-close-1\x00"), raw...)
}

func sameRouteFlowClaim(a, b RouteFlowReceipt) bool {
	return bytes.Equal(RouteFlowReceiptBytes(a), RouteFlowReceiptBytes(b)) && bytes.Equal(a.Signature, b.Signature)
}

// ClosingSourceClaimFacts reconstructs original identity after restart; it
// neither reauthorizes an old boot nor claims a successful journal readback.
func (m RouteRuntime) ClosingSourceClaimFacts(h RouteFlow) (RouteFlowReceipt, error) {
	f, ok := m.flow(h)
	if !ok || !f.Closing || !f.Tracked || f.Boot == ([32]byte{}) || m.consumer.Route.Side != m.consumer.Route.Policy.Source.Tenant {
		return RouteFlowReceipt{}, ErrLease
	}
	return RouteFlowReceipt{Cluster: m.consumer.Local.Cluster, Reference: referenceNeed(m.consumer), Boot: f.Boot, Pin: f.Pin, Tuple: tupleHash(f.Tuple), Peer: f.Peer.Reference, PeerBoot: f.Peer.Boot}, nil
}

func (m RouteRuntime) validSourceCloseClaim(a Authority, claim RouteFlowReceipt, tuple RouteTuple) bool {
	if m.consumer.Route == nil || m.consumer.Route.Side == m.consumer.Route.Policy.Source.Tenant || a.cluster != m.consumer.Local.Cluster || claim.Cluster != a.cluster || !sameReference(claim.Peer, referenceNeed(m.consumer)) || claim.Boot == ([32]byte{}) || claim.PeerBoot == ([32]byte{}) || claim.Pin.Token == 0 || claim.Pin.Generation != claim.Reference.Generation || claim.PeerPin.Token != 0 || claim.PeerPin.Generation != 0 || !claim.JournalSynced || claim.Tuple != tupleHash(tuple) || !validOriginalTuple(*m.consumer.Route, tuple) {
		return false
	}
	peer, ok := peerProjection(m.consumer, claim.Reference)
	shared, known := a.ReferenceConsumer(claim.Reference.Consumer)
	return ok && known && sameReference(referenceNeed(shared), claim.Reference) && shared.DesiredSource == peer.DesiredSource && shared.DesiredHash == peer.DesiredHash && shared.Route != nil && shared.Route.Side == peer.Route.Side && ed25519.Verify(ed25519.PublicKey(peer.Local.Owner[:]), RouteFlowReceiptBytes(claim), claim.Signature)
}

// BeginPeerFlowClose preserves the original destination pin, or atomically
// seals a never-admitted source token. It does not close another pin/tuple.
func (m RouteRuntime) BeginPeerFlowClose(a Authority, claim RouteFlowReceipt, tuple RouteTuple) (RouteRuntime, RouteFlow, error) {
	if !m.validSourceCloseClaim(a, claim, tuple) {
		return m, RouteFlow{}, ErrLease
	}
	for _, f := range m.flows {
		if f.Remote != nil && f.Remote.Pin == claim.Pin {
			if f.Tuple != tuple || !sameRouteFlowClaim(*f.Remote, claim) {
				return m, RouteFlow{}, ErrLease
			}
			h := RouteFlow{m.consumer.ID, f.Pin, f.Tuple}
			q, err := m.BeginFlowClose(h)
			return q, h, err
		}
		if f.Tuple == tuple && f.Remote == nil {
			return m, RouteFlow{}, ErrLease
		} // Legacy/unknown is not never-admitted.
	}
	if m.fenced && m.packetClose != nil {
		return m.clone(), RouteFlow{}, nil
	} // Permanent instance closure dominates every late claim.
	q := m.clone()
	q.closedPeers = closeRoutePin(q.closedPeers, claim.Pin.Token)
	if len(q.closedPeers) > maxRecords {
		return m, RouteFlow{}, ErrLease
	}
	return q, RouteFlow{}, nil
}

func (m RouteRuntime) FinishPeerFlowClose(a Authority, h RouteFlow, claim RouteFlowReceipt, local RouteFlowClose) (RouteRuntime, error) {
	f, ok := m.flow(h)
	if !ok || !f.Closing || f.Remote == nil || !m.validSourceCloseClaim(a, claim, f.Tuple) || !sameRouteFlowClaim(*f.Remote, claim) {
		return m, ErrLease
	}
	return m.ReleaseFlow(h, local)
}

func (m RouteRuntime) PeerFlowCloseFacts(a Authority, claim RouteFlowReceipt, tuple RouteTuple) (RoutePeerFlowClose, error) {
	if !m.validSourceCloseClaim(a, claim, tuple) || !closedRoutePin(m.closedPeers, claim.Pin.Token) && !(m.fenced && m.packetClose != nil) {
		return RoutePeerFlowClose{}, ErrLease
	}
	for _, f := range m.flows {
		if f.Remote != nil && f.Remote.Pin == claim.Pin {
			return RoutePeerFlowClose{}, ErrLease
		}
	}
	return RoutePeerFlowClose{Cluster: m.consumer.Local.Cluster, Reference: referenceNeed(m.consumer), Boot: claim.PeerBoot, Claim: ownRouteFlowReceipt(claim)}, nil
}

// FinishSourceFlowClose requires BOTH its own native/IO closure and the peer's
// durable original-source tombstone. Neither timeout nor peer absence suffices.
func (m RouteRuntime) FinishSourceFlowClose(h RouteFlow, local RouteFlowClose, peer RoutePeerFlowClose) (RouteRuntime, error) {
	f, ok := m.flow(h)
	if !ok || !f.Closing || !f.Tracked || m.consumer.Route.Side != m.consumer.Route.Policy.Source.Tenant {
		return m, ErrLease
	}
	want, err := m.ClosingSourceClaimFacts(h)
	if err != nil {
		return m, err
	}
	want.JournalSynced = true
	if peer.Cluster != m.consumer.Local.Cluster || !sameReference(peer.Reference, f.Peer.Reference) || peer.Boot != f.Peer.Boot || !peer.JournalSynced || !peer.Stopped || !peer.NoPending || !peer.Tombstoned || !bytes.Equal(RouteFlowReceiptBytes(want), RouteFlowReceiptBytes(peer.Claim)) || !ed25519.Verify(ed25519.PublicKey(m.consumer.Local.Owner[:]), RouteFlowReceiptBytes(peer.Claim), peer.Claim.Signature) || !ed25519.Verify(ed25519.PublicKey(f.Peer.Reference.Owner[:]), RoutePeerFlowCloseBytes(peer), peer.Signature) {
		return m, ErrLease
	}
	return m.ReleaseFlow(h, local)
}

// FlowCloseFacts is unsigned. Only the actual owner can establish a completed
// packet barrier and exact native drain before setting flags and signing.
func (m RouteRuntime) FlowCloseFacts(h RouteFlow) (RouteFlowClose, error) {
	f, ok := m.flow(h)
	if !ok || !f.Closing {
		return RouteFlowClose{}, ErrLease
	}
	return RouteFlowClose{Cluster: m.consumer.Local.Cluster, Reference: referenceNeed(m.consumer), Boot: m.boot, Pin: f.Pin, Tuple: tupleHash(f.Tuple), Native: routeNativeKey(m.consumer) + "/flow/" + generationText(f.Pin.Token)}, nil
}
