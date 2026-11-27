// SPDX-License-Identifier: Apache-2.0

package services

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"slices"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/tenancy"
)

// RouteFlowReceipt is published by the native owner only AFTER the original
// flow checkpoint has been durably stored. It is not a Raft grant or a close
// proof. Source receipts have no PeerPin; destination receipts acknowledge the
// exact source pin, without replacing either side's lifetime.
type RouteFlowReceipt struct {
	Cluster       [32]byte
	Reference     ReferenceNeed
	Boot          [32]byte
	Pin           reconcile.Lease
	Tuple         [32]byte
	Peer          ReferenceNeed
	PeerBoot      [32]byte
	PeerPin       reconcile.Lease
	JournalSynced bool
	Signature     []byte
}

func RouteFlowReceiptBytes(p RouteFlowReceipt) []byte {
	p.Signature = nil
	raw, _ := json.Marshal(p)
	return append([]byte("sfc-route-flow-receipt-1\x00"), raw...)
}

func ownRouteFlowReceipt(p RouteFlowReceipt) RouteFlowReceipt {
	p.Signature = slices.Clone(p.Signature)
	return p
}

func validPeerFlowReceipt(c ReferenceConsumer, f routeFlowState, p RouteFlowReceipt) bool {
	peer, ok := peerProjection(c, f.Peer.Reference)
	if !ok || f.Boot == ([32]byte{}) || p.Cluster != c.Local.Cluster || !sameReference(p.Reference, f.Peer.Reference) || p.Boot != f.Peer.Boot || p.Pin.Generation != peer.Generation || p.Pin.Token == 0 || p.Tuple != tupleHash(f.Tuple) || !sameReference(p.Peer, referenceNeed(c)) || p.PeerBoot != f.Boot || !p.JournalSynced {
		return false
	}
	if c.Route.Side == c.Route.Policy.Source.Tenant {
		if p.PeerPin != f.Pin {
			return false
		}
	} else if p.PeerPin != (reconcile.Lease{}) {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(peer.Local.Owner[:]), RouteFlowReceiptBytes(p), p.Signature)
}

// OriginalFlow recovers an opaque handle, including a pending handshake. It
// grants no admission: callers still need current policy/native/peer checks.
func (m RouteRuntime) OriginalFlow(tuple RouteTuple) (RouteFlow, bool) {
	for _, f := range m.flows {
		if f.Tuple == tuple {
			return RouteFlow{m.consumer.ID, f.Pin, f.Tuple}, true
		}
	}
	return RouteFlow{}, false
}

// FlowReceiptFacts never claims a successful store write. The actual adapter
// must sync this core before setting JournalSynced and signing these facts.
func (m RouteRuntime) FlowReceiptFacts(h RouteFlow) (RouteFlowReceipt, error) {
	f, ok := m.flow(h)
	if !ok || f.Boot != m.boot || !m.nativeReady() {
		return RouteFlowReceipt{}, ErrLease
	}
	p := RouteFlowReceipt{Cluster: m.consumer.Local.Cluster, Reference: referenceNeed(m.consumer), Boot: f.Boot, Pin: f.Pin, Tuple: tupleHash(f.Tuple), Peer: f.Peer.Reference, PeerBoot: f.Peer.Boot}
	if m.consumer.Route.Side != m.consumer.Route.Policy.Source.Tenant {
		if f.Remote == nil || !validPeerFlowReceipt(m.consumer, f, *f.Remote) {
			return RouteFlowReceipt{}, ErrLease
		}
		p.PeerPin = f.Remote.Pin
	}
	return p, nil
}

// RecordPeerFlow binds one immutable opposite-owner receipt to this ORIGINAL
// pin. A lost response can be replayed; a different pin or boot cannot replace
// the first receipt. The returned candidate must be synced before packet IO.
func (m RouteRuntime) RecordPeerFlow(c access.Catalog, n tenancy.Networks, a Authority, h RouteFlow, p RouteFlowReceipt, now Clock) (RouteRuntime, error) {
	f, ok := m.flow(h)
	if !ok || f.Boot != m.boot || closedRoutePin(m.closedPeers, p.Pin.Token) || !m.AllowsPacket(c, n, a, h, f.Tuple, p.Boot, now) || !validPeerFlowReceipt(m.consumer, f, p) {
		return m, ErrLease
	}
	if f.Remote != nil {
		if !bytes.Equal(RouteFlowReceiptBytes(*f.Remote), RouteFlowReceiptBytes(p)) || !bytes.Equal(f.Remote.Signature, p.Signature) {
			return m, ErrLease
		}
		return m.clone(), nil
	}
	q := m.clone()
	f = q.flows[f.Pin.Token]
	owned := ownRouteFlowReceipt(p)
	f.Remote = &owned
	q.flows[f.Pin.Token] = f
	q.floors(c, n, a)
	return q, nil
}

// AllowsCoordinatedPacketBytes is the actual packet adapter gate. The older
// one-sided model API does not establish the opposite owner's durable pin.
func (m RouteRuntime) AllowsCoordinatedPacketBytes(c access.Catalog, n tenancy.Networks, a Authority, h RouteFlow, peerBoot, sender [32]byte, packet []byte, now Clock) bool {
	f, ok := m.flow(h)
	return ok && f.Boot == m.boot && f.Remote != nil && validPeerFlowReceipt(m.consumer, f, *f.Remote) && m.AllowsPacketBytes(c, n, a, h, peerBoot, sender, packet, now)
}
