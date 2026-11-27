// SPDX-License-Identifier: Apache-2.0

package services

import (
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/tenancy"
)

// packetTuple uses the same authoritative allocation incarnations as DNS and
// retirement. Packet addresses never create or learn an endpoint reservation.
func packetTuple(a Authority, sender [32]byte, packet []byte) (RouteTuple, network.TransportPacket, error) {
	transport, err := network.PacketTransport(packet)
	if err != nil || sender == ([32]byte{}) {
		return RouteTuple{}, transport, ErrLease
	}
	source, sourceKnown := a.book.AllocationAt(transport.Source)
	destination, destinationKnown := a.book.AllocationAt(transport.Destination)
	if !sourceKnown || !destinationKnown || source.Owner != poolOwner(Source{Owner: sender}) {
		return RouteTuple{}, transport, ErrLease
	}
	return RouteTuple{Source: source, Destination: destination, SourcePort: transport.SourcePort, DestinationPort: transport.DestinationPort, Protocol: transport.Protocol}, transport, nil
}

// BorrowPacket is the actual IP input boundary of the existing flow algorithm.
// The owner must authenticate sender from its exact local Bridge or SFCP peer,
// persist this returned core AND the opposite owner's pin before forwarding.
// A parser call cannot supply either native provenance or durable publication.
func (m RouteRuntime) BorrowPacket(c access.Catalog, n tenancy.Networks, a Authority, peer RouteNativeProof, peerBoot, sender [32]byte, packet []byte, now Clock) (RouteRuntime, RouteFlow, error) {
	if m.consumer.Route == nil || len(packet) > min(m.consumer.Route.Source.MTU, m.consumer.Route.Destination.MTU) {
		return m, RouteFlow{}, ErrLease
	}
	tuple, transport, err := packetTuple(a, sender, packet)
	if err != nil || sender != m.consumer.Route.Source.Owner || transport.Protocol == 6 && transport.TCPFlags&0x17 != 0x02 {
		return m, RouteFlow{}, ErrLease
	}
	return m.BorrowFlow(c, n, a, peer, peerBoot, tuple, now)
}

// AllowsPacketBytes preserves the original opaque pin and exact allocation
// generation for forward and return traffic; reverse packets create no flow.
func (m RouteRuntime) AllowsPacketBytes(c access.Catalog, n tenancy.Networks, a Authority, flow RouteFlow, peerBoot, sender [32]byte, packet []byte, now Clock) bool {
	if m.consumer.Route == nil || len(packet) > min(m.consumer.Route.Source.MTU, m.consumer.Route.Destination.MTU) {
		return false
	}
	tuple, _, err := packetTuple(a, sender, packet)
	return err == nil && m.AllowsPacket(c, n, a, flow, tuple, peerBoot, now)
}

// ExistingPacket resolves retransmissions and replies to their original pin.
// It grants no new lifetime and never adopts a flow from a different peer boot.
func (m RouteRuntime) ExistingPacket(c access.Catalog, n tenancy.Networks, a Authority, peerBoot, sender [32]byte, packet []byte, now Clock) (RouteFlow, error) {
	if m.consumer.Route == nil || len(packet) > min(m.consumer.Route.Source.MTU, m.consumer.Route.Destination.MTU) {
		return RouteFlow{}, ErrLease
	}
	tuple, _, err := packetTuple(a, sender, packet)
	if err != nil {
		return RouteFlow{}, err
	}
	for _, original := range m.flows {
		if tuple != original.Tuple && tuple != reverseTuple(original.Tuple) {
			continue
		}
		flow := RouteFlow{m.consumer.ID, original.Pin, original.Tuple}
		if m.AllowsPacket(c, n, a, flow, tuple, peerBoot, now) {
			return flow, nil
		}
	}
	return RouteFlow{}, ErrLease
}

// AllowsCoordinatedPacket resolves only an existing signed two-owner flow.
// The supplied immutable view must be protected by the actual owner/path's
// current authorization lifetime; this function performs no external IO.
func (m RouteRuntime) AllowsCoordinatedPacket(c access.Catalog, n tenancy.Networks, a Authority, sender [32]byte, packet []byte, now Clock) bool {
	tuple, _, err := packetTuple(a, sender, packet)
	if err != nil {
		return false
	}
	for _, f := range m.flows {
		if tuple == f.Tuple || tuple == reverseTuple(f.Tuple) {
			h := RouteFlow{m.consumer.ID, f.Pin, f.Tuple}
			return m.AllowsCoordinatedPacketBytes(c, n, a, h, f.Peer.Boot, sender, packet, now)
		}
	}
	return false
}
