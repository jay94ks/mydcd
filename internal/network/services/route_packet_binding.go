// SPDX-License-Identifier: Apache-2.0

package services

import (
	"crypto/sha256"
	"encoding/json"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/tenancy"
)

// Both directions and both owners hash the same source->destination original
// pin pair. No tuple-only packet can acquire a later flow's incarnation.
func (m RouteRuntime) packetToken(f routeFlowState) [16]byte {
	source, destination := referenceNeed(m.consumer), f.Peer.Reference
	sourceBoot, destinationBoot := f.Boot, f.Peer.Boot
	sourcePin, destinationPin := f.Pin, f.Remote.Pin
	if m.consumer.Route.Side != m.consumer.Route.Policy.Source.Tenant {
		source, destination = destination, source
		sourceBoot, destinationBoot = destinationBoot, sourceBoot
		sourcePin, destinationPin = destinationPin, sourcePin
	}
	raw, _ := json.Marshal(struct {
		Cluster                     [32]byte
		Source, Destination         ReferenceNeed
		SourceBoot, DestinationBoot [32]byte
		SourcePin, DestinationPin   reconcile.Lease
		Tuple                       [32]byte
	}{m.consumer.Local.Cluster, source, destination, sourceBoot, destinationBoot, sourcePin, destinationPin, tupleHash(f.Tuple)})
	digest := sha256.Sum256(append([]byte("sfc-route-packet-1\x00"), raw...))
	return [16]byte(digest[:16])
}

func (m RouteRuntime) PacketBinding(c access.Catalog, n tenancy.Networks, a Authority, sender [32]byte, packet []byte, now Clock) (network.PacketBinding, bool) {
	tuple, _, err := packetTuple(a, sender, packet)
	if err != nil {
		return network.PacketBinding{}, false
	}
	for _, f := range m.flows {
		if tuple != f.Tuple && tuple != reverseTuple(f.Tuple) {
			continue
		}
		handle := RouteFlow{m.consumer.ID, f.Pin, f.Tuple}
		if !m.AllowsCoordinatedPacketBytes(c, n, a, handle, f.Peer.Boot, sender, packet, now) {
			return network.PacketBinding{}, false
		}
		owner := m.consumer.Route.Destination.Owner
		if tuple.Destination == f.Tuple.Source {
			owner = m.consumer.Route.Source.Owner
		}
		name := routePacketNetwork(m.consumer)
		endpoint := network.Endpoint{Owner: owner, Network: network.NetworkID(m.consumer.Local.Cluster, name), ID: network.EndpointID(m.consumer.Local.Cluster, name, tuple.Destination.Owner, tuple.Destination.Endpoint, tuple.Destination.Generation, tuple.Destination.Address), Address: tuple.Destination.Address}
		return network.PacketBinding{Token: m.packetToken(f), Endpoint: endpoint}, true
	}
	return network.PacketBinding{}, false
}
