// SPDX-License-Identifier: Apache-2.0

package network

import (
	"crypto/sha256"
	"encoding/binary"
	"net/netip"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

type RoutePortRange struct{ First, Last uint16 }

// PacketRoutePolicy is an immutable native projection of one approved route.
// User grants, original bindings and durable flow pins remain with their
// existing owners. This port filter cannot authorize a new flow by itself.
type PacketRoutePolicy struct {
	Source, Destination netip.Prefix
	LocalSource         bool
	Protocol            uint8
	Ports               []RoutePortRange
	Bridge              string `json:",omitempty"`
}

func (p PacketRoutePolicy) valid(spec TunnelSpec) bool {
	if p.Bridge != "" && (len(p.Bridge) != 14 || !strings.HasPrefix(p.Bridge, "md") || strings.Trim(p.Bridge[2:], "0123456789abcdef") != "") {
		return false
	}
	if !p.Source.IsValid() || !p.Destination.IsValid() || p.Source != p.Source.Masked() || p.Destination != p.Destination.Masked() || p.Source.Bits() == 0 || p.Destination.Bits() == 0 || !packetAddress(p.Source.Addr()) || !packetAddress(p.Destination.Addr()) || p.Source.Addr().Is4() != p.Destination.Addr().Is4() || p.Source.Overlaps(p.Destination) || p.Protocol != 6 && p.Protocol != 17 || len(p.Ports) == 0 || len(p.Ports) > 64 || len(spec.Addresses) != 0 || len(spec.Routes) != 1 {
		return false
	}
	remote := p.Source
	if p.LocalSource {
		remote = p.Destination
	}
	if spec.Routes[0] != remote {
		return false
	}
	for i, ports := range p.Ports {
		if ports.First == 0 || ports.Last < ports.First || i > 0 && p.Ports[i-1].Last >= ports.First {
			return false
		}
	}
	return true
}

// Both sides share the policy namespace mark; their original local native
// identities own separate tables. Hash collisions are ownership errors.
func routeMark(spec TunnelSpec) uint32 {
	cluster, _, _ := strings.Cut(spec.Owner, "/")
	digest := sha256.Sum256([]byte("mydc-route-mark-1\x00" + cluster + "\x00" + spec.Network))
	return binary.BigEndian.Uint32(digest[:4]) | 0x80000000
}

func routeTable(spec TunnelSpec) int {
	if spec.RoutePolicy == nil || spec.RoutePolicy.Bridge == "" {
		return unix.RT_TABLE_MAIN
	}
	digest := sha256.Sum256([]byte("mydc-route-table-1\x00" + spec.Owner + "\x00" + spec.Network + "\x00" + spec.RoutePolicy.Bridge))
	return int(binary.BigEndian.Uint32(digest[:4])&0x3fffffff | 0x40000000)
}

// direction is shared by the native filter and the packet admission boundary.
// localPacket means bytes leaving the local kernel through this route TUN.
func (p PacketRoutePolicy) direction(localPacket bool) (netip.Prefix, netip.Prefix, bool) {
	if p.LocalSource == localPacket {
		return p.Source, p.Destination, true
	}
	return p.Destination, p.Source, false
}

func (p PacketRoutePolicy) allows(localPacket bool, packet []byte) bool {
	tuple, err := PacketTransport(packet)
	if err != nil || tuple.Protocol != p.Protocol {
		return false
	}
	source, destination, destinationPort := p.direction(localPacket)
	if !source.Contains(tuple.Source) || !destination.Contains(tuple.Destination) {
		return false
	}
	port := tuple.SourcePort
	if destinationPort {
		port = tuple.DestinationPort
	}
	for _, ports := range p.Ports {
		if port >= ports.First && port <= ports.Last {
			return true
		}
	}
	return false
}

// Clone owns all mutable bytes used by a native/packet lifetime.
func (s TunnelSpec) Clone() TunnelSpec {
	s.Addresses = slices.Clone(s.Addresses)
	s.Routes = slices.Clone(s.Routes)
	s.Lifecycle.Proof = slices.Clone(s.Lifecycle.Proof)
	if s.RoutePolicy != nil {
		policy := *s.RoutePolicy
		policy.Ports = slices.Clone(policy.Ports)
		s.RoutePolicy = &policy
	}
	return s
}
