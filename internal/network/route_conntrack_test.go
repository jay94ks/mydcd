// SPDX-License-Identifier: Apache-2.0

package network

import (
	"net"
	"net/netip"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestIndividualRouteConntrackFilterPreservesOtherTuplesMarksAndDirections(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		for _, protocol := range []uint8{6, 17} {
			spec := routeTunnelSpec(true)
			spec.RoutePolicy.Protocol = protocol
			source, destination := "10.1.0.10", "10.2.0.10"
			if ipv6 {
				source, destination = "fd00:1::10", "fd00:2::10"
				spec.RoutePolicy.Source = netip.MustParsePrefix("fd00:1::/64")
				spec.RoutePolicy.Destination = netip.MustParsePrefix("fd00:2::/64")
			}
			tuple := TransportPacket{Source: netip.MustParseAddr(source), Destination: netip.MustParseAddr(destination), SourcePort: 41000, DestinationPort: 3306, Protocol: protocol}
			filter := routeFlowConntrackFilter{spec, tuple}
			original := netlink.ConntrackFlow{Mark: routeMark(spec), Forward: netlink.IPTuple{SrcIP: net.ParseIP(source), DstIP: net.ParseIP(destination), SrcPort: 41000, DstPort: 3306, Protocol: protocol}, Reverse: netlink.IPTuple{SrcIP: net.ParseIP(destination), DstIP: net.ParseIP(source), SrcPort: 3306, DstPort: 41000, Protocol: protocol}}
			if !filter.MatchConntrackFlow(&original) {
				t.Fatal("exact original conntrack did not match", ipv6, protocol)
			}
			for _, direction := range []netlink.IPTuple{original.Forward, original.Reverse} {
				if actual, ok := routeConntrackTuple(spec, direction); !ok || actual != tuple {
					t.Fatal("kernel direction changed canonical tuple", ipv6, protocol, actual)
				}
			}
			// One exact direction still identifies a NATed original flow.
			nat := original
			nat.Forward.SrcIP = net.ParseIP("192.0.2.3")
			if !filter.MatchConntrackFlow(&nat) {
				t.Fatal("exact reverse tuple was lost behind NAT")
			}
			for _, mutate := range []func(*netlink.ConntrackFlow){
				func(f *netlink.ConntrackFlow) { f.Mark++ },
				func(f *netlink.ConntrackFlow) { f.Forward.SrcPort++; f.Reverse.DstPort++ },
				func(f *netlink.ConntrackFlow) { f.Forward.DstPort++; f.Reverse.SrcPort++ },
				func(f *netlink.ConntrackFlow) { f.Forward.Protocol++; f.Reverse.Protocol++ },
				func(f *netlink.ConntrackFlow) {
					f.Forward.SrcIP = net.ParseIP("192.0.2.4")
					f.Reverse.DstIP = net.ParseIP("192.0.2.4")
				},
			} {
				other := original
				mutate(&other)
				if filter.MatchConntrackFlow(&other) {
					t.Fatal("per-flow deletion included foreign tuple/mark", ipv6, protocol)
				}
			}
			if filter.MatchConntrackFlow(nil) {
				t.Fatal("nil conntrack row was owned")
			}
		}
	}
}
