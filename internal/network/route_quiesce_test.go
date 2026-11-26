// SPDX-License-Identifier: Apache-2.0

package network

import (
	"net"
	"net/netip"
	"testing"

	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
)

func TestRouteConntrackRetirementMatchesOnlyOriginalMarkAndPolicyTuple(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		spec := routeTunnelSpec(true)
		source, destination := "10.1.0.10", "10.2.0.10"
		foreign := "10.3.0.10"
		if ipv6 {
			source, destination, foreign = "fd00:1::10", "fd00:2::10", "fd00:3::10"
			spec.RoutePolicy.Source = netip.MustParsePrefix("fd00:1::/64")
			spec.RoutePolicy.Destination = netip.MustParsePrefix("fd00:2::/64")
		}
		filter := routeConntrackFilter{spec}
		original := netlink.ConntrackFlow{Mark: routeMark(spec), Forward: netlink.IPTuple{SrcIP: net.ParseIP(source), DstIP: net.ParseIP(destination), SrcPort: 41000, DstPort: 3306, Protocol: 6}, Reverse: netlink.IPTuple{SrcIP: net.ParseIP(destination), DstIP: net.ParseIP(source), SrcPort: 3306, DstPort: 41000, Protocol: 6}}
		if !filter.MatchConntrackFlow(&original) {
			t.Fatal("original marked request/reply was not retired", ipv6)
		}
		for _, mutate := range []func(*netlink.ConntrackFlow){
			func(p *netlink.ConntrackFlow) { p.Mark++ },
			func(p *netlink.ConntrackFlow) { p.Forward.Protocol, p.Reverse.Protocol = 17, 17 },
			func(p *netlink.ConntrackFlow) { p.Forward.DstPort, p.Reverse.SrcPort = 3307, 3307 },
			func(p *netlink.ConntrackFlow) {
				p.Forward.SrcIP, p.Reverse.DstIP = net.ParseIP(foreign), net.ParseIP(foreign)
			},
			func(p *netlink.ConntrackFlow) {
				p.Forward.DstIP, p.Reverse.SrcIP = net.ParseIP(foreign), net.ParseIP(foreign)
			},
		} {
			other := original
			mutate(&other)
			if filter.MatchConntrackFlow(&other) {
				t.Fatal("conntrack retirement adopted a foreign mark/protocol/port/CIDR", ipv6)
			}
		}
		if filter.MatchConntrackFlow(nil) {
			t.Fatal("nil conntrack row was treated as owned")
		}
	}
}

func TestRouteFencedNativeModeDropsDataAndCannotCreateConntrack(t *testing.T) {
	for _, source := range []bool{false, true} {
		spec := routeTunnelSpec(source)
		spec.RoutePolicy.Bridge = "md0123456789ab"
		id := tunnelIdentity{name: "owned-tun", alias: "owned-alias", table: "owned-table"}
		fenced := tunnelRulesMode(spec, id, true)
		for _, name := range []string{"from", "to"} {
			if len(fenced.rules[name]) != 1 || len(fenced.rules[name][0].Exprs) != 1 {
				t.Fatal("fenced TUN retained an accepting data rule", name)
			}
			verdict, ok := fenced.rules[name][0].Exprs[0].(*expr.Verdict)
			if !ok || verdict.Kind != expr.VerdictDrop {
				t.Fatal("fenced TUN did not drop all original data", name)
			}
		}
		// Only existing original ct marks from the exact Bridge may still
		// select the now dropping TUN; no NEW/zero-mark or TUN injection rule.
		if len(fenced.rules["select"]) != len(spec.RoutePolicy.Ports)+1 {
			t.Fatal("fenced selector retained new/injected admission rules")
		}
		for _, rule := range fenced.rules["select"] {
			for _, expression := range rule.Exprs {
				if ct, ok := expression.(*expr.Ct); ok && ct.Key == expr.CtKeySTATE {
					t.Fatal("fenced selector retained new-connection admission")
				}
			}
		}
	}
}
