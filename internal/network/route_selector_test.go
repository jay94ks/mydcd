// SPDX-License-Identifier: Apache-2.0

package network

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"testing"

	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func selectedRouteSpec() TunnelSpec {
	spec := routeTunnelSpec(true)
	spec.Owner, spec.RoutePolicy.Bridge = "cluster/node-a", "md0123456789ab"
	return spec
}

func TestRouteSelectorSeparatesSameCIDRPoliciesAndPinsBridgeDirection(t *testing.T) {
	first := selectedRouteSpec()
	second := first.Clone()
	second.Network += "/second"
	second.RoutePolicy.Ports = []RoutePortRange{{First: 443, Last: 443}}
	if routeTable(first) == unix.RT_TABLE_MAIN || routeTable(first) == routeTable(second) || routeMark(first) == routeMark(second) {
		t.Fatal("same CIDR policies share a main/native selection identity")
	}
	peer := first.Clone()
	peer.Owner, peer.RoutePolicy.Bridge, peer.RoutePolicy.LocalSource = "cluster/node-b", "mdabcdef012345", false
	peer.Routes[0] = peer.RoutePolicy.Source
	if routeMark(peer) != routeMark(first) || routeTable(peer) == routeTable(first) {
		t.Fatal("both sides lost shared policy mark or separate native tables")
	}
	rule := routeSelectorRule(first)
	if rule.Mark != routeMark(first) || rule.Mask == nil || *rule.Mask != ^uint32(0) || rule.IifName != first.RoutePolicy.Bridge || rule.Src.String() != first.RoutePolicy.Source.String() || rule.Dst.String() != first.RoutePolicy.Destination.String() || rule.Table != routeTable(first) || rule.Protocol != unix.RTPROT_STATIC {
		t.Fatal("RPDB selection escaped original Bridge/prefix/mark")
	}
	legacy := first.Clone()
	legacy.RoutePolicy.Bridge = ""
	if hasRouteSelector(legacy) || routeTable(legacy) != unix.RT_TABLE_MAIN {
		t.Fatal("legacy exact native spec was reinterpreted as a new selector")
	}
	guard := routeSelectorGuard(first)
	if guard.Type != unix.RTN_UNREACHABLE || guard.Table != rule.Table || guard.Dst.String() != "0.0.0.0/0" || guard.Priority != first.RouteMetric {
		t.Fatal("partial native table could fall through to main")
	}
}

func TestRouteSelectorRejectsForeignMarkScopeAndKeepsOtherBridges(t *testing.T) {
	want := routeSelectorRule(selectedRouteSpec())
	foreign := want
	foreign.Table++
	if !markedRuleConflicts(foreign, want) {
		t.Fatal("foreign table hijacked the original marked scope")
	}
	foreign.IifName = "mdabcdef012345"
	if markedRuleConflicts(foreign, want) {
		t.Fatal("another original Bridge's selector was treated as this owner's")
	}
	foreign.IifName = ""
	if !markedRuleConflicts(foreign, want) {
		t.Fatal("unbounded foreign marked rule bypassed original Bridge selection")
	}
	plain := *netlink.NewRule()
	plain.Table, plain.Priority = unix.RT_TABLE_MAIN, 32766
	if markedRuleConflicts(plain, want) {
		t.Fatal("default main rule was claimed as an owned selector")
	}
}

func TestIPv6SelectorGuardRecognizesKernelLoopbackAndRejectsForeignOutput(t *testing.T) {
	spec := selectedRouteSpec()
	spec.RoutePolicy.Source = netip.MustParsePrefix("fd00:249:125::/64")
	want := routeSelectorGuard(spec)
	observed := want
	observed.LinkIndex = 1
	if !sameSelectorGuard(observed, want) {
		t.Fatal("IPv6 unreachable default lost its kernel loopback readback")
	}
	observed.LinkIndex = 7
	if sameSelectorGuard(observed, want) {
		t.Fatal("foreign output link was accepted as the unreachable guard")
	}
	observed.LinkIndex, observed.Type = 1, unix.RTN_UNICAST
	if sameSelectorGuard(observed, want) {
		t.Fatal("unicast loopback route replaced the unreachable guard")
	}
	observed = routeSelectorGuard(selectedRouteSpec())
	want = observed
	observed.LinkIndex = 1
	if sameSelectorGuard(observed, want) {
		t.Fatal("IPv6-only canonicalization changed IPv4 ownership")
	}
}

func TestConntrackSetterCodecRetainsExactSourceRegisterForNativeReadback(t *testing.T) {
	for _, register := range []uint32{1, 3} {
		want := &expr.Ct{Key: expr.CtKeyMARK, Register: register, SourceRegister: true}
		raw, err := expr.MarshalExprData(unix.NFPROTO_INET, want)
		if err != nil {
			t.Fatal(err)
		}
		var got expr.Ct
		if err := expr.Unmarshal(unix.NFPROTO_INET, raw, &got); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(want, &got) {
			t.Fatal("conntrack native readback discarded setter register", want, got)
		}
	}
}

func TestRouteSelectorFirewallSeparatesNewRequestsFromRepliesAndInjectedPackets(t *testing.T) {
	for _, source := range []bool{true, false} {
		spec := selectedRouteSpec()
		spec.RoutePolicy.LocalSource = source
		if !source {
			spec.Routes[0] = spec.RoutePolicy.Source
		}
		firewall := tunnelRules(spec, tunnelIdentity{name: "owned-tun", alias: "owned-alias", table: "owned-table"})
		ports := len(spec.RoutePolicy.Ports)
		wantRules := 3*ports + 1
		if source {
			wantRules += ports
		}
		if len(firewall.rules["select"]) != wantRules {
			t.Fatal("unexpected request/reply selection surface", source)
		}
		var packetMarks, ctSets, newStates int
		for _, rule := range firewall.rules["select"] {
			for _, expression := range rule.Exprs {
				if meta, ok := expression.(*expr.Meta); ok && meta.Key == expr.MetaKeyMARK && meta.SourceRegister {
					packetMarks++
				}
				if ct, ok := expression.(*expr.Ct); ok {
					if ct.Key == expr.CtKeyMARK && ct.SourceRegister {
						ctSets++
					}
					if ct.Key == expr.CtKeySTATE {
						newStates++
					}
				}
			}
		}
		expectedMarks := wantRules - 1
		if packetMarks != expectedMarks || ctSets != wantRules-1 || newStates != btoi(source)*ports {
			t.Fatal("original request/reply/injection mark or NEW admission scope changed")
		}
		raw, err := json.Marshal(spec)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeTunnel(string(raw)); err != nil {
			t.Fatal(err)
		}
	}
}

func btoi(value bool) int {
	if value {
		return 1
	}
	return 0
}
