// SPDX-License-Identifier: Apache-2.0

package network

import (
	"errors"
	"net"
	"os"
	"reflect"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const routeRulePriority = 10000

func hasRouteSelector(s TunnelSpec) bool { return s.RoutePolicy != nil && s.RoutePolicy.Bridge != "" }

// Source validation reverses the packet's addresses and uses its output
// Bridge for the lookup. The original mark must participate in that lookup,
// without disabling rp_filter or changing another interface's configuration.
// Callers have already checked this exact TUN's type/name/ownership alias.
func routeSourceValidation(s TunnelSpec, id tunnelIdentity, configure bool) error {
	if !hasRouteSelector(s) || !s.RoutePolicy.Source.Addr().Is4() {
		return nil
	}
	path := "/proc/sys/net/ipv4/conf/" + id.name + "/src_valid_mark"
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	value := strings.TrimSpace(string(raw))
	if value == "0" && configure {
		if err := os.WriteFile(path, []byte("1\n"), 0600); err != nil {
			return err
		}
		raw, err = os.ReadFile(path)
		if err != nil {
			return err
		}
		value = strings.TrimSpace(string(raw))
	}
	if value != "1" {
		return ErrKernelOwnership
	}
	return nil
}

func routeSelectorRule(s TunnelSpec) netlink.Rule {
	p := s.RoutePolicy
	source, destination, _ := p.direction(true)
	rule := netlink.NewRule()
	rule.Family = unix.AF_INET6
	if source.Addr().Is4() {
		rule.Family = unix.AF_INET
	}
	mask := ^uint32(0)
	rule.Priority, rule.Table, rule.Mark, rule.Mask = routeRulePriority, routeTable(s), routeMark(s), &mask
	rule.IifName, rule.Src, rule.Dst, rule.Protocol = p.Bridge, prefixNet(source), prefixNet(destination), unix.RTPROT_STATIC
	return *rule
}

// The guard prevents an incomplete owned table from falling through to main.
func routeSelectorGuard(s TunnelSpec) netlink.Route {
	family := unix.AF_INET6
	bits := 128
	if s.RoutePolicy.Source.Addr().Is4() {
		family, bits = unix.AF_INET, 32
	}
	return netlink.Route{Family: family, Dst: &net.IPNet{IP: make(net.IP, bits/8), Mask: net.CIDRMask(0, bits)}, Table: routeTable(s), Protocol: unix.RTPROT_STATIC, Scope: netlink.SCOPE_UNIVERSE, Type: unix.RTN_UNREACHABLE, Priority: s.RouteMetric}
}

func sameSelectorGuard(got, want netlink.Route) bool {
	// IPv6 materializes an unreachable default on the namespace's loopback
	// (Linux LOOPBACK_IFINDEX=1), even when RouteAdd supplied no output link.
	if got.Family == unix.AF_INET6 && got.LinkIndex == 1 {
		got.LinkIndex = 0
	}
	return got.Family == want.Family && (got.Dst == nil || got.Dst.String() == want.Dst.String()) && got.Table == want.Table && got.LinkIndex == 0 && got.Protocol == want.Protocol && got.Scope == want.Scope && got.Type == want.Type && got.Priority == want.Priority && len(got.Gw) == 0 && len(got.MultiPath) == 0 && got.MTU == 0
}

// inspectRouteSelector rejects foreign rules/routes before either adoption or
// removal. It never repairs by deleting a rule or flushing someone else's table.
func inspectRouteSelector(s TunnelSpec, link netlink.Link) (rulePresent, guardPresent bool, err error) {
	if !hasRouteSelector(s) {
		return false, false, nil
	}
	want := routeSelectorRule(s)
	rules, err := netlink.RuleList(want.Family)
	if err != nil {
		return false, false, err
	}
	for _, got := range rules {
		if got.Table == want.Table {
			if rulePresent || !reflect.DeepEqual(got, want) {
				return false, false, ErrKernelOwnership
			}
			rulePresent = true
			continue
		}
		if markedRuleConflicts(got, want) {
			return false, false, ErrKernelOwnership
		}
	}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: want.Table}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return false, false, err
	}
	remotePresent := false
	for _, got := range routes {
		if sameSelectorGuard(got, routeSelectorGuard(s)) {
			if guardPresent {
				return false, false, ErrKernelOwnership
			}
			guardPresent = true
			continue
		}
		if link == nil || remotePresent || !sameRoute(got, routeFor(link, s.Routes[0], s)) {
			return false, false, ErrKernelOwnership
		}
		remotePresent = true
	}
	return rulePresent, guardPresent, nil
}

func markedRuleConflicts(got, want netlink.Rule) bool {
	if got.Mark == 0 && got.Mask == nil {
		return false
	}
	mask := ^uint32(0)
	if got.Mask != nil {
		mask = *got.Mask
	}
	if mask == 0 || got.Mark&mask != want.Mark&mask || got.IifName != "" && got.IifName != want.IifName {
		return false
	}
	for _, pair := range [][2]*net.IPNet{{got.Src, want.Src}, {got.Dst, want.Dst}} {
		if pair[0] != nil && pair[1] != nil && !pair[0].Contains(pair[1].IP) && !pair[1].Contains(pair[0].IP) {
			return false
		}
	}
	return true
}

func ensureRouteSelector(s TunnelSpec, link netlink.Link) error {
	if !hasRouteSelector(s) {
		return nil
	}
	rulePresent, guardPresent, err := inspectRouteSelector(s, link)
	if err != nil {
		return err
	}
	if !guardPresent {
		guard := routeSelectorGuard(s)
		if err := netlink.RouteAdd(&guard); err != nil {
			return err
		}
	}
	if !rulePresent {
		rule := routeSelectorRule(s)
		if err := netlink.RuleAdd(&rule); err != nil {
			return err
		}
	}
	rulePresent, guardPresent, err = inspectRouteSelector(s, link)
	if err != nil || !rulePresent || !guardPresent {
		return errors.Join(err, ErrKernelOwnership)
	}
	return nil
}

func removeRouteSelector(s TunnelSpec) error {
	if !hasRouteSelector(s) {
		return nil
	}
	rulePresent, guardPresent, err := inspectRouteSelector(s, nil)
	if err != nil {
		return err
	}
	if rulePresent {
		rule := routeSelectorRule(s)
		if err := netlink.RuleDel(&rule); err != nil {
			return err
		}
	}
	if guardPresent {
		guard := routeSelectorGuard(s)
		if err := netlink.RouteDel(&guard); err != nil {
			return err
		}
	}
	return nil
}
