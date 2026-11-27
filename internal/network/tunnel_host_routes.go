// SPDX-License-Identifier: Apache-2.0

package network

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Every TUN of a server carries the same server address, so the main-table
// /32 of a remote server belongs to the sfc-system TUN alone. A tenant TUN
// still has to carry replies from its containers to a remote server's host
// Ingress (whose connections come from that server's address). Those routes
// go in the tenant TUN's own host table, and one rule per local pool sends
// only packets from that pool there. A packet from anywhere else, the host
// included, never sees the table and keeps using the main table.

const hostRulePriority = 10100

func validHostRoutes(s TunnelSpec) bool {
	if len(s.HostRoutes) == 0 {
		return len(s.HostSources) == 0
	}
	if s.RoutePolicy != nil || len(s.HostRoutes) > 64 || len(s.HostSources) == 0 || len(s.HostSources) > 8 {
		return false
	}
	for _, list := range [][]netip.Prefix{s.HostRoutes, s.HostSources} {
		previous := ""
		for _, p := range list {
			if !p.IsValid() || !packetAddress(p.Addr()) || p != p.Masked() || p.Bits() == 0 || p.String() <= previous {
				return false
			}
			previous = p.String()
		}
	}
	for _, p := range s.HostRoutes {
		if p.Bits() != p.Addr().BitLen() || slices.ContainsFunc(s.Routes, p.Overlaps) || slices.ContainsFunc(s.HostSources, p.Overlaps) {
			return false
		}
	}
	return true
}

// Overlay is every remote prefix the plane, firewall and topology route
// through this TUN: Routes and HostRoutes, sorted.
func (s TunnelSpec) Overlay() []netip.Prefix {
	out := append(slices.Clone(s.Routes), s.HostRoutes...)
	slices.SortFunc(out, func(a, b netip.Prefix) int { return strings.Compare(a.String(), b.String()) })
	return out
}

func hostTable(s TunnelSpec) int {
	digest := sha256.Sum256([]byte("sfc-host-table-1\x00" + s.Owner + "\x00" + s.Network))
	return int(binary.BigEndian.Uint32(digest[:4])&0x3fffffff | 0x40000000)
}

func hostRouteFor(link netlink.Link, p netip.Prefix, s TunnelSpec) netlink.Route {
	r := routeFor(link, p, s)
	r.Table = hostTable(s)
	return r
}

func hostRule(s TunnelSpec, source netip.Prefix) netlink.Rule {
	rule := netlink.NewRule()
	rule.Family = unix.AF_INET6
	if source.Addr().Is4() {
		rule.Family = unix.AF_INET
	}
	rule.Priority, rule.Table, rule.Src, rule.Protocol = hostRulePriority, hostTable(s), prefixNet(source), unix.RTPROT_STATIC
	return *rule
}

// ownHostRule is the exact shape hostRule writes, for any source.
func ownHostRule(got netlink.Rule, s TunnelSpec) bool {
	return got.Table == hostTable(s) && got.Priority == hostRulePriority && got.Src != nil && got.Dst == nil && got.IifName == "" && got.OifName == "" && !got.Invert && got.Mark == 0 && got.Mask == nil && got.Goto == -1 && got.TunID == 0 && got.Protocol == unix.RTPROT_STATIC
}

// hostRules lists the rules that look up this TUN's host table. Any of them
// not in the exact shape hostRule writes is foreign.
func hostRules(s TunnelSpec) ([]netlink.Rule, error) {
	var out []netlink.Rule
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		rules, err := netlink.RuleList(family)
		if family == unix.AF_INET6 && errors.Is(err, unix.EAFNOSUPPORT) {
			continue // a kernel without IPv6 holds no IPv6 rules
		}
		if err != nil {
			return nil, err
		}
		for _, got := range rules {
			if got.Table != hostTable(s) {
				continue
			}
			if !ownHostRule(got, s) {
				return nil, ErrKernelOwnership
			}
			out = append(out, got)
		}
	}
	return out, nil
}

func ruleSource(r netlink.Rule) netip.Prefix {
	a, _ := netip.AddrFromSlice(r.Src.IP)
	ones, _ := r.Src.Mask.Size()
	return netip.PrefixFrom(a.Unmap(), ones)
}

// hostTableRoutes lists the routes of this TUN's host table. Any of them not
// on this link in the shape hostRouteFor writes is foreign.
func hostTableRoutes(link netlink.Link, s TunnelSpec) (map[netip.Prefix]netlink.Route, error) {
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: hostTable(s)}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, err
	}
	out := map[netip.Prefix]netlink.Route{}
	for _, r := range routes {
		if r.Dst == nil || link == nil {
			return nil, ErrKernelOwnership
		}
		a, ok := netip.AddrFromSlice(r.Dst.IP)
		ones, _ := r.Dst.Mask.Size()
		p := netip.PrefixFrom(a.Unmap(), ones)
		if !ok || !sameRoute(r, hostRouteFor(link, p, s)) {
			return nil, ErrKernelOwnership
		}
		out[p] = r
	}
	return out, nil
}

// ensureHostRoutes makes the host table hold exactly HostRoutes and the rules
// exactly HostSources. A spec with no host routes leaves neither.
func ensureHostRoutes(link netlink.Link, s TunnelSpec) error {
	rules, err := hostRules(s)
	if err != nil {
		return err
	}
	routes, err := hostTableRoutes(link, s)
	if err != nil {
		return err
	}
	// Rules go first when narrowing and last when widening, so no source ever
	// looks up a table that is missing routes it was promised.
	for _, r := range rules {
		if !slices.Contains(s.HostSources, ruleSource(r)) {
			if err := netlink.RuleDel(&r); err != nil {
				return err
			}
		}
	}
	for p, r := range routes {
		if !slices.Contains(s.HostRoutes, p) {
			if err := netlink.RouteDel(&r); err != nil {
				return err
			}
		}
	}
	for _, p := range s.HostRoutes {
		if _, ok := routes[p]; !ok {
			r := hostRouteFor(link, p, s)
			if err := netlink.RouteAdd(&r); err != nil {
				return err
			}
		}
	}
	for _, source := range s.HostSources {
		if !slices.ContainsFunc(rules, func(r netlink.Rule) bool { return ruleSource(r) == source }) {
			rule := hostRule(s, source)
			if err := netlink.RuleAdd(&rule); err != nil {
				return err
			}
		}
	}
	exact, err := inspectHostRoutes(link, s)
	if err != nil || !exact {
		return errors.Join(err, ErrKernelOwnership)
	}
	return nil
}

// inspectHostRoutes reports whether the host table and its rules are exactly
// what the spec says.
func inspectHostRoutes(link netlink.Link, s TunnelSpec) (bool, error) {
	rules, err := hostRules(s)
	if err != nil {
		return false, err
	}
	routes, err := hostTableRoutes(link, s)
	if err != nil {
		return false, err
	}
	if len(rules) != len(s.HostSources) || len(routes) != len(s.HostRoutes) {
		return false, nil
	}
	for _, r := range rules {
		if !slices.Contains(s.HostSources, ruleSource(r)) {
			return false, nil
		}
	}
	for _, p := range s.HostRoutes {
		if _, ok := routes[p]; !ok {
			return false, nil
		}
	}
	return true, nil
}

// removeHostRules drops this TUN's host rules once its device (and with it
// every host table route) is gone.
func removeHostRules(s TunnelSpec) error {
	rules, err := hostRules(s)
	if err != nil {
		return err
	}
	for _, r := range rules {
		if err := netlink.RuleDel(&r); err != nil {
			return err
		}
	}
	return nil
}

// LocalHostRoutes is the spec this server applies for a committed tenant TUN
// source: its remote server addresses move from Routes to HostRoutes, looked
// up from sources (this member's own pools). The committed source keeps the
// plain shape, so the cluster's state and every permit digest stay as they
// are; only the local kernel layout changes. The system network keeps its
// server addresses in the main table and never calls this.
func LocalHostRoutes(s TunnelSpec, sources []netip.Prefix) TunnelSpec {
	s = s.Clone()
	if s.RoutePolicy != nil || len(s.HostRoutes) != 0 || len(sources) == 0 {
		return s
	}
	routes := s.Routes[:0:0]
	for _, p := range s.Routes {
		if SharedServerPrefix(p) && p.Bits() == p.Addr().BitLen() {
			s.HostRoutes = append(s.HostRoutes, p)
		} else {
			routes = append(routes, p)
		}
	}
	if len(s.HostRoutes) == 0 {
		return s
	}
	s.Routes = routes
	s.HostSources = slices.Clone(sources)
	slices.SortFunc(s.HostSources, func(a, b netip.Prefix) int { return strings.Compare(a.String(), b.String()) })
	s.HostSources = slices.Compact(s.HostSources)
	return s
}
