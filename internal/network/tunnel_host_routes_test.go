// SPDX-License-Identifier: Apache-2.0

package network

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func hostRouteSpec() TunnelSpec {
	return TunnelSpec{Schema: 1, Owner: "cluster/a", Network: "tenant/t/network/n", MTU: 1400, RouteMetric: 100,
		Addresses:   []netip.Prefix{netip.MustParsePrefix("10.254.240.2/32")},
		Routes:      []netip.Prefix{netip.MustParsePrefix("198.19.91.16/28")},
		HostRoutes:  []netip.Prefix{netip.MustParsePrefix("10.254.240.5/32")},
		HostSources: []netip.Prefix{netip.MustParsePrefix("198.19.91.0/28")}}
}

func encodeTunnel(t *testing.T, s TunnelSpec) string {
	t.Helper()
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// A tenant TUN keeps a remote server's address out of Routes (the main
// table, which sfc-system owns) and in HostRoutes, looked up only from its
// own pools.
func TestTunnelHostRoutesAreExact(t *testing.T) {
	if _, err := DecodeTunnel(encodeTunnel(t, hostRouteSpec())); err != nil {
		t.Fatal("valid host routes refused", err)
	}
	for name, mutate := range map[string]func(*TunnelSpec){
		"no sources":       func(s *TunnelSpec) { s.HostSources = nil },
		"sources only":     func(s *TunnelSpec) { s.HostRoutes = nil },
		"not a host":       func(s *TunnelSpec) { s.HostRoutes = []netip.Prefix{netip.MustParsePrefix("10.254.240.0/28")} },
		"overlaps a route": func(s *TunnelSpec) { s.HostRoutes = []netip.Prefix{netip.MustParsePrefix("198.19.91.17/32")} },
		"in a source":      func(s *TunnelSpec) { s.HostRoutes = []netip.Prefix{netip.MustParsePrefix("198.19.91.1/32")} },
		"unsorted": func(s *TunnelSpec) {
			s.HostRoutes = []netip.Prefix{netip.MustParsePrefix("10.254.240.5/32"), netip.MustParsePrefix("10.254.240.3/32")}
		},
		"unmasked source": func(s *TunnelSpec) { s.HostSources = []netip.Prefix{netip.MustParsePrefix("198.19.91.1/28")} },
		"with a route policy": func(s *TunnelSpec) {
			s.RoutePolicy = &PacketRoutePolicy{Source: netip.MustParsePrefix("198.19.91.0/28"), Destination: netip.MustParsePrefix("198.19.91.16/28"), Protocol: 6, Ports: []RoutePortRange{{First: 80, Last: 80}}}
		},
	} {
		s := hostRouteSpec()
		mutate(&s)
		if _, err := DecodeTunnel(encodeTunnel(t, s)); err == nil {
			t.Fatal("decoded", name)
		}
	}
	s := hostRouteSpec()
	if got := s.Overlay(); !slices.Equal(got, []netip.Prefix{netip.MustParsePrefix("10.254.240.5/32"), netip.MustParsePrefix("198.19.91.16/28")}) {
		t.Fatal("overlay", got)
	}
	if hostTable(s) == routeTable(s) || hostTable(s) < 0x40000000 {
		t.Fatal("host table", hostTable(s))
	}
	rule := hostRule(s, s.HostSources[0])
	if !ownHostRule(rule, s) || rule.Src.String() != "198.19.91.0/28" {
		t.Fatal("host rule shape", rule)
	}
}

// The committed source keeps the plain shape; this server moves the remote
// server addresses into the host table, looked up from its own pools.
func TestLocalHostRoutesSplitsOnlyServerAddresses(t *testing.T) {
	committed := hostRouteSpec()
	committed.Routes = []netip.Prefix{netip.MustParsePrefix("10.254.240.5/32"), netip.MustParsePrefix("198.19.91.16/28")}
	committed.HostRoutes, committed.HostSources = nil, nil
	pools := []netip.Prefix{netip.MustParsePrefix("198.19.91.0/28")}
	local := LocalHostRoutes(committed, pools)
	if !slices.Equal(local.Routes, []netip.Prefix{netip.MustParsePrefix("198.19.91.16/28")}) || !slices.Equal(local.HostRoutes, []netip.Prefix{netip.MustParsePrefix("10.254.240.5/32")}) || !slices.Equal(local.HostSources, pools) {
		t.Fatal("split", local)
	}
	if _, err := DecodeTunnel(encodeTunnel(t, local)); err != nil {
		t.Fatal("local spec does not decode", err)
	}
	if !slices.Equal(local.Overlay(), committed.Routes) || stableTunnelSpec(local) != stableTunnelSpec(committed) || len(committed.HostRoutes) != 0 {
		t.Fatal("local spec changed the overlay or the device identity")
	}
	for name, s := range map[string]TunnelSpec{"no pools": LocalHostRoutes(committed, nil), "no server address": LocalHostRoutes(hostRouteSpec(), pools)} {
		if name == "no pools" && !slices.Equal(s.Routes, committed.Routes) || name == "no server address" && !slices.Equal(s.HostRoutes, hostRouteSpec().HostRoutes) {
			t.Fatal(name, s)
		}
	}
}

// A server joining or leaving changes only host routes in place: the device
// identity, its pins and the serving plane stay.
func TestTunnelHostRoutesChangeInPlace(t *testing.T) {
	before := hostRouteSpec()
	after := hostRouteSpec()
	after.HostRoutes = append(after.HostRoutes, netip.MustParsePrefix("10.254.240.6/32"))
	lone := hostRouteSpec()
	lone.Routes, lone.HostRoutes, lone.HostSources = []netip.Prefix{}, nil, nil
	d := &TunnelDriver{Owner: before.Owner}
	for _, next := range []TunnelSpec{after, lone} {
		if !d.InPlace(reconcile.Resource{Generation: 1, Present: true, Spec: encodeTunnel(t, before)}, reconcile.Resource{Generation: 1, Present: true, Spec: encodeTunnel(t, next)}) {
			t.Fatal("host route change replaced the device", next)
		}
	}
	firewall := tunnelRules(after, tunnelIdentity{name: "owned-tun", alias: "owned-alias", table: "owned-table"})
	plain := tunnelRules(lone, tunnelIdentity{name: "owned-tun", alias: "owned-alias", table: "owned-table"})
	for _, chain := range []string{"from", "to"} {
		if rules := firewall.rules[chain]; len(rules) != len(plain.rules[chain])+3 {
			t.Fatal("firewall does not accept every overlay prefix", chain, len(rules), len(plain.rules[chain]))
		}
	}
}

// The remote server's address names its owner as a peer, like its pool.
func TestTunnelHostRoutesFindTheirPeer(t *testing.T) {
	a, b := hostRouteSpec(), hostRouteSpec()
	b.Owner = "cluster/b"
	b.Addresses = []netip.Prefix{netip.MustParsePrefix("10.254.240.5/32")}
	b.Routes = []netip.Prefix{netip.MustParsePrefix("198.19.91.0/28")}
	b.HostRoutes = []netip.Prefix{netip.MustParsePrefix("10.254.240.2/32")}
	b.HostSources = []netip.Prefix{netip.MustParsePrefix("198.19.91.16/28")}
	g := TunnelTopology{Tunnels: map[string]TunnelSpec{"tun/a": a, "tun/b": b}, Pools: []RoutePool{
		{Network: a.Network, Owner: a.Owner, Prefix: netip.MustParsePrefix("198.19.91.0/28")},
		{Network: a.Network, Owner: b.Owner, Prefix: netip.MustParsePrefix("198.19.91.16/28")},
	}}
	if peers, err := g.Peers("tun/a"); err != nil || !slices.Equal(peers, []string{b.Owner}) {
		t.Fatal(peers, err)
	}
}

// On a real kernel (isolated namespace, like TestRealBoundaryTunnelKernelJournal):
// the host table and its pool rule follow HostRoutes in place, the main table
// never holds the server /32, and Remove leaves nothing behind.
func TestRealBoundaryTunnelHostRoutes(t *testing.T) {
	host := os.Getenv("SFC_KERNEL_HOST_NETNS")
	if host == "" {
		t.Skip("requires the documented isolated network namespace and rollback plan")
	}
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil || host == current || os.Geteuid() != 0 {
		t.Fatal("refusing kernel mutation outside isolated privileged namespace", host, current, err)
	}
	owner := os.Getenv("SFC_KERNEL_TEST_OWNER")
	if owner == "" {
		t.Fatal("explicit test owner required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	t.Cleanup(cancel)
	if lo, err := netlink.LinkByName("lo"); err != nil || netlink.LinkSetUp(lo) != nil {
		t.Fatal("loopback", err)
	}
	snapshot := func() []byte {
		t.Helper()
		var result [][]byte
		for _, cmd := range [][]string{{"ip", "-j", "link"}, {"ip", "-j", "-4", "route", "show", "table", "all"}, {"ip", "-j", "-4", "rule"}, {"nft", "-j", "list", "ruleset"}} {
			b, err := exec.CommandContext(ctx, cmd[0], cmd[1:]...).Output()
			if err != nil {
				t.Fatal("namespace snapshot", cmd, err)
			}
			result = append(result, b)
		}
		b, _ := json.Marshal(result)
		return b
	}
	before := snapshot()
	spec := hostRouteSpec()
	spec.Owner, spec.MTU = owner, 1280
	m, err := OpenTunnelManager(filepath.Join(t.TempDir(), "tunnel.db"), owner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	key := "network/tun/host-routes"
	resource := reconcile.Resource{Present: true, Generation: 1, Spec: encodeTunnel(t, spec)}
	_, id, err := m.driver.parameters(key, reconcile.Operation{Target: resource})
	if err != nil {
		t.Fatal(err)
	}
	step := func(next TunnelSpec, revision uint64) netlink.Link {
		t.Helper()
		if err := m.Desired(key, revision, 1, &next, 2); err != nil {
			t.Fatal(err)
		}
		if err := m.Step(ctx, key); err != nil {
			t.Fatal("native apply", err)
		}
		link, err := netlink.LinkByName(id.name)
		if err != nil {
			t.Fatal(err)
		}
		if exact, err := inspectHostRoutes(link, next); err != nil || !exact {
			t.Fatal("host table and rules", err)
		}
		for _, p := range next.HostRoutes {
			main, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Dst: prefixNet(p), Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_DST|netlink.RT_FILTER_TABLE)
			if err != nil || len(main) != 0 {
				t.Fatal("server address reached the main table", main, err)
			}
		}
		return link
	}
	first := step(spec, 1)
	joined := spec
	joined.HostRoutes = []netip.Prefix{netip.MustParsePrefix("10.254.240.5/32"), netip.MustParsePrefix("10.254.240.6/32")}
	if again := step(joined, 2); again.Attrs().Index != first.Attrs().Index {
		t.Fatal("host route change replaced the device")
	}
	lone := spec
	lone.Routes, lone.HostRoutes, lone.HostSources = []netip.Prefix{}, nil, nil
	step(lone, 3)
	step(joined, 4)
	if err := m.Desired(key, 5, 1, nil, 2); err != nil {
		t.Fatal(err)
	}
	// Drain, then removal: no consumer holds the TUN here.
	for i := 0; ; i++ {
		err := m.Step(ctx, key)
		if err == nil {
			break
		}
		if !errors.Is(err, reconcile.ErrPending) || i == 3 {
			t.Fatal("native remove", err)
		}
	}
	if rules, err := hostRules(joined); err != nil || len(rules) != 0 {
		t.Fatal("host rules left behind", rules, err)
	}
	if after := snapshot(); !bytes.Equal(before, after) {
		t.Fatalf("namespace not restored\nbefore=%s\nafter=%s", before, after)
	}
}
