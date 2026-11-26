// SPDX-License-Identifier: Apache-2.0

package network

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestTunnelSpecRejectsImplicitAndConflictingRoutes(t *testing.T) {
	s := TunnelSpec{Schema: 1, Owner: "node", Network: "overlay", MTU: 1280, RouteMetric: 100, Routes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}
	decode := func(s TunnelSpec) error {
		b, _ := json.Marshal(s)
		_, err := DecodeTunnel(string(b))
		return err
	}
	if err := decode(s); err != nil {
		t.Fatal(err)
	}
	lone := s
	lone.Routes = []netip.Prefix{}
	if err := decode(lone); err != nil {
		t.Fatal("a lone TUN member without routes refused", err)
	}
	for _, routes := range [][]netip.Prefix{
		{netip.MustParsePrefix("0.0.0.0/0")},
		{netip.MustParsePrefix("127.0.0.0/8")},
		{netip.MustParsePrefix("192.0.2.1/24")},
		{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.0.2.0/25")},
	} {
		bad := s
		bad.Routes = routes
		if decode(bad) == nil {
			t.Fatal("accepted implicit/ambiguous route", routes)
		}
	}
}

func TestRealBoundaryTunnelKernelJournal(t *testing.T) {
	host := os.Getenv("MYDC_KERNEL_HOST_NETNS")
	if host == "" {
		t.Skip("requires the documented isolated network namespace and rollback plan")
	}
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil || host == current || os.Geteuid() != 0 {
		t.Fatal("refusing kernel mutation outside isolated privileged namespace", host, current, err)
	}
	owner := os.Getenv("MYDC_KERNEL_TEST_OWNER")
	if owner == "" {
		t.Fatal("explicit test owner required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	t.Cleanup(cancel)
	// First activation initializes permanent loopback qdisc/local routes in
	// a fresh netns. Treat it as fixture setup, outside the native baseline;
	// namespace destruction is the rollback for that one-time initialization.
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	wasUp := lo.Attrs().Flags&net.FlagUp != 0
	t.Cleanup(func() {
		if !wasUp {
			if err := netlink.LinkSetDown(lo); err != nil {
				t.Error(err)
			}
		}
	})
	if err = netlink.LinkSetUp(lo); err != nil {
		t.Fatal(err)
	}
	snapshot := func() []byte {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		var result [][]byte
		for _, cmd := range [][]string{{"ip", "-j", "link"}, {"ip", "-j", "-4", "route", "show", "table", "all"}, {"ip", "-j", "-6", "route", "show", "table", "all"}, {"nft", "-j", "list", "ruleset"}} {
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
	t.Logf("isolated namespace=%s host=%s owner=%s; prestate=%s", current, host, owner, before)
	spec := TunnelSpec{Schema: 1, Owner: owner, Network: "kernel-boundary", MTU: 1280, RouteMetric: 100,
		Addresses: []netip.Prefix{netip.MustParsePrefix("10.249.24.1/32"), netip.MustParsePrefix("fd00:249:24::1/128")},
		Routes:    []netip.Prefix{netip.MustParsePrefix("10.249.24.2/32"), netip.MustParsePrefix("fd00:249:24::2/128")}}
	path := filepath.Join(t.TempDir(), "tunnel.db")
	m, err := OpenTunnelManager(path, owner)
	if err != nil {
		t.Fatal(err)
	}
	key := "network/tun/kernel"
	b, _ := json.Marshal(spec)
	resource := reconcile.Resource{Present: true, Generation: 1, Spec: string(b)}
	_, id, err := m.driver.parameters(key, reconcile.Operation{Target: resource})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// The anonymous namespace is also a final containment boundary if
		// ownership cannot be proven after an interrupted native operation.
		if link, e := netlink.LinkByName(id.name); e == nil && ownTunnel(link, id) {
			if !t.Failed() {
				t.Error("product left kernel resources; invoking rollback fallback")
			}
			_, e = m.driver.run(context.Background(), key, reconcile.Operation{Kind: reconcile.Remove, Target: resource}, true)
			if e != nil {
				t.Error("kernel rollback", e)
			}
		}
		if e := m.Close(); e != nil {
			t.Error(e)
		}
		if after := snapshot(); !bytes.Equal(before, after) {
			t.Errorf("namespace not restored\nbefore=%s\nafter=%s", before, after)
		}
	})
	if err = m.Desired(key, 1, 1, &spec, 2); err != nil {
		t.Fatal(err)
	}
	if err = m.Step(ctx, key); err != nil {
		t.Fatal("native create/readback", err)
	}
	r, _ := m.View(key)
	if r.State.Pending != nil || r.State.Applied != resource {
		t.Fatal("native result not durably applied", r)
	}
	link, err := netlink.LinkByName(id.name)
	if err != nil {
		t.Fatal(err)
	}
	originalIndex := link.Attrs().Index
	t.Logf("native TUN=%s ifindex=%d alias=%s nft=%s", id.name, originalIndex, id.alias, id.table)
	lease, err := m.Acquire(key, "packet-plane", 1)
	if err != nil {
		t.Fatal(err)
	}
	tunnelMYDCPRoundTrip(t, ctx, lease.IO, spec)
	dependency, err := m.BorrowDependency(ctx, key, "ingress/original", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Acquire(key, "ingress/original", 1); !errors.Is(err, reconcile.ErrLease) {
		t.Fatal("dependency received packet FD", err)
	}
	// A foreign alias cannot be adopted or deleted under the old journal.
	if err = netlink.LinkSetAlias(link, "foreign-kernel-owner"); err != nil {
		t.Fatal(err)
	}
	if _, err = m.driver.Execute(ctx, key, reconcile.Operation{Kind: reconcile.Remove, Target: resource}); !errors.Is(err, ErrKernelOwnership) {
		t.Fatal("foreign native alias removed", err)
	}
	if err = netlink.LinkSetAlias(link, id.alias); err != nil {
		t.Fatal(err)
	}
	if err = m.Close(); err != nil {
		t.Fatal(err)
	}
	m, err = OpenTunnelManager(path, owner)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := m.Acquire(key, "packet-plane", 1)
	if err != nil || restored.Pin != lease.Pin {
		t.Fatal("same DB lost original native pin", restored.Pin, lease.Pin, err)
	}
	again, err := m.BorrowDependency(ctx, key, "ingress/original", 1)
	if err != nil || again != dependency {
		t.Fatal("same DB replaced ingress TUN reference", again, dependency, err)
	}
	link, err = netlink.LinkByName(id.name)
	if err != nil || link.Attrs().Index != originalIndex {
		t.Fatal("restart replaced original kernel device", err)
	}
	tunnelUDPRoundTrip(t, restored.IO, "udp4", "10.249.24.1", "10.249.24.2")
	// A peer leaving and another joining changes only the route set: the same
	// device, address and pin stay while routes and accept rules follow.
	joined := spec
	joined.Routes = []netip.Prefix{netip.MustParsePrefix("10.249.24.3/32"), netip.MustParsePrefix("fd00:249:24::2/128")}
	if _, joinedID, err := m.driver.parameters(key, reconcile.Operation{Target: reconcile.Resource{Present: true, Generation: 1, Spec: mustJSON(joined)}}); err != nil || joinedID != id {
		t.Fatal("route change renamed the native identity", joinedID, id, err)
	}
	if err = m.Desired(key, 2, 1, &joined, 2); err != nil {
		t.Fatal(err)
	}
	if err = m.Step(ctx, key); err != nil {
		t.Fatal("in-place route change", err)
	}
	link, err = netlink.LinkByName(id.name)
	if err != nil || link.Attrs().Index != originalIndex {
		t.Fatal("route change replaced the device", err)
	}
	for prefix, want := range map[string]bool{"10.249.24.2/32": false, "10.249.24.3/32": true, "fd00:249:24::2/128": true} {
		present, err := routeState(link, netip.MustParsePrefix(prefix), joined)
		if err != nil || present != want {
			t.Fatal("route set after change", prefix, present, err)
		}
	}
	if present, err := inspectTunnelFirewall(joined, id); err != nil || !present {
		t.Fatal("accept rules did not follow the route set", err)
	}
	tunnelUDPRoundTrip(t, restored.IO, "udp4", "10.249.24.1", "10.249.24.3")
	// The last peer leaving keeps a lone TUN with no routes on the same
	// device; a peer joining again adds its routes in place.
	lone := joined
	lone.Routes = []netip.Prefix{}
	for i, next := range []TunnelSpec{lone, joined} {
		if err = m.Desired(key, uint64(3+i), 1, &next, 2); err != nil {
			t.Fatal(err)
		}
		if err = m.Step(ctx, key); err != nil {
			t.Fatal("in-place route change", len(next.Routes), err)
		}
		link, err = netlink.LinkByName(id.name)
		if err != nil || link.Attrs().Index != originalIndex {
			t.Fatal("route change replaced the device", len(next.Routes), err)
		}
		for _, prefix := range joined.Routes {
			present, err := routeState(link, prefix, next)
			if err != nil || present != (len(next.Routes) > 0) {
				t.Fatal("route set after change", prefix, present, err)
			}
		}
		if present, err := inspectTunnelFirewall(next, id); err != nil || !present {
			t.Fatal("accept rules did not follow the route set", len(next.Routes), err)
		}
	}
	tunnelUDPRoundTrip(t, restored.IO, "udp4", "10.249.24.1", "10.249.24.3")
	spec, resource = joined, reconcile.Resource{Present: true, Generation: 1, Spec: mustJSON(joined)}
	// Link deletion would also implicitly remove routes in other tables.
	// The owner must see those routes and refuse to erase foreign state.
	foreign := netlink.Route{LinkIndex: originalIndex, Dst: prefixNet(netip.MustParsePrefix("198.51.100.7/32")), Table: 10001, Protocol: unix.RTPROT_STATIC, Scope: netlink.SCOPE_LINK, Priority: 101}
	t.Cleanup(func() { _ = netlink.RouteDel(&foreign) })
	if err = netlink.RouteAdd(&foreign); err != nil {
		t.Fatal(err)
	}
	if _, err = m.driver.Execute(ctx, key, reconcile.Operation{Kind: reconcile.Remove, Target: resource}); !errors.Is(err, ErrKernelOwnership) {
		t.Fatal("foreign route in another table was removed", err)
	}
	if present, err := inspectTunnelFirewall(spec, id); err != nil || !present {
		t.Fatal("rejected removal dropped live TUN firewall", err)
	}
	if err = netlink.RouteDel(&foreign); err != nil {
		t.Fatal(err)
	}
	if err = m.Desired(key, 5, 1, nil, 2); err != nil {
		t.Fatal(err)
	}
	// Drain is persisted and waits for the consumers (reconcile.ErrPending).
	if err = m.Step(ctx, key); !errors.Is(err, reconcile.ErrPending) {
		t.Fatal("live packet user did not block Drain", err)
	}
	if err = m.Return(restored); err != nil {
		t.Fatal(err)
	}
	if err = m.Step(ctx, key); !errors.Is(err, reconcile.ErrPending) {
		t.Fatal("Ingress dependency did not block native removal", err)
	}
	if err = m.Return(TunnelLease{Key: key, Consumer: "ingress/original", Pin: dependency}); err != nil {
		t.Fatal(err)
	}
	if err = m.Step(ctx, key); err != nil {
		t.Fatal("native removal/readback", err)
	}
	r, err = m.View(key)
	if err != nil || r.State.Pending != nil || r.State.Applied.Present || r.State.GenerationFloor != 1 || len(r.Consumers) != 0 {
		t.Fatal("kernel retirement not settled", r, err)
	}
	t.Log("actual dual-stack 1280B IP read/write; same DB/TUN ifindex/pin; foreign alias/table route and live Drain rejection; native TUN/route/nft removal")
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func TestTunnelIdentityIgnoresTheRouteSetOnlyWithoutARoutePolicy(t *testing.T) {
	d := &TunnelDriver{Owner: "owner"}
	base := TunnelSpec{Schema: 1, Owner: "owner", Network: "n", MTU: 1400, RouteMetric: 100,
		Addresses: []netip.Prefix{netip.MustParsePrefix("10.9.0.1/32")}, Routes: []netip.Prefix{netip.MustParsePrefix("10.9.1.0/24")}}
	identity := func(s TunnelSpec) tunnelIdentity {
		t.Helper()
		_, id, err := d.parameters("k", reconcile.Operation{Target: reconcile.Resource{Present: true, Generation: 4, Spec: mustJSON(s)}})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	first := identity(base)
	moved := base
	moved.Routes = []netip.Prefix{netip.MustParsePrefix("10.9.1.0/24"), netip.MustParsePrefix("10.9.2.0/24")}
	if identity(moved) != first {
		t.Fatal("a joining peer renamed the device")
	}
	mtu := base
	mtu.MTU = 1380
	if identity(mtu) == first {
		t.Fatal("an MTU change kept the device identity")
	}
	a, b := tunnelRules(base, first), tunnelRules(moved, first)
	for name := range a.rules {
		if !routeChain(name) && len(a.rules[name]) != len(b.rules[name]) {
			t.Fatal("a route change touched a hook chain", name)
		}
	}
	if len(b.rules["from"]) != len(a.rules["from"])+1 {
		t.Fatal("accept rules did not follow the route set")
	}
}

func tunnelUDPRoundTrip(t *testing.T, device PacketIO, af, local, remote string) {
	t.Helper()
	c, err := net.DialUDP(af, &net.UDPAddr{IP: net.ParseIP(local)}, &net.UDPAddr{IP: net.ParseIP(remote), Port: 53001})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if af == "udp4" {
		raw, err := c.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var optionErr error
		if err = raw.Control(func(fd uintptr) {
			optionErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO)
		}); err != nil || optionErr != nil {
			t.Fatal(err, optionErr)
		}
	}
	header, source, target := 20, 12, 16
	if af == "udp6" {
		header, source, target = 40, 8, 24
	}
	payload := bytes.Repeat([]byte{0x52}, 1280-header-8)
	if _, err = c.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err = device.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 65535)
	n, err := device.Read(packet)
	if err != nil || n != 1280 || binary.BigEndian.Uint16(packet[header+2:]) != 53001 {
		t.Fatal("kernel TUN packet", af, n, err)
	}
	packet = packet[:n]
	addressBytes := target - source
	oldSource := append([]byte(nil), packet[source:target]...)
	copy(packet[source:target], packet[target:target+addressBytes])
	copy(packet[target:target+addressBytes], oldSource)
	port := append([]byte(nil), packet[header:header+2]...)
	copy(packet[header:header+2], packet[header+2:header+4])
	copy(packet[header+2:header+4], port)
	// Swapping both address and port pairs preserves their one's-complement
	// sums, including the mandatory IPv6 UDP pseudo-header checksum.
	if _, err = device.Write(packet); err != nil {
		t.Fatal("kernel TUN injection", af, err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	reply := make([]byte, 2048)
	n, err = c.Read(reply)
	if err != nil || !bytes.Equal(reply[:n], payload) {
		t.Fatal("kernel UDP return", af, n, err)
	}
}
