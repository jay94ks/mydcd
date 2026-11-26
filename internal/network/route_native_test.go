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
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/vishvananda/netlink"
)

// Native route TUN/nft lifecycle only. This does not substitute for the two
// route owners' real packet, provenance, bilateral flow or closure integration.
func TestRealBoundaryRouteTunnelNativePolicyJournal(t *testing.T) {
	for _, family := range []string{"ipv4", "ipv6"} {
		t.Run(family, func(t *testing.T) { testRouteTunnelNativePolicy(t, family == "ipv6") })
	}
}

func testRouteTunnelNativePolicy(t *testing.T, ipv6 bool) {
	host, owner := os.Getenv("MYDC_KERNEL_HOST_NETNS"), os.Getenv("MYDC_KERNEL_TEST_OWNER")
	if host == "" {
		t.Skip("owned isolated network namespace and prior rollback plan required")
	}
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil || current == host || owner == "" || os.Geteuid() != 0 {
		t.Fatal("refuse unowned/host kernel mutation", err)
	}
	snapshot := func() []byte {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		var records [][]byte
		for _, args := range [][]string{{"ip", "-j", "link"}, {"ip", "-j", "addr"}, {"ip", "-j", "-4", "rule"}, {"ip", "-j", "-6", "rule"}, {"ip", "-j", "-4", "route", "show", "table", "all"}, {"ip", "-j", "-6", "route", "show", "table", "all"}, {"nft", "-j", "list", "ruleset"}} {
			raw, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
			if err != nil {
				t.Fatal("owned native baseline/read-back", args, err, string(raw))
			}
			records = append(records, raw)
		}
		raw, _ := json.Marshal(records)
		return raw
	}
	before := snapshot()
	t.Logf("route native baseline: namespace=%s host=%s owner=%s prestate=%s", current, host, owner, before)
	spec := routeTunnelSpec(true)
	spec.Owner = owner
	spec.RoutePolicy.Bridge = "md0123456789ab"
	spec.RoutePolicy.Source = netip.MustParsePrefix("10.249.125.0/24")
	spec.RoutePolicy.Destination = netip.MustParsePrefix("10.249.126.0/24")
	if ipv6 {
		spec.RoutePolicy.Source = netip.MustParsePrefix("fd00:249:125::/64")
		spec.RoutePolicy.Destination = netip.MustParsePrefix("fd00:249:126::/64")
	}
	spec.Routes = []netip.Prefix{spec.RoutePolicy.Destination}
	raw, _ := json.Marshal(spec)
	resource := reconcile.Resource{Present: true, Generation: 1, Spec: string(raw)}
	key, path := "network/tun/route-policy-boundary", filepath.Join(t.TempDir(), "tunnel.db")
	second := spec.Clone()
	second.Network += "/second-policy"
	second.RoutePolicy.Ports = []RoutePortRange{{First: 9443, Last: 9443}}
	secondRaw, _ := json.Marshal(second)
	secondKey := key + "-second"
	secondResource := reconcile.Resource{Present: true, Generation: 1, Spec: string(secondRaw)}
	bridgeAlias := "mydc-route-test-" + familyLabel(ipv6)
	var createdBridge bool
	manager, err := OpenTunnelManager(path, owner)
	if err != nil {
		t.Fatal(err)
	}
	_, native, err := manager.driver.parameters(key, reconcile.Operation{Target: resource})
	if err != nil {
		t.Fatal(errors.Join(err, manager.Close()))
	}
	t.Cleanup(func() {
		// A fresh driver can settle the exact original native object even if
		// the test stopped between closing and reopening the original DB.
		rollback := &TunnelDriver{Owner: owner}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, original := range []struct {
			key      string
			resource reconcile.Resource
		}{{secondKey, secondResource}, {key, resource}} {
			if outcome, err := rollback.run(ctx, original.key, reconcile.Operation{Kind: reconcile.Remove, Target: original.resource}, true); err != nil || outcome != reconcile.EffectApplied {
				t.Error("exact route native rollback", original.key, outcome, err)
			}
		}
		if err := rollback.Close(); err != nil {
			t.Error(err)
		}
		if manager != nil {
			if err := manager.Close(); err != nil {
				t.Error(err)
			}
		}
		if createdBridge {
			bridge, err := netlink.LinkByName(spec.RoutePolicy.Bridge)
			if err != nil || bridge.Type() != "bridge" || bridge.Attrs().Alias != bridgeAlias {
				t.Error("original selector Bridge ownership lost", err)
			} else if err := netlink.LinkDel(bridge); err != nil {
				t.Error(err)
			}
		}
		if after := snapshot(); !bytes.Equal(before, after) {
			t.Errorf("route native namespace not restored\nbefore=%s\nafter=%s", before, after)
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 12*time.Second)
	defer cancel()
	if absent, err := manager.driver.RouteAbsent(ctx, key, resource); err != nil || !absent {
		t.Fatal("readonly route absence before native creation", absent, err)
	}
	if _, err := netlink.LinkByName(spec.RoutePolicy.Bridge); !missingLink(err) {
		t.Fatal("refuse existing selector Bridge", err)
	}
	bridge := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: spec.RoutePolicy.Bridge, Alias: bridgeAlias}}
	if err := netlink.LinkAdd(bridge); err != nil {
		t.Fatal(err)
	}
	createdBridge = true
	if err := netlink.LinkSetAlias(bridge, bridgeAlias); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(bridge); err != nil {
		t.Fatal(err)
	}
	if err = manager.Desired(key, 1, 1, &spec, 2); err != nil {
		t.Fatal(err)
	}
	if err = manager.Step(ctx, key); err != nil {
		t.Fatal("route native create/read-back", err)
	}
	row, err := manager.View(key)
	if err != nil || row.State.Pending != nil || row.State.Applied != resource {
		t.Fatal("route policy result not durably applied", err)
	}
	if _, err = manager.Inspect(ctx, key); err != nil {
		t.Fatal("actual route TUN/nft inspect", err)
	}
	// A fresh read-only driver must neither attach an FD nor repair policy.
	reader := &TunnelDriver{Owner: owner}
	defer reader.Close()
	inspectOriginal := func() (reconcile.Outcome, error) {
		return reader.Inspect(ctx, key, reconcile.Operation{ID: 1, Kind: reconcile.Apply, Phase: reconcile.Dispatched, Target: resource})
	}
	installedBefore := snapshot()
	if outcome, err := inspectOriginal(); err != nil || outcome != reconcile.EffectApplied || len(reader.files) != 0 {
		t.Fatal("admission inspection did not observe original policy", outcome, err)
	}
	if installedAfter := snapshot(); !bytes.Equal(installedBefore, installedAfter) {
		t.Fatal("admission inspection changed native topology or firewall")
	}
	if !ipv6 {
		path := "/proc/sys/net/ipv4/conf/" + native.name + "/src_valid_mark"
		if err := os.WriteFile(path, []byte("0\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := manager.Inspect(ctx, key); !errors.Is(err, ErrKernelOwnership) {
			t.Fatal("wrong source validation was published as serving", err)
		}
		if outcome, err := inspectOriginal(); outcome == reconcile.EffectApplied || !errors.Is(err, ErrKernelOwnership) {
			t.Fatal("admission inspection accepted/repaired source validation", outcome, err)
		}
		if raw, err := os.ReadFile(path); err != nil || !bytes.Equal(raw, []byte("0\n")) {
			t.Fatal("admission inspection repaired source validation", err)
		}
		if _, err := manager.driver.PacketIO(key, resource); !errors.Is(err, ErrKernelOwnership) {
			t.Fatal("wrong source validation exposed packet IO", err)
		}
		if err := os.WriteFile(path, []byte("1\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	linkForRoute, err := netlink.LinkByName(native.name)
	if err != nil {
		t.Fatal(err)
	}
	removedRoute := routeFor(linkForRoute, spec.Routes[0], spec)
	if err := netlink.RouteDel(&removedRoute); err != nil {
		t.Fatal(err)
	}
	missingBefore := snapshot()
	if outcome, err := inspectOriginal(); outcome == reconcile.EffectApplied || err == nil {
		t.Fatal("admission inspection accepted/repaired missing route", outcome, err)
	}
	if missingAfter := snapshot(); !bytes.Equal(missingBefore, missingAfter) {
		t.Fatal("admission inspection changed missing-route state")
	}
	// Explicit fixture restoration, outside the read-only API.
	if err := netlink.RouteAdd(&removedRoute); err != nil {
		t.Fatal(err)
	}
	if absent, err := manager.driver.RouteAbsent(ctx, key, resource); err == nil || absent {
		t.Fatal("live original route was reported absent", absent, err)
	}
	if _, err := manager.Inspect(ctx, key); err != nil {
		t.Fatal("readonly absence probe changed the serving original native", err)
	}
	if err := manager.Desired(secondKey, 1, 1, &second, 2); err != nil {
		t.Fatal(err)
	}
	if err := manager.Step(ctx, secondKey); err != nil {
		t.Fatal("same CIDR's independent policy table", err)
	}
	if _, err := manager.Inspect(ctx, secondKey); err != nil {
		t.Fatal(err)
	}
	if routeTable(spec) == routeTable(second) || routeMark(spec) == routeMark(second) {
		t.Fatal("same-CIDR policies collided in native selection")
	}
	testRouteConntrackNative(t, ctx, manager.driver, key, resource, spec)
	link, err := netlink.LinkByName(native.name)
	if err != nil {
		t.Fatal(err)
	}
	index := link.Attrs().Index
	bad := spec.Clone()
	bad.RoutePolicy.Ports[0].Last++
	if _, err = inspectTunnelFirewall(bad, native); !errors.Is(err, ErrKernelOwnership) {
		t.Fatal("actual nft read-back accepted a different approved port policy", err)
	}
	if err = manager.Close(); err != nil {
		t.Fatal(err)
	}
	manager = nil
	manager, err = OpenTunnelManager(path, owner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = manager.Inspect(ctx, key); err != nil {
		t.Fatal("same DB route native read-back", err)
	}
	if _, err = manager.Inspect(ctx, secondKey); err != nil {
		t.Fatal("same DB second policy selection", err)
	}
	link, err = netlink.LinkByName(native.name)
	if err != nil || link.Attrs().Index != index {
		t.Fatal("same DB replaced original route TUN", err)
	}
	if err := manager.driver.QuiesceRoute(ctx, key, resource); err != nil {
		t.Fatal("original route packet fence/empty owned conntrack census", err)
	}
	if _, table, err := lookupTunnelFirewallMode(spec, native, true); err != nil || table == nil {
		t.Fatal("retiring policy did not read back exact fenced mode", err)
	}
	if _, err := manager.Inspect(ctx, key); err == nil {
		t.Fatal("fenced policy was published as serving")
	}
	if rows, err := manager.driver.RouteConntrackCensus(ctx, key, resource); err == nil || rows != nil {
		t.Fatal("fenced native produced an active-flow absence census", err)
	}
	if err := manager.driver.QuiesceRoute(ctx, key, resource); err != nil {
		t.Fatal("same original packet fence could not resume", err)
	}
	if _, err := manager.Inspect(ctx, secondKey); err != nil {
		t.Fatal("first fence altered the other original policy", err)
	}
	if err = manager.Desired(key, 2, 1, nil, 2); err != nil {
		t.Fatal(err)
	}
	if err = manager.Step(ctx, key); err != nil {
		t.Fatal("route native removal", err)
	}
	if gone, err := manager.Gone(ctx, key, 2, 1, spec); err != nil || !gone {
		t.Fatal("original route policy/native journal not Gone before rollback", gone, err)
	}
	if absent, err := manager.driver.RouteAbsent(ctx, key, resource); err != nil || !absent {
		t.Fatal("readonly route absence after original native retirement", absent, err)
	}
	foreign := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: native.name, Alias: "mydc-native-absence-foreign-marker"}}
	foreignCreated := false
	removeForeign := func() {
		if !foreignCreated {
			return
		}
		link, err := netlink.LinkByName(native.name)
		if err != nil || link.Type() != "dummy" || link.Attrs().Alias != foreign.Attrs().Alias {
			t.Error("foreign absence marker ownership changed", err)
			return
		}
		if err := netlink.LinkDel(link); err != nil {
			t.Error("foreign absence marker rollback", err)
			return
		}
		foreignCreated = false
	}
	t.Cleanup(removeForeign) // Before creating this test-owned foreign object.
	if err := netlink.LinkAdd(foreign); err != nil {
		t.Fatal(err)
	}
	foreignCreated = true
	if err := netlink.LinkSetAlias(foreign, foreign.Attrs().Alias); err != nil {
		t.Fatal(err)
	}
	foreignBefore := snapshot()
	if absent, err := manager.driver.RouteAbsent(ctx, key, resource); err == nil || absent {
		t.Fatal("same-name foreign device supplied original termination evidence", absent, err)
	}
	if !bytes.Equal(foreignBefore, snapshot()) {
		t.Fatal("readonly absence probe modified a foreign current-kernel object")
	}
	removeForeign()
	if foreignCreated {
		t.Fatal("foreign marker rollback incomplete")
	}
	if rows, err := manager.driver.RouteConntrackCensus(ctx, key, resource); err == nil || rows != nil {
		t.Fatal("missing original native produced an active-flow absence census", err)
	}
	if _, err := manager.Inspect(ctx, secondKey); err != nil {
		t.Fatal("first removal altered the same-CIDR peer policy", err)
	}
	if err := manager.Desired(secondKey, 2, 1, nil, 2); err != nil {
		t.Fatal(err)
	}
	if err := manager.Step(ctx, secondKey); err != nil {
		t.Fatal(err)
	}
	if gone, err := manager.Gone(ctx, secondKey, 2, 1, second); err != nil || !gone {
		t.Fatal("second policy selector did not close", err)
	}
}

func familyLabel(ipv6 bool) string {
	if ipv6 {
		return "ipv6"
	}
	return "ipv4"
}
