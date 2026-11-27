// SPDX-License-Identifier: Apache-2.0

package network

import (
	"context"
	"net"
	"sync"
	"testing"

	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/vishvananda/netlink"
)

type routeFixtureConntrack struct{ original netlink.ConntrackFlow }

func sameRouteFixtureTuple(a, b netlink.IPTuple) bool {
	return a.Protocol == b.Protocol && a.SrcPort == b.SrcPort && a.DstPort == b.DstPort && a.SrcIP.Equal(b.SrcIP) && a.DstIP.Equal(b.DstIP)
}
func (f routeFixtureConntrack) MatchConntrackFlow(row *netlink.ConntrackFlow) bool {
	want := f.original
	return row != nil && row.FamilyType == want.FamilyType && row.Zone == want.Zone && row.Mark == want.Mark && sameRouteFixtureTuple(row.Forward, want.Forward) && sameRouteFixtureTuple(row.Reverse, want.Reverse)
}

// The enclosing route native test already checked ownership of a private
// netns and registered native/Bridge/baseline rollback. These are deliberately
// inserted kernel rows, not a claim about actual service traffic or peer GC.
func testRouteConntrackNative(t *testing.T, ctx context.Context, driver *TunnelDriver, key string, resource reconcile.Resource, spec TunnelSpec) {
	t.Helper()
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if rows, err := driver.RouteConntrackCensus(cancelled, key, resource); err != context.Canceled || rows != nil {
		t.Fatal("cancelled census produced usable absence", err)
	}
	family := netlink.InetFamily(netlink.FAMILY_V6)
	if spec.RoutePolicy.Source.Addr().Is4() {
		family = netlink.InetFamily(netlink.FAMILY_V4)
	}
	source, destination := spec.RoutePolicy.Source.Addr().Next().Next(), spec.RoutePolicy.Destination.Addr().Next().Next()
	base := netlink.ConntrackFlow{FamilyType: uint8(family), Mark: routeMark(spec), TimeOut: 120, ProtoInfo: &netlink.ProtoInfoTCP{State: 3}, Forward: netlink.IPTuple{SrcIP: net.IP(source.AsSlice()), DstIP: net.IP(destination.AsSlice()), SrcPort: 43001, DstPort: 3306, Protocol: 6}, Reverse: netlink.IPTuple{SrcIP: net.IP(destination.AsSlice()), DstIP: net.IP(source.AsSlice()), SrcPort: 3306, DstPort: 43001, Protocol: 6}}
	other, foreign := base, base
	other.Forward.SrcPort++
	other.Reverse.DstPort++
	foreign.Forward.SrcPort += 2
	foreign.Reverse.DstPort += 2
	foreign.Mark ^= 1
	originals := []netlink.ConntrackFlow{base, other, foreign}
	before, err := netlink.ConntrackTableList(netlink.ConntrackTable, family)
	if err != nil {
		t.Fatal("complete conntrack baseline", err)
	}
	for _, want := range originals {
		for _, row := range before {
			if row != nil && row.Zone == want.Zone && (sameRouteFixtureTuple(row.Forward, want.Forward) || sameRouteFixtureTuple(row.Reverse, want.Reverse)) {
				t.Fatal("refuse preexisting conntrack tuple")
			}
		}
	}
	var cleanupOnce sync.Once
	cleanup := func() {
		cleanupOnce.Do(func() {
			for _, original := range originals {
				filter := routeFixtureConntrack{original}
				if _, err := netlink.ConntrackDeleteFilter(netlink.ConntrackTable, family, filter); err != nil {
					t.Error("exact fixture conntrack rollback", err)
				}
				rows, err := netlink.ConntrackTableList(netlink.ConntrackTable, family)
				if err != nil {
					t.Error("complete fixture conntrack rollback census", err)
					continue
				}
				for _, row := range rows {
					if filter.MatchConntrackFlow(row) {
						t.Error("original fixture conntrack remained after rollback")
					}
				}
			}
		})
	}
	t.Cleanup(cleanup) // Before the first create, including ambiguous failures.
	defer cleanup()
	for i := range originals {
		if err := netlink.ConntrackCreate(netlink.ConntrackTable, family, &originals[i]); err != nil {
			t.Fatal("create exact owned fixture conntrack", err)
		}
	}
	census, err := driver.RouteConntrackCensus(ctx, key, resource)
	target := TransportPacket{Source: source, Destination: destination, SourcePort: 43001, DestinationPort: 3306, Protocol: 6}
	neighbor, foreignTuple := target, target
	neighbor.SourcePort++
	foreignTuple.SourcePort += 2
	if err != nil || !census[target] || !census[neighbor] || census[foreignTuple] {
		t.Fatal("owned/foreign census mismatch", err)
	}
	if err := driver.DrainRouteFlow(ctx, key, resource, target); err != nil {
		t.Fatal("exact per-flow drain", err)
	}
	census, err = driver.RouteConntrackCensus(ctx, key, resource)
	if err != nil || census[target] || !census[neighbor] {
		t.Fatal("per-flow drain changed a neighboring flow", err)
	}
	rows, err := netlink.ConntrackTableList(netlink.ConntrackTable, family)
	if err != nil {
		t.Fatal("foreign preservation readback", err)
	}
	retained := false
	for _, row := range rows {
		retained = retained || (routeFixtureConntrack{foreign}).MatchConntrackFlow(row)
	}
	if !retained {
		t.Fatal("per-flow drain removed foreign-mark fixture row")
	}
}
