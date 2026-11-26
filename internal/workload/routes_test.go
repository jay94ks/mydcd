// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"github.com/jay94ks/mydcd/internal/network"
	"net/netip"
	"slices"
	"testing"
)

func TestContainerRouteAdmissionKeepsOnlyRemoteOverlay(t *testing.T) {
	good := ContainerSpec{IPv4: netip.MustParseAddr("198.19.80.2"), IPv6: netip.MustParseAddr("fd00:1::2"), Routes: []ContainerRoute{{netip.MustParsePrefix("198.19.80.16/28"), netip.MustParseAddr("198.19.80.1")}, {netip.MustParsePrefix("fd00:2::/64"), netip.MustParseAddr("fd00:1::1")}}}
	bridge := network.BridgeSpec{Pools: []network.Pool{{Prefix: netip.MustParsePrefix("198.19.80.0/28"), Gateway: netip.MustParseAddr("198.19.80.1")}, {Prefix: netip.MustParsePrefix("fd00:1::/64"), Gateway: netip.MustParseAddr("fd00:1::1")}}}
	if err := ValidateContainerRoutes(good, bridge); err != nil {
		t.Fatal(err)
	}
	for n, mutate := range []func(*ContainerSpec){
		func(s *ContainerSpec) { s.Routes[0].Destination = netip.MustParsePrefix("0.0.0.0/0") },
		func(s *ContainerSpec) { s.Routes[0].Destination = netip.MustParsePrefix("198.19.80.17/28") },
		func(s *ContainerSpec) { s.Routes[0].Destination = netip.MustParsePrefix("198.19.80.0/28") },
		func(s *ContainerSpec) { s.Routes[0].Destination = netip.MustParsePrefix("127.0.0.0/8") },
		func(s *ContainerSpec) { s.Routes[0].Gateway = netip.MustParseAddr("198.19.80.3") },
		func(s *ContainerSpec) { s.Routes[0].Gateway = s.IPv4 },
		func(s *ContainerSpec) { s.Routes[0].Gateway = netip.MustParseAddr("fd00:1::1") },
		func(s *ContainerSpec) { s.IPv4 = netip.Addr{} },
		func(s *ContainerSpec) { s.Routes = append(s.Routes[:1], s.Routes[0]) },
		func(s *ContainerSpec) {
			s.Routes = []ContainerRoute{{netip.MustParsePrefix("198.19.80.16/28"), s.Routes[0].Gateway}, {netip.MustParsePrefix("198.19.80.16/29"), s.Routes[0].Gateway}}
		},
		func(s *ContainerSpec) { s.Routes[0], s.Routes[1] = s.Routes[1], s.Routes[0] },
	} {
		bad := good
		bad.Routes = slices.Clone(good.Routes)
		mutate(&bad)
		if ValidateContainerRoutes(bad, bridge) == nil {
			t.Fatal("unsafe route admitted", n)
		}
	}
	if ValidateContainerRoutes(ContainerSpec{}, bridge) != nil {
		t.Fatal("unaffected original route-free tasks changed")
	}
}
