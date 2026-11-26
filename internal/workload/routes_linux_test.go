// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"net"
	"net/netip"
	"os"
	"testing"

	"github.com/moby/moby/api/types/container"
	"github.com/vishvananda/netlink"
)

func TestTaskRouteReadbackRejectsForeignAttributes(t *testing.T) {
	want := taskRoute(3, ContainerRoute{Destination: netip.MustParsePrefix("198.19.80.16/28"), Gateway: netip.MustParseAddr("198.19.80.1")})
	if !sameTaskRoute(want, want) {
		t.Fatal("original exact route rejected")
	}
	for n, mutate := range []func(*netlink.Route){
		func(r *netlink.Route) { r.Table = 777 },
		func(r *netlink.Route) { r.Priority++ },
		func(r *netlink.Route) { r.Protocol++ },
		func(r *netlink.Route) { r.LinkIndex++ },
		func(r *netlink.Route) { r.Gw = net.IPv4(198, 19, 80, 3) },
		func(r *netlink.Route) { r.Src = net.IPv4(198, 19, 80, 3) },
		func(r *netlink.Route) { r.MTU = 1400 },
		func(r *netlink.Route) { r.Flags = 1 },
	} {
		bad := want
		mutate(&bad)
		if sameTaskRoute(bad, want) {
			t.Fatal("foreign route accepted", n)
		}
	}
}

func TestTaskRouteHandleRejectsNodeNamespace(t *testing.T) {
	got := container.InspectResponse{State: &container.State{Running: true, Pid: os.Getpid()}, NetworkSettings: &container.NetworkSettings{SandboxID: "foreign-node", SandboxKey: "/proc/self/ns/net"}}
	h, err := containerRouteHandle(got)
	if h != nil {
		h.Close()
		t.Fatal("opened node namespace for Task routing")
	}
	if err == nil {
		t.Fatal("node namespace accepted")
	}
}
