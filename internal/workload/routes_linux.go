// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"time"

	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/network"
	"github.com/moby/moby/api/types/container"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// The caller has verified the original immutable container and bridge pin.
// Both Docker's sandbox and its running PID must name the SAME namespace,
// distinct from the node. Never route through the node's default netlink handle.
func containerRouteHandle(got container.InspectResponse) (*netlink.Handle, error) {
	if got.State == nil || !got.State.Running || got.State.Pid < 1 || got.NetworkSettings == nil || got.NetworkSettings.SandboxID == "" || got.NetworkSettings.SandboxKey == "" {
		return nil, engine.ErrOwnership
	}
	f, err := os.Open(got.NetworkSettings.SandboxKey)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	owned, err := f.Stat()
	if err != nil {
		return nil, err
	}
	pid, err := os.Stat(fmt.Sprintf("/proc/%d/ns/net", got.State.Pid))
	if err != nil {
		return nil, err
	}
	node, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		return nil, err
	}
	if !os.SameFile(owned, pid) || os.SameFile(owned, node) {
		return nil, engine.ErrOwnership
	}
	h, err := netlink.NewHandleAt(netns.NsHandle(f.Fd()), unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	if err = h.SetSocketTimeout(time.Second); err != nil {
		h.Close()
		return nil, err
	}
	return h, nil
}

func taskRoute(link int, r ContainerRoute) netlink.Route {
	return netlink.Route{LinkIndex: link, Dst: &net.IPNet{IP: net.IP(r.Destination.Addr().AsSlice()), Mask: net.CIDRMask(r.Destination.Bits(), r.Destination.Addr().BitLen())}, Gw: net.IP(r.Gateway.AsSlice()), Table: unix.RT_TABLE_MAIN, Protocol: unix.RTPROT_STATIC, Scope: netlink.SCOPE_UNIVERSE, Type: unix.RTN_UNICAST, Priority: 100}
}

func sameTaskRoute(got, want netlink.Route) bool {
	if got.Dst == nil || want.Dst == nil || got.Dst.String() != want.Dst.String() || !got.Gw.Equal(want.Gw) {
		return false
	}
	// Normalize only representation supplied by the kernel, not foreign route
	// attributes (policy table/protocol/metric/multipath/MTU/source/etc.).
	got.Dst = want.Dst
	got.Gw = want.Gw
	got.Family = want.Family
	if len(got.Src) == 0 {
		got.Src = nil
	}
	if len(got.MultiPath) == 0 {
		got.MultiPath = nil
	}
	return reflect.DeepEqual(got, want)
}

func inspectTaskRoute(h *netlink.Handle, want netlink.Route) (bool, error) {
	family := netlink.FAMILY_V6
	if want.Gw.To4() != nil {
		family = netlink.FAMILY_V4
	}
	rows, err := h.RouteListFiltered(family, &netlink.Route{Dst: want.Dst, Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_DST|netlink.RT_FILTER_TABLE)
	if err != nil {
		return false, err
	}
	if len(rows) == 0 {
		return false, nil
	}
	if len(rows) != 1 || !sameTaskRoute(rows[0], want) {
		return false, engine.ErrOwnership
	}
	return true, nil
}

func containerRoutes(ctx context.Context, s ContainerSpec, bridge network.BridgeSpec, got container.InspectResponse, apply bool) (bool, error) {
	if err := ValidateContainerRoutes(s, bridge); err != nil {
		return false, err
	}
	if len(s.Routes) == 0 {
		return true, nil
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	h, err := containerRouteHandle(got)
	if err != nil {
		return false, err
	}
	defer h.Close()
	links, err := h.LinkList()
	if err != nil {
		return false, err
	}
	all := true
	for _, r := range s.Routes {
		local := s.IPv6
		if r.Gateway.Is4() {
			local = s.IPv4
		}
		index := 0
		for _, link := range links {
			addresses, e := h.AddrList(link, netlink.FAMILY_ALL)
			if e != nil {
				return false, e
			}
			for _, a := range addresses {
				if a.IP.Equal(net.IP(local.AsSlice())) {
					if index != 0 {
						return false, engine.ErrOwnership
					}
					index = link.Attrs().Index
				}
			}
		}
		if index == 0 {
			return false, engine.ErrOwnership
		}
		want := taskRoute(index, r)
		present, e := inspectTaskRoute(h, want)
		if e != nil {
			return false, e
		}
		if !present && apply {
			if e = ctx.Err(); e != nil {
				return false, e
			}
			// Add only. EEXIST or an inconclusive result must pass the same
			// exact readback; never replace a route supplied by another owner.
			addErr := h.RouteAdd(&want)
			present, e = inspectTaskRoute(h, want)
			if e != nil {
				return false, e
			}
			if !present {
				return false, errors.Join(engine.ErrOwnership, addErr)
			}
		}
		all = all && present
	}
	return all, nil
}
