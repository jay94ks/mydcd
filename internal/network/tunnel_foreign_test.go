// SPDX-License-Identifier: Apache-2.0

package network

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestForeignTunnelNotes(t *testing.T) {
	_, a, _ := net.ParseCIDR("10.254.2.0/24")
	_, b, _ := net.ParseCIDR("10.254.1.0/24")
	got := routePrefixes([]netlink.Route{{Dst: a}, {}, {Dst: b}})
	if len(got) != 2 || got[0] != "10.254.1.0/24" || got[1] != "10.254.2.0/24" {
		t.Fatal(got)
	}
	if d := describeRouteDevice(1 << 30); d != "ifindex 1073741824" {
		t.Fatal(d)
	}
}
