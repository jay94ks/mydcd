// SPDX-License-Identifier: Apache-2.0

package network

import (
	"net"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// In a fresh network namespace, a connection to the cluster address reaches
// the container address once SetClusterAppNAT holds it, and not after the
// forward is gone. The table is left exactly as asked each time.
func TestClusterAppNATHandsTheClusterAddressToThePool(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	done, skip := make(chan struct{}), error(nil)
	go func() {
		defer close(done)
		runtime.LockOSThread() // the thread dies with its namespace
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			skip = err
			return
		}
		lo, err := netlink.LinkByName("lo")
		if err == nil {
			err = netlink.LinkSetUp(lo)
		}
		if err == nil {
			err = netlink.AddrAdd(lo, &netlink.Addr{IPNet: &net.IPNet{IP: net.IPv4(10, 254, 1, 2), Mask: net.CIDRMask(32, 32)}})
		}
		if err == nil {
			// this server's own route lookup comes before the output hook
			// (production: setClusterAppRoutes, via the container)
			err = netlink.RouteAdd(&netlink.Route{LinkIndex: lo.Attrs().Index, Dst: &net.IPNet{IP: net.IPv4(10, 254, 0, 0), Mask: net.CIDRMask(24, 32)}})
		}
		if err != nil {
			t.Error(err)
			return
		}
		ln, err := net.Listen("tcp4", "10.254.1.2:0")
		if err != nil {
			t.Error(err)
			return
		}
		defer ln.Close()
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()
		port := ln.Addr().(*net.TCPAddr).Port
		dial := func() error {
			c, err := net.DialTimeout("tcp4", netip.AddrPortFrom(netip.MustParseAddr("10.254.0.2"), uint16(port)).String(), time.Second)
			if err == nil {
				c.Close()
			}
			return err
		}
		if dial() == nil {
			t.Error("reached the cluster address without a forward")
		}
		f := []ClusterAppForward{{Cluster: netip.MustParseAddr("10.254.0.2"), Pool: netip.MustParseAddr("10.254.1.2")}}
		for range 2 { // the second call finds it in place
			if err := SetClusterAppNAT(f); err != nil {
				t.Error(err)
				return
			}
		}
		if err := dial(); err != nil {
			t.Error("forward:", err)
		}
		if present, same, err := clusterAppNATState(&nftables.Conn{}, f); err != nil || !present || !same {
			t.Error(present, same, err)
		}
		// Without the TUN only this server's own connections are rewritten;
		// with it, packets coming in on it are too, and on no other device.
		if got := preroutingRules(t); len(got) != 0 {
			t.Error("prerouting without a TUN:", got)
		}
		f[0].In = "mt0123456789ab"
		if err := SetClusterAppNAT(f); err != nil {
			t.Error(err)
		}
		if got := preroutingRules(t); len(got) != 1 || !strings.Contains(got[0], "<mt0123456789ab") {
			t.Error("prerouting:", got)
		}
		if err := dial(); err != nil {
			t.Error("own connection with a TUN:", err)
		}
		if err := SetClusterAppNAT(nil); err != nil {
			t.Error(err)
		}
		if present, _, err := clusterAppNATState(&nftables.Conn{}, nil); err != nil || present {
			t.Error("table left", err)
		}
		if dial() == nil {
			t.Error("reached the cluster address after the forward was removed")
		}
		for _, bad := range []ClusterAppForward{{Cluster: netip.MustParseAddr("10.30.0.2"), Pool: f[0].Pool}, {Cluster: f[0].Cluster, Pool: netip.MustParseAddr("10.254.240.9")}} {
			if SetClusterAppNAT([]ClusterAppForward{bad}) == nil {
				t.Error("accepted", bad)
			}
		}
	}()
	<-done
	if skip != nil {
		t.Skip("no network namespace:", skip)
	}
}

// The host route for a cluster address goes via the container and is
// removed with the forward; other routes stay.
func TestClusterAppRoutesFollowTheForwards(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	done, skip := make(chan struct{}), error(nil)
	go func() {
		defer close(done)
		runtime.LockOSThread()
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			skip = err
			return
		}
		tun := &netlink.Tuntap{LinkAttrs: netlink.LinkAttrs{Name: "sys0"}, Mode: netlink.TUNTAP_MODE_TUN}
		err := netlink.LinkAdd(tun)
		if err == nil {
			err = netlink.AddrAdd(tun, &netlink.Addr{IPNet: &net.IPNet{IP: net.IPv4(10, 254, 1, 1), Mask: net.CIDRMask(24, 32)}})
		}
		if err == nil {
			err = netlink.LinkSetUp(tun)
		}
		other := netlink.Route{LinkIndex: tun.Attrs().Index, Dst: &net.IPNet{IP: net.IPv4(10, 254, 0, 9), Mask: net.CIDRMask(32, 32)}}
		if err == nil {
			err = netlink.RouteAdd(&other)
		}
		if err != nil {
			t.Error(err)
			return
		}
		list := func() []string {
			rows, err := netlink.RouteList(nil, netlink.FAMILY_V4)
			if err != nil {
				t.Error(err)
				return nil
			}
			var out []string
			for _, r := range rows {
				if r.Dst != nil && ClusterBlock.Contains(netip.MustParseAddr(r.Dst.IP.String())) {
					out = append(out, r.Dst.String()+" "+r.Gw.String())
				}
			}
			return out
		}
		f := []ClusterAppForward{{Cluster: netip.MustParseAddr("10.254.0.2"), Pool: netip.MustParseAddr("10.254.1.2")}}
		for range 2 {
			if err := setClusterAppRoutes(f); err != nil {
				t.Error(err)
				return
			}
		}
		if got := list(); !slices.Equal(got, []string{"10.254.0.2/32 10.254.1.2", "10.254.0.9/32 <nil>"}) {
			t.Error(got)
		}
		if err := setClusterAppRoutes(nil); err != nil {
			t.Error(err)
		}
		if got := list(); !slices.Equal(got, []string{"10.254.0.9/32 <nil>"}) {
			t.Error(got)
		}
	}()
	<-done
	if skip != nil {
		t.Skip("no network namespace:", skip)
	}
}

// preroutingRules are the tags of the prerouting chain's rules, after
// checking each one matches its input device first.
func preroutingRules(t *testing.T) []string {
	c := &nftables.Conn{}
	table := &nftables.Table{Name: clusterAppNATTable, Family: nftables.TableFamilyIPv4}
	rules, err := c.GetRules(table, &nftables.Chain{Name: "prerouting", Table: table})
	if err != nil {
		t.Error(err)
		return nil
	}
	var out []string
	for _, r := range rules {
		if m, ok := r.Exprs[0].(*expr.Meta); !ok || m.Key != expr.MetaKeyIIFNAME {
			t.Error("prerouting rule does not match its input device first")
		}
		out = append(out, string(r.UserData))
	}
	return out
}
