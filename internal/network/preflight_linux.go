// SPDX-License-Identifier: Apache-2.0

package network

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"

	"github.com/moby/moby/client"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// CheckBridgeSpace checks the real Engine and host routes for an uncreated
// immutable bridge demand. Existing exact sources use Manager.Inspect instead.
// It creates no bridge, route, allocation, or provisional native generation.
func (m *Manager) CheckBridgeSpace(ctx context.Context, prefixes []netip.Prefix) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(prefixes) == 0 {
		return ErrPolicy
	}
	items, err := m.driver.Engine.API.NetworkList(ctx, client.NetworkListOptions{})
	if err != nil {
		return err
	}
	for _, item := range items.Items {
		got, err := m.driver.Engine.API.NetworkInspect(ctx, item.ID, client.NetworkInspectOptions{})
		if err != nil {
			return err
		}
		for _, pool := range got.Network.IPAM.Config {
			if !pool.Subnet.IsValid() {
				continue
			}
			for _, prefix := range prefixes {
				if prefix.Overlaps(pool.Subnet) {
					return fmt.Errorf("planned bridge CIDR %s conflicts with an existing Engine network", prefix)
				}
			}
		}
	}
	routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	for _, route := range routes {
		if route.Dst == nil {
			continue
		}
		bits, _ := route.Dst.Mask.Size()
		if bits == 0 {
			continue
		}
		address, ok := netip.AddrFromSlice(route.Dst.IP)
		if !ok {
			return ErrPolicy
		}
		actual := netip.PrefixFrom(address.Unmap(), bits).Masked()
		for _, prefix := range prefixes {
			if prefix.Overlaps(actual) {
				return fmt.Errorf("planned bridge CIDR %s conflicts with a host route", prefix)
			}
		}
	}
	return ctx.Err()
}

// CheckAccess checks the same local privilege/device boundary required by the
// real TUN driver. It neither issues TUNSETIFF nor changes routes/firewalls.
func (m *TunnelManager) CheckAccess(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.driver.mu.Lock()
	defer m.driver.mu.Unlock()
	if m.driver.closed {
		return os.ErrClosed
	}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&header, &data[0]); err != nil {
		return err
	}
	if data[0].Effective&(uint32(1)<<uint(unix.CAP_NET_ADMIN)) == 0 {
		return unix.EPERM
	}
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	var stat unix.Stat_t
	err = unix.Fstat(fd, &stat)
	if err == nil && (stat.Mode&unix.S_IFMT != unix.S_IFCHR || unix.Major(stat.Rdev) != 10 || unix.Minor(stat.Rdev) != 200) {
		err = ErrKernelOwnership
	}
	return errors.Join(err, unix.Close(fd))
}
