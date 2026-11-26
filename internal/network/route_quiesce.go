// SPDX-License-Identifier: Apache-2.0

package network

import (
	"context"
	"errors"
	"net/netip"
	"os"

	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/vishvananda/netlink"
)

// Ownership is the intersection of the original policy mark and its exact
// protocol/CIDR/port direction. Never flush a table or delete by mark alone.
type routeConntrackFilter struct{ spec TunnelSpec }

func (f routeConntrackFilter) tuple(t netlink.IPTuple) bool {
	p := f.spec.RoutePolicy
	source, a := netip.AddrFromSlice(t.SrcIP)
	destination, b := netip.AddrFromSlice(t.DstIP)
	if p == nil || !a || !b || t.Protocol != p.Protocol {
		return false
	}
	source, destination = source.Unmap(), destination.Unmap()
	port := uint16(0)
	if p.Source.Contains(source) && p.Destination.Contains(destination) {
		port = t.DstPort
	} else if p.Destination.Contains(source) && p.Source.Contains(destination) {
		port = t.SrcPort
	}
	for _, allowed := range p.Ports {
		if port >= allowed.First && port <= allowed.Last {
			return true
		}
	}
	return false
}

func (f routeConntrackFilter) MatchConntrackFlow(flow *netlink.ConntrackFlow) bool {
	return flow != nil && flow.Mark == routeMark(f.spec) && (f.tuple(flow.Forward) || f.tuple(flow.Reverse))
}

// QuiesceRoute is the monotonic packet-retirement stage of the original
// TunnelDriver. The owner has durably fenced admission and joined all reader/
// callback/write users BEFORE calling. A successful return requires positive
// fenced native readback and a complete, empty owned conntrack census.
func (d *TunnelDriver) QuiesceRoute(ctx context.Context, key string, resource reconcile.Resource) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return os.ErrClosed
	}
	s, id, err := d.parameters(key, reconcile.Operation{Target: resource})
	if err != nil || s.RoutePolicy == nil {
		return errors.Join(err, ErrPolicy)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	link, linkErr := netlink.LinkByName(id.name)
	if linkErr != nil && !missingLink(linkErr) {
		return linkErr
	}
	if linkErr == nil && !ownTunnel(link, id) {
		return ErrKernelOwnership
	}
	if _, _, err := inspectRouteSelector(s, link); err != nil {
		return err
	}
	_, table, err := lookupTunnelFirewallEither(s, id)
	if err != nil {
		return err
	}
	if table != nil {
		if err := fenceTunnelFirewall(s, id); err != nil {
			return err
		}
	} else if linkErr == nil {
		return ErrKernelOwnership // A live device lost its original policy.
	}
	family := netlink.InetFamily(netlink.FAMILY_V6)
	if s.RoutePolicy.Source.Addr().Is4() {
		family = netlink.InetFamily(netlink.FAMILY_V4)
	}
	filter := routeConntrackFilter{spec: s}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := netlink.ConntrackDeleteFilter(netlink.ConntrackTable, family, filter); err != nil {
		return err
	}
	flows, err := netlink.ConntrackTableList(netlink.ConntrackTable, family)
	if err != nil {
		return err
	}
	for _, flow := range flows {
		if filter.MatchConntrackFlow(flow) {
			return ErrKernelOwnership
		}
	}
	if table != nil {
		_, fenced, err := lookupTunnelFirewallMode(s, id, true)
		if err != nil || fenced == nil {
			return errors.Join(err, ErrKernelOwnership)
		}
	}
	return ctx.Err()
}
