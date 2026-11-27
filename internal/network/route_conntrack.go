// SPDX-License-Identifier: Apache-2.0

package network

import (
	"context"
	"errors"
	"net/netip"
	"os"

	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/vishvananda/netlink"
)

// A conntrack tuple is canonical policy source->destination, regardless of
// which kernel direction carries those addresses. TCP flags are not identity.
func routeConntrackTuple(spec TunnelSpec, t netlink.IPTuple) (TransportPacket, bool) {
	if !(routeConntrackFilter{spec}).tuple(t) {
		return TransportPacket{}, false
	}
	source, ok := netip.AddrFromSlice(t.SrcIP)
	if !ok {
		return TransportPacket{}, false
	}
	destination, ok := netip.AddrFromSlice(t.DstIP)
	if !ok {
		return TransportPacket{}, false
	}
	tuple := TransportPacket{Source: source.Unmap(), Destination: destination.Unmap(), SourcePort: t.SrcPort, DestinationPort: t.DstPort, Protocol: t.Protocol}
	if !spec.RoutePolicy.Source.Contains(tuple.Source) {
		tuple.Source, tuple.Destination = tuple.Destination, tuple.Source
		tuple.SourcePort, tuple.DestinationPort = tuple.DestinationPort, tuple.SourcePort
	}
	return tuple, tuple.SourcePort != 0 && tuple.DestinationPort != 0
}

type routeFlowConntrackFilter struct {
	spec  TunnelSpec
	tuple TransportPacket
}

func (f routeFlowConntrackFilter) MatchConntrackFlow(flow *netlink.ConntrackFlow) bool {
	if !(routeConntrackFilter{f.spec}).MatchConntrackFlow(flow) {
		return false
	}
	for _, direction := range []netlink.IPTuple{flow.Forward, flow.Reverse} {
		if tuple, ok := routeConntrackTuple(f.spec, direction); ok && tuple == f.tuple {
			return true
		}
	}
	return false
}

// Caller holds d.mu. Never manufacture an empty census for an absent/fenced,
// foreign, partially installed, changed or closed original native target.
func (d *TunnelDriver) activeRouteConntrack(ctx context.Context, key string, resource reconcile.Resource) (TunnelSpec, tunnelIdentity, netlink.InetFamily, error) {
	var family netlink.InetFamily
	if d.closed {
		return TunnelSpec{}, tunnelIdentity{}, family, os.ErrClosed
	}
	s, id, err := d.parameters(key, reconcile.Operation{Target: resource})
	if err != nil || s.RoutePolicy == nil || s.RoutePolicy.Bridge == "" {
		return s, id, family, errors.Join(err, ErrPolicy)
	}
	if err = ctx.Err(); err != nil {
		return s, id, family, err
	}
	outcome, err := d.inspect(s, id, reconcile.Apply)
	if err != nil || outcome != reconcile.EffectApplied {
		return s, id, family, errors.Join(err, ErrKernelOwnership)
	}
	family = netlink.InetFamily(netlink.FAMILY_V6)
	if s.RoutePolicy.Source.Addr().Is4() {
		family = netlink.InetFamily(netlink.FAMILY_V4)
	}
	return s, id, family, ctx.Err()
}

// RouteConntrackCensus returns only owned canonical tuples from a COMPLETE
// kernel dump. Any dump/readback/context failure returns no usable census.
func (d *TunnelDriver) RouteConntrackCensus(ctx context.Context, key string, resource reconcile.Resource) (map[TransportPacket]bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	s, id, family, err := d.activeRouteConntrack(ctx, key, resource)
	if err != nil {
		return nil, err
	}
	flows, err := netlink.ConntrackTableList(netlink.ConntrackTable, family)
	if err != nil {
		return nil, err
	}
	filter := routeConntrackFilter{s}
	result := map[TransportPacket]bool{}
	for _, flow := range flows {
		if !filter.MatchConntrackFlow(flow) {
			continue
		}
		for _, direction := range []netlink.IPTuple{flow.Forward, flow.Reverse} {
			if tuple, ok := routeConntrackTuple(s, direction); ok {
				result[tuple] = true
			}
		}
	}
	outcome, err := d.inspect(s, id, reconcile.Apply)
	if err != nil || outcome != reconcile.EffectApplied {
		return nil, errors.Join(err, ErrKernelOwnership)
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

// DrainRouteFlow is used only after the original flow is durably Closing and
// packet IO passed its barrier. It touches that exact mark+policy+tuple; an
// error or recreated row preserves the original flow pin for later recovery.
func (d *TunnelDriver) DrainRouteFlow(ctx context.Context, key string, resource reconcile.Resource, tuple TransportPacket) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	s, id, family, err := d.activeRouteConntrack(ctx, key, resource)
	if err != nil {
		return err
	}
	tuple.TCPFlags = 0
	p := s.RoutePolicy
	if tuple.Protocol != p.Protocol || tuple.SourcePort == 0 || tuple.DestinationPort == 0 || !p.Source.Contains(tuple.Source) || !p.Destination.Contains(tuple.Destination) {
		return ErrPolicy
	}
	portAllowed := false
	for _, ports := range p.Ports {
		portAllowed = portAllowed || tuple.DestinationPort >= ports.First && tuple.DestinationPort <= ports.Last
	}
	if !portAllowed {
		return ErrPolicy
	}
	filter := routeFlowConntrackFilter{s, tuple}
	if _, err = netlink.ConntrackDeleteFilter(netlink.ConntrackTable, family, filter); err != nil {
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
	outcome, err := d.inspect(s, id, reconcile.Apply)
	if err != nil || outcome != reconcile.EffectApplied {
		return errors.Join(err, ErrKernelOwnership)
	}
	return ctx.Err()
}
