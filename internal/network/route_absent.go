// SPDX-License-Identifier: Apache-2.0

package network

import (
	"context"
	"errors"
	"os"

	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/vishvananda/netlink"
)

// RouteAbsent is read-only. Absence alone proves neither an unsent Apply nor
// original execution termination. The owner must establish that separately.
// In particular this never repairs/removes a same-named current-kernel object.
func (d *TunnelDriver) RouteAbsent(ctx context.Context, key string, resource reconcile.Resource) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return false, os.ErrClosed
	}
	s, id, err := d.parameters(key, reconcile.Operation{Target: resource})
	if err != nil || !hasRouteSelector(s) {
		return false, errors.Join(err, ErrPolicy)
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if _, held := d.files[key]; held {
		return false, ErrKernelOwnership
	}
	outcome, err := d.inspect(s, id, reconcile.Remove)
	if err != nil || outcome != reconcile.EffectApplied {
		return false, errors.Join(err, ErrKernelOwnership)
	}
	family := netlink.InetFamily(netlink.FAMILY_V6)
	if s.RoutePolicy.Source.Addr().Is4() {
		family = netlink.InetFamily(netlink.FAMILY_V4)
	}
	flows, err := netlink.ConntrackTableList(netlink.ConntrackTable, family)
	if err != nil {
		return false, err
	}
	filter := routeConntrackFilter{spec: s}
	for _, flow := range flows {
		if filter.MatchConntrackFlow(flow) {
			return false, ErrKernelOwnership
		}
	}
	outcome, err = d.inspect(s, id, reconcile.Remove)
	if err != nil || outcome != reconcile.EffectApplied {
		return false, errors.Join(err, ErrKernelOwnership)
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return true, nil
}
