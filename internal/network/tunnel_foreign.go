// SPDX-License-Identifier: Apache-2.0

package network

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/vishvananda/netlink"
)

const tunnelAliasPrefix = "sfc-tun-1:"

// describeRouteDevice names the device a conflicting route points at, so the
// error says which device holds it. A sfc TUN there is either another
// network's TUN of this cluster routing the same prefix, or one left from an
// earlier cluster on this server.
func describeRouteDevice(index int) string {
	link, err := netlink.LinkByIndex(index)
	if err != nil {
		return fmt.Sprintf("ifindex %d", index)
	}
	a := link.Attrs()
	if strings.HasPrefix(a.Alias, tunnelAliasPrefix) {
		return fmt.Sprintf("device %s (another sfc TUN on this server: either another network of this cluster routes the same prefix, or the device is left from an earlier cluster and ip link del %s removes it)", a.Name, a.Name)
	}
	return fmt.Sprintf("device %s", a.Name)
}

// ForeignDevices lists the sfc TUN devices on this host that this journal's
// records do not name, with the routes they hold. After a re-init the old
// cluster's TUNs stay and can hold this cluster's routes. A retained owner
// from a key rotation also has its own TUNs, so callers only warn.
func (m *TunnelManager) ForeignDevices() ([]string, error) {
	own := map[string]bool{}
	for _, key := range m.journal.Keys() {
		r, err := m.journal.Read(key)
		if err != nil {
			continue
		}
		targets := []reconcile.Resource{r.State.Applied, r.State.Desired.Resource}
		if r.State.Pending != nil {
			targets = append(targets, r.State.Pending.Target)
		}
		for _, t := range targets {
			if !t.Present {
				continue
			}
			if _, id, err := m.driver.parameters(key, reconcile.Operation{Target: t}); err == nil {
				own[id.name] = true
			}
		}
	}
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	var notes []string
	for _, link := range links {
		a := link.Attrs()
		if own[a.Name] || !strings.HasPrefix(a.Name, "mt") || !strings.HasPrefix(a.Alias, tunnelAliasPrefix) {
			continue
		}
		routes, _ := netlink.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{LinkIndex: a.Index}, netlink.RT_FILTER_OIF)
		notes = append(notes, fmt.Sprintf("%s [%s]", a.Name, strings.Join(routePrefixes(routes), " ")))
	}
	sort.Strings(notes)
	return notes, nil
}

func routePrefixes(routes []netlink.Route) []string {
	var out []string
	for _, r := range routes {
		if r.Dst == nil {
			continue
		}
		if p, ok := netip.AddrFromSlice(r.Dst.IP); ok {
			ones, _ := r.Dst.Mask.Size()
			out = append(out, netip.PrefixFrom(p.Unmap(), ones).String())
		}
	}
	sort.Strings(out)
	return out
}
