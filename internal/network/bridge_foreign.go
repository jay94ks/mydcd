// SPDX-License-Identifier: Apache-2.0

package network

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/vishvananda/netlink"
)

// sfcBridgeName is the engine's bridge device name for a managed Bridge:
// "md" and 12 lowercase hex digits (bridgeDeviceName).
func sfcBridgeName(name string) bool {
	return len(name) == 14 && strings.HasPrefix(name, "md") && strings.Trim(name[2:], "0123456789abcdef") == ""
}

// ownBridgeNames are the bridge devices the records of j name.
func (m *Manager) ownBridgeNames(j *reconcile.Journal, own map[string]bool) {
	for _, key := range j.Keys() {
		r, err := j.Read(key)
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
				own[bridgeDeviceName(id)] = true
			}
		}
	}
}

// ForeignBridges lists the sfc bridge devices (md + 12 hex) on this host
// that neither this journal nor a retained owner's journal names, with their
// state and addresses. Wiping the state directories of an earlier cluster
// leaves its bridges in the kernel; one with the same subnet as a bridge of
// this cluster keeps a connected route that can take this cluster's traffic
// (lab 2026-11-28: 10.254.0.2 via 10.254.1.2 went to a stale DOWN bridge).
// A note says which current bridge it overlaps. Callers only warn.
func (m *Manager) ForeignBridges() ([]string, error) {
	own := map[string]bool{}
	m.ownBridgeNames(m.journal, own)
	m.admitMu.Lock()
	retained := make([]*Manager, 0, len(m.retained))
	for _, other := range m.retained {
		retained = append(retained, other)
	}
	m.admitMu.Unlock()
	for _, other := range retained {
		other.ownBridgeNames(other.journal, own)
	}
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	addresses := func(link netlink.Link) []*net.IPNet {
		var out []*net.IPNet
		list, _ := netlink.AddrList(link, netlink.FAMILY_ALL)
		for _, a := range list {
			if a.IPNet != nil && !a.IP.IsLinkLocalUnicast() {
				out = append(out, a.IPNet)
			}
		}
		return out
	}
	current := map[string][]*net.IPNet{}
	for _, link := range links {
		if a := link.Attrs(); own[a.Name] && link.Type() == "bridge" {
			current[a.Name] = addresses(link)
		}
	}
	var notes []string
	for _, link := range links {
		a := link.Attrs()
		if own[a.Name] || link.Type() != "bridge" || !sfcBridgeName(a.Name) {
			continue
		}
		state := "DOWN"
		if a.Flags&net.FlagUp != 0 {
			state = "UP"
		}
		var prefixes, overlaps []string
		for _, n := range addresses(link) {
			prefixes = append(prefixes, n.String())
			for name, mine := range current {
				for _, c := range mine {
					if c.Contains(n.IP) || n.Contains(c.IP) {
						overlaps = append(overlaps, name)
					}
				}
			}
		}
		note := fmt.Sprintf("%s %s [%s]", a.Name, state, strings.Join(prefixes, " "))
		if len(overlaps) > 0 {
			sort.Strings(overlaps)
			note += " same subnet as this cluster's " + strings.Join(overlaps, ", ")
		}
		notes = append(notes, note)
	}
	sort.Strings(notes)
	return notes, nil
}
