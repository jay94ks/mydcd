// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/web/sfc"
)

// screenPageSize is the page size of the screen resources list: its rows
// are regrouped from sfcd's, so its cursor is the screen key.
const screenPageSize = 50

// screenResources joins every sfcd resources page of tenant under one
// revision, as the CLI does, and pages the screen rows (resourceEntries)
// after the screen key after. Revision is ResourcesRootRevision and
// Collection NetworkRevision (create-network Expected).
func screenResources(ctx context.Context, c sfc.Conn, tenant, after string) (sfc.Page[sfc.ResourceEntry], error) {
	var rows []control.ResourceEntry
	var first sfc.Page[control.ResourceEntry]
	for next, i := "", 0; i == 0 || next != ""; i++ {
		p, err := c.Resources(ctx, tenant, next)
		if err != nil {
			return sfc.Page[sfc.ResourceEntry]{}, err
		}
		if i == 0 {
			first = p
		} else if p.Revision != first.Revision || p.Collection != first.Collection || p.QuotaRevision != first.QuotaRevision {
			return sfc.Page[sfc.ResourceEntry]{}, &sfc.Error{Method: "resources", Code: sfc.CodeConflict, Detail: "resources changed while reading them"}
		}
		rows = append(rows, p.Items...)
		if p.Next == next {
			break
		}
		next = p.Next
	}
	items := resourceEntries(rows)
	sort.SliceStable(items, func(i, j int) bool { return items[i].Key < items[j].Key })
	out := sfc.Page[sfc.ResourceEntry]{Revision: first.Revision, Collection: first.Collection}
	for _, e := range items {
		if e.Key <= after {
			continue
		}
		if len(out.Items) == screenPageSize {
			out.Next = out.Items[len(out.Items)-1].Key
			break
		}
		out.Items = append(out.Items, e)
	}
	return out, nil
}

// fillNetworkUsers sets each network row's Apps/Standalones from sfcd's
// network-users rows (how many apps and standalone containers use it). A
// failed read leaves the counts out.
func fillNetworkUsers(ctx context.Context, c sfc.Conn, rows []sfc.ResourceEntry) {
	for i, e := range rows {
		if e.Network == nil {
			continue
		}
		_, users, err := publicReadAll(ctx, c, "network-users", e.Tenant, control.PublicReadQuery{Name: e.Network.Name})
		if err != nil {
			continue
		}
		n := *e.Network
		_, n.Apps, n.Standalones = resourceUsers(users, true)
		rows[i].Network = &n
	}
}

// resourceEntries is the screen form of the joined sfcd rows: one row per
// network (a TUN network has one sfcd row per member), limits keyed by
// tenant, routes and bridges as they are. The system network, the system
// row and reservations are not shown.
func resourceEntries(rows []control.ResourceEntry) []sfc.ResourceEntry {
	var out []sfc.ResourceEntry
	nets := map[string]int{} // tenant/name → index in out
	for _, e := range rows {
		switch {
		case e.Limit != nil:
			l := e.Limit
			key := l.Tenant + "/limit/" + l.Node
			if l.Tenant == "" {
				key = "_cluster/limit/" + l.Node
			}
			out = append(out, sfc.ResourceEntry{Key: key, Tenant: l.Tenant, Limit: &sfc.NodeLimit{Node: l.Node, CPUs: float64(l.Capacity.CPU) / cpuUnit,
				MemoryBytes: l.Capacity.Memory, Revision: l.Revision, Networks: l.Networks, MaxConsumers: l.MaxConsumers,
				PacketQueuePackets: l.PacketQueuePackets, PacketQueueBytes: l.PacketQueueBytes, MaxIngressInstances: l.MaxIngressInstances,
				MaxIngressListeners: l.MaxIngressListeners, MaxIngressRequests: l.MaxIngressRequests,
				MaxIngressConnections: l.MaxIngressConnections, IngressBufferBytes: l.IngressBufferBytes}})
		case e.Network != nil && e.Network.System:
			// sfcd keeps the system network itself; it is no workspace's
		case e.Network != nil:
			src := *e.Network
			name, kind := src.ID, "bridge"
			if src.Logical != "" {
				name, kind = src.Logical, "tun"
			}
			k := src.Tenant + "/" + name
			i, ok := nets[k]
			if !ok {
				i = len(out)
				nets[k] = i
				out = append(out, sfc.ResourceEntry{Key: src.Tenant + "/network/" + name, Tenant: src.Tenant, Network: &sfc.Network{Name: name, Kind: kind}})
			}
			n := out[i].Network
			member := sfc.NetworkMember{Node: src.Node, ID: src.ID, Generation: src.Generation, Revision: src.Revision, Draining: src.Draining, Source: src}
			if len(src.Pools) > 0 {
				member.CIDR = src.Pools[0].Prefix.String()
			}
			if len(src.TunnelAddresses) > 0 {
				member.Tunnel = src.TunnelAddresses[0].Addr().String()
			}
			if ch := e.Change; ch != nil {
				member.Change = &sfc.NetworkChange{ID: ch.ID, Generation: ch.Generation, Revision: ch.Revision, TargetRevision: ch.TargetRevision,
					Phase: string(ch.Phase), MetadataOnly: ch.MetadataOnly}
				if len(ch.Target.Pools) > 0 {
					member.Change.TargetCIDR = ch.Target.Pools[0].Prefix.String()
				}
			}
			if e.DNS != nil {
				member.DNS = &sfc.MemberDNS{State: e.DNS.State, Ready: e.DNS.Ready, Resolvers: append([]string{}, e.DNS.Resolvers...)}
				// the address containers on this member ask: the member's own
				// running resolver (address:53)
				if len(e.DNS.Resolvers) > 0 && e.DNS.Policy.Enabled {
					if ap, err := netip.ParseAddrPort(e.DNS.Resolvers[0]); err == nil {
						member.Resolver = ap.Addr().String()
					}
				}
			}
			n.Members = append(n.Members, member)
			n.Toggles = slices.Clone(src.Toggles)
			n.Revision = max(n.Revision, src.Revision)
			if e.DNS != nil {
				// one policy for the network; Resolvers are every member's
				var resolvers []string
				if n.DNS != nil {
					resolvers = n.DNS.Resolvers
				}
				d := sfc.DNSView(e.DNS.Policy, e.DNS.Revision)
				d.Resolvers, d.Ready, d.State = append(resolvers, e.DNS.Resolvers...), e.DNS.Ready, e.DNS.State
				n.DNS = d
			}
		case e.Route != nil:
			var names control.RouteNames
			if e.RouteNames != nil {
				names = *e.RouteNames
			}
			r := sfc.RouteView(*e.Route, names)
			out = append(out, sfc.ResourceEntry{Key: "route/" + e.Route.Source.Tenant + "/" + e.Route.ID, Tenant: e.Route.Source.Tenant, Route: &r})
		case e.Bridge != nil:
			b := sfc.BridgeView(*e.Bridge)
			out = append(out, sfc.ResourceEntry{Key: "bridge/" + b.Owner + "/" + b.Name, Tenant: b.Owner, Bridge: &b})
		}
	}
	for _, e := range out {
		n := e.Network
		if n == nil {
			continue
		}
		slices.SortFunc(n.Members, func(a, b sfc.NetworkMember) int { return strings.Compare(a.Node, b.Node) })
		for _, mb := range n.Members {
			n.Nodes = append(n.Nodes, mb.Node)
		}
		n.CIDR = n.Members[0].CIDR
	}
	return out
}
