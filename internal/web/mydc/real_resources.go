// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"context"
	"slices"
	"strings"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/userauth"
)

// realPageSize is the page size of lists the real adapter joins and
// regroups itself (resources): the screen form of a page differs from the
// mydcd rows, so the cursor is the screen key.
const realPageSize = 50

// Resources joins every mydcd resources page under one revision, as the
// CLI does, and regroups the per-server network rows into one network each
// (a TUN network has one row per member). Reservations are not shown.
func (c *realConn) Resources(ctx context.Context, tenant, after string) (Page[ResourceEntry], error) {
	const m = "resources"
	var rows []control.ResourceEntry
	var root, networks, quotas uint64
	for next, first := "", true; first || next != ""; first = false {
		reply, err := realCall(ctx, c, m, func(u userauth.Client, s access.Session) (userauth.Reply, error) {
			return u.ResourcePage(ctx, c.peer, s, tenant, next)
		})
		if err != nil {
			return Page[ResourceEntry]{}, err
		}
		if first {
			root, networks, quotas = reply.ResourcesRootRevision, reply.NetworkRevision, reply.QuotaRevision
		} else if reply.ResourcesRootRevision != root || reply.NetworkRevision != networks || reply.QuotaRevision != quotas {
			return Page[ResourceEntry]{}, fail(m, CodeConflict, "resources changed while reading them")
		}
		rows = append(rows, reply.Resources...)
		next = reply.ResourcesNext
	}
	p := paginate(resourceEntries(rows), func(e ResourceEntry) string { return e.Key }, after, realPageSize, root)
	p.Collection = networks
	return p, nil
}

// resourceEntries is the screen form of the joined mydcd rows.
func resourceEntries(rows []control.ResourceEntry) []ResourceEntry {
	var out []ResourceEntry
	nets := map[string]int{} // tenant/name → index in out
	for _, e := range rows {
		switch {
		case e.Limit != nil:
			l := e.Limit
			key := l.Tenant + "/limit/" + l.Node
			if l.Tenant == "" {
				key = "_cluster/limit/" + l.Node
			}
			out = append(out, ResourceEntry{Key: key, Tenant: l.Tenant, Limit: &NodeLimit{Node: l.Node, CPUs: float64(l.Capacity.CPU) / cpuUnit,
				MemoryBytes: l.Capacity.Memory, Revision: l.Revision, Networks: l.Networks, MaxConsumers: l.MaxConsumers,
				PacketQueuePackets: l.PacketQueuePackets, PacketQueueBytes: l.PacketQueueBytes, MaxIngressInstances: l.MaxIngressInstances,
				MaxIngressListeners: l.MaxIngressListeners, MaxIngressRequests: l.MaxIngressRequests,
				MaxIngressConnections: l.MaxIngressConnections, IngressBufferBytes: l.IngressBufferBytes}})
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
				out = append(out, ResourceEntry{Key: src.Tenant + "/network/" + name, Tenant: src.Tenant, Network: &Network{Name: name, Kind: kind}})
			}
			n := out[i].Network
			member := NetworkMember{Node: src.Node, ID: src.ID, Generation: src.Generation, Revision: src.Revision, Draining: src.Draining, Source: src}
			if len(src.Pools) > 0 {
				member.CIDR = src.Pools[0].Prefix.String()
			}
			if len(src.TunnelAddresses) > 0 {
				member.Tunnel = src.TunnelAddresses[0].Addr().String()
			}
			if ch := e.Change; ch != nil {
				member.Change = &NetworkChange{ID: ch.ID, Generation: ch.Generation, Revision: ch.Revision, TargetRevision: ch.TargetRevision,
					Phase: string(ch.Phase), MetadataOnly: ch.MetadataOnly}
				if len(ch.Target.Pools) > 0 {
					member.Change.TargetCIDR = ch.Target.Pools[0].Prefix.String()
				}
			}
			n.Members = append(n.Members, member)
			n.Toggles = slices.Clone(src.Toggles)
			n.Revision = max(n.Revision, src.Revision)
			if e.DNS != nil {
				d := dnsView(e.DNS.Policy, e.DNS.Revision)
				d.Resolvers, d.Ready, d.State = append([]string{}, e.DNS.Resolvers...), e.DNS.Ready, e.DNS.State
				n.DNS = d
			}
		case e.Route != nil:
			r := RouteView(*e.Route)
			out = append(out, ResourceEntry{Key: "route/" + e.Route.Source.Tenant + "/" + e.Route.ID, Tenant: e.Route.Source.Tenant, Route: &r})
		}
	}
	for _, e := range out {
		n := e.Network
		if n == nil {
			continue
		}
		slices.SortFunc(n.Members, func(a, b NetworkMember) int { return strings.Compare(a.Node, b.Node) })
		for _, mb := range n.Members {
			n.Nodes = append(n.Nodes, mb.Node)
		}
		n.CIDR = n.Members[0].CIDR
	}
	return out
}
