// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"math"
	"net/netip"
	"slices"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/workload"
)

// resourceRows turns one of the fake's screen-shaped resource rows into
// sfcd's `resources` rows (control.Resources.Page): one per network member
// (its tenancy.Network source, the change with its target, the network's
// DNS policy with this member's readback) and one per limit. The screen
// regroups them (internal/web/server resourceEntries).
func (w *world) resourceRows(r ResourceEntry) []control.ResourceEntry {
	var out []control.ResourceEntry
	if l := r.Limit; l != nil {
		v := tenancy.NodeLimit{Tenant: r.Tenant, Node: l.Node, Revision: l.Revision, Capacity: workload.Resources{CPU: uint64(math.Round(l.CPUs * cpuUnit)), Memory: l.MemoryBytes},
			Networks: l.Networks, MaxConsumers: l.MaxConsumers, PacketQueuePackets: l.PacketQueuePackets, PacketQueueBytes: l.PacketQueueBytes,
			MaxIngressInstances: l.MaxIngressInstances, MaxIngressListeners: l.MaxIngressListeners, MaxIngressRequests: l.MaxIngressRequests,
			MaxIngressConnections: l.MaxIngressConnections, IngressBufferBytes: l.IngressBufferBytes}
		out = append(out, control.ResourceEntry{Key: "limit/" + r.Tenant + "/" + l.Node, Limit: &v})
	}
	n := r.Network
	if n == nil {
		return out
	}
	for _, m := range n.Members {
		src := m.Source
		src.Pools = slices.Clone(src.Pools)
		src.TunnelAddresses = slices.Clone(src.TunnelAddresses)
		src.Toggles = slices.Clone(n.Toggles)
		e := control.ResourceEntry{Key: "network/" + src.Tenant + "/" + src.ID, Network: &src}
		if ch := m.Change; ch != nil {
			target, ok := w.netTargets[src.Tenant+"/"+src.ID]
			if !ok {
				target = src
				if p, err := netip.ParsePrefix(ch.TargetCIDR); err == nil && len(target.Pools) > 0 {
					target.Pools = slices.Clone(target.Pools)
					target.Pools[0].Prefix = p
				}
			}
			e.Change = &control.NetworkChangeStatus{ID: ch.ID, Generation: ch.Generation, Revision: ch.Revision, TargetRevision: ch.TargetRevision,
				Phase: tenancy.ChangePhase(ch.Phase), MetadataOnly: ch.MetadataOnly, Target: target}
		}
		if d := n.DNS; d != nil {
			v := control.DNSPolicyView{Revision: d.Revision, Policy: d.Policy, Resolvers: slices.Clone(d.Resolvers), Ready: d.Ready, State: d.State}
			// each member answers on its own resolver (the fake's: its gateway)
			v.Resolvers = nil
			if m.Resolver != "" {
				v.Resolvers = []string{m.Resolver + ":53"}
			}
			if md := m.DNS; md != nil {
				v.Resolvers, v.Ready, v.State = slices.Clone(md.Resolvers), md.Ready, md.State
			}
			e.DNS = &v
		}
		out = append(out, e)
	}
	return out
}
