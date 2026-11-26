// SPDX-License-Identifier: Apache-2.0

package desired

import (
	"encoding/json"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/workload"
	"maps"
	"net/netip"
	"strings"
)

// Plan is read-only. IP candidates are checked again in committed Apply, and
// no speculative generation/lease is returned as a native reservation.
func (p Policy) Plan(s state.State, in workload.PlacementInput, reports []workload.Node, now, maxAge uint64) (workload.PlacementPlan, error) {
	invalid := func() (workload.PlacementPlan, error) { return workload.PlacementPlan{}, workload.ErrPlacement }
	if in.Schema != 1 || !strings.HasPrefix(in.Key, TaskPrefix) || len(in.Key) <= len(TaskPrefix) || len(in.Key) > 512 || in.Network == "" || in.Template.Schema != 1 || in.Template.Lifecycle.Drain || !in.Template.Lifecycle.Valid() {
		return invalid()
	}
	o := s.Object(in.Key)
	if in.Expected != o.Revision || s.Index() == ^uint64(0) {
		return invalid()
	}
	g, err := p.Project(s)
	if err != nil {
		return workload.PlacementPlan{}, err
	}
	eligible := g.Eligibility(s)
	if o.Present {
		old, known := g.Tasks[in.Key]
		if !known {
			return invalid()
		}
		proposal, err := workload.Propose(workload.Task{Revision: o.Revision, Current: old.Node, Need: workload.Resources{CPU: uint64(old.NanoCPU), Memory: uint64(old.Memory)}}, reports, eligible, now, maxAge)
		if err != nil {
			return invalid()
		}
		proposal.Blocked = proposal.Blocked || old.Lifecycle.Drain
		return workload.PlacementPlan{Schema: 1, Key: in.Key, Expected: in.Expected, Proposal: proposal, Spec: old}, nil
	}
	if in.Template.Memory <= 0 || in.Template.NanoCPU <= 0 {
		return invalid()
	}
	used := map[string]workload.Resources{}
	counts, addresses := map[string]int{}, map[string]int{}
	for _, tun := range g.Tunnels {
		if !tun.Lifecycle.Released() {
			addresses[tun.Owner] += len(tun.Addresses)
		}
	}
	for _, task := range g.Tasks {
		if task.Lifecycle.Released() {
			continue
		}
		u := used[task.Node]
		u.CPU += uint64(task.NanoCPU)
		u.Memory += uint64(task.Memory)
		used[task.Node] = u
		counts[task.Node]++
		if task.IPv4.IsValid() {
			addresses[task.Node]++
		}
		if task.IPv6.IsValid() {
			addresses[task.Node]++
		}
	}
	candidates := map[string]workload.ContainerSpec{}
	nodes := make([]workload.Node, 0, len(reports))
	for _, n := range reports {
		budget, known := g.Nodes[n.ID]
		if !known || n.Revision > s.Index() || !maps.Equal(n.Labels, budget.Labels) || counts[n.ID] >= budget.MaxContainers || in.Template.Node != "" && in.Template.Node != n.ID {
			continue
		}
		n.Capacity.CPU = min(n.Capacity.CPU, budget.CPU)
		n.Capacity.Memory = min(n.Capacity.Memory, budget.Memory)
		n.Used.CPU = max(n.Used.CPU, used[n.ID].CPU)
		n.Used.Memory = max(n.Used.Memory, used[n.ID].Memory)
		for _, key := range Sorted(g.Bridges) {
			bridge := g.Bridges[key]
			if bridge.Owner != n.ID || bridge.Network != in.Network || bridge.Lifecycle.Drain || in.Template.Bridge != "" && in.Template.Bridge != key || in.Template.BridgeGeneration != 0 && in.Template.BridgeGeneration != s.Object(key).Generation {
				continue
			}
			candidate := in.Template
			candidate.Node = n.ID
			candidate.Bridge = key
			candidate.BridgeGeneration = s.Object(key).Generation
			book, e := g.IPAM.Resize(g.IPAM.Count() + 2)
			if e != nil {
				return invalid()
			}
			v4, v6 := false, false
			for _, pool := range bridge.Pools {
				is4 := pool.Prefix.Addr().Is4()
				if is4 && v4 || !is4 && v6 {
					continue
				}
				want := candidate.IPv6
				family := "/6"
				if is4 {
					want = candidate.IPv4
					family = "/4"
				}
				if want.IsValid() && !pool.Prefix.Contains(want) {
					continue
				}
				var allocation network.Allocation
				book, allocation, e = book.Reserve(in.Key+family, n.ID, in.Network, pool.ID, s.Index()+1, want)
				if e != nil {
					continue
				}
				if is4 {
					candidate.IPv4 = allocation.Address
					v4 = true
				} else {
					candidate.IPv6 = allocation.Address
					v6 = true
				}
			}
			if in.Template.IPv4.IsValid() && !v4 || in.Template.IPv6.IsValid() && !v6 || !v4 && !v6 {
				continue
			}
			count := 0
			if candidate.IPv4.IsValid() {
				count++
			}
			if candidate.IPv6.IsValid() {
				count++
			}
			if addresses[n.ID]+count > budget.MaxEndpoints {
				continue
			}
			// Invalid unspecified families stay invalid, not zero IP addresses.
			if !v4 {
				candidate.IPv4 = netip.Addr{}
			}
			if !v6 {
				candidate.IPv6 = netip.Addr{}
			}
			b, e := json.Marshal(candidate)
			if e != nil {
				return invalid()
			}
			if _, e = workload.DecodeContainer(string(b)); e != nil {
				continue
			}
			candidates[n.ID] = candidate
			nodes = append(nodes, n)
			break
		}
	}
	proposal, err := workload.Propose(workload.Task{Revision: in.Expected, Need: workload.Resources{CPU: uint64(in.Template.NanoCPU), Memory: uint64(in.Template.Memory)}, Labels: in.Labels}, nodes, eligible, now, maxAge)
	if err != nil {
		return workload.PlacementPlan{}, err
	}
	return workload.PlacementPlan{Schema: 1, Key: in.Key, Expected: in.Expected, Proposal: proposal, Spec: candidates[proposal.Node]}, nil
}
