// SPDX-License-Identifier: Apache-2.0

package desired

import (
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/workload"
	"net/netip"
	"testing"
)

func TestPlanReusesCommittedIPAMAndZeroCAS(t *testing.T) {
	f := newFixture(t)
	template := f.task
	template.Node = ""
	template.Bridge = ""
	template.BridgeGeneration = 0
	template.IPv4 = netip.Addr{}
	in := workload.PlacementInput{Schema: 1, Key: TaskPrefix + "a", Network: f.bridge.Network, Template: template}
	n := workload.Node{ID: f.owner, Generation: f.s.Object(NodePrefix + "a").Generation, Revision: f.s.Index(), ObservedAt: 100, Ready: true, Capacity: workload.Resources{CPU: 1000000000, Memory: 128 << 20}}
	plan, err := f.p.Plan(f.s, in, []workload.Node{n}, 100, 10)
	if err != nil || plan.Expected != 0 || plan.Proposal.ExpectedRevision != 0 || plan.Spec.IPv4 != f.task.IPv4 || plan.Spec.Node != f.owner || plan.Spec.BridgeGeneration != f.task.BridgeGeneration {
		t.Fatal("new plan", plan, err)
	}
	g, err := f.p.Project(f.s)
	if err != nil || g.IPAM.Count() != 0 || f.s.Object(in.Key).Present {
		t.Fatal("plan reserved or committed state", err)
	}
	f.apply(in.Key, plan.Spec, state.Applied)
	in.Key = TaskPrefix + "b"
	if _, err = f.p.Plan(f.s, in, []workload.Node{n}, 100, 10); err == nil {
		t.Fatal("pre-application report admitted new placement")
	}
	n.Revision = f.s.Index()
	second, err := f.p.Plan(f.s, in, []workload.Node{n}, 100, 10)
	if err != nil || second.Spec.IPv4 != f.task.IPv4.Next() {
		t.Fatal("committed allocation was reused", second, err)
	}
	in.Key = TaskPrefix + "a"
	in.Expected = f.s.Object(in.Key).Revision
	preserved, err := f.p.Plan(f.s, in, nil, 100, 10)
	if err != nil || !preserved.Proposal.Preserved || !preserved.Proposal.Blocked || preserved.Spec.IPv4 != plan.Spec.IPv4 {
		t.Fatal("missing observation evicted running task", preserved, err)
	}
}

func TestPlanRejectsStaleAndOvercommittedReports(t *testing.T) {
	f := newFixture(t)
	template := f.task
	template.Node = ""
	template.Bridge = ""
	template.BridgeGeneration = 0
	template.IPv4 = netip.Addr{}
	in := workload.PlacementInput{Schema: 1, Key: TaskPrefix + "new", Network: f.bridge.Network, Template: template}
	n := workload.Node{ID: f.owner, Generation: 1, Revision: f.s.Index(), ObservedAt: 100, Ready: true, Capacity: workload.Resources{CPU: 1000000000, Memory: 128 << 20}}
	for _, alter := range []func(*workload.Node){func(n *workload.Node) { n.Ready = false }, func(n *workload.Node) { n.ObservedAt = 89 }, func(n *workload.Node) { n.ObservedAt = 101 }, func(n *workload.Node) { n.Generation++ }, func(n *workload.Node) { n.Revision = 1 }, func(n *workload.Node) { n.Revision = 999 }, func(n *workload.Node) { n.Used = n.Capacity }, func(n *workload.Node) { n.Labels = map[string]string{"invented": "a"} }} {
		bad := n
		alter(&bad)
		if _, err := f.p.Plan(f.s, in, []workload.Node{bad}, 100, 10); err == nil {
			t.Fatal("ineligible plan", bad)
		}
	}
	first := f.task
	first.Memory = 112 << 20
	f.apply(TaskPrefix+"old", first, state.Applied)
	n.Revision = f.s.Index()
	n.Used = workload.Resources{} // old observed usage cannot erase the committed reservation
	if _, err := f.p.Plan(f.s, in, []workload.Node{n}, 100, 10); err == nil {
		t.Fatal("stale observed usage overcommitted memory")
	}
	in.Template.IPv4 = f.bridge.Pools[0].Gateway
	if _, err := f.p.Plan(f.s, in, []workload.Node{n}, 100, 10); err == nil {
		t.Fatal("gateway allocated")
	}
}
