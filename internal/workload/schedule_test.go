// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"reflect"
	"testing"
)

func TestPlacementFreshnessCapacityAndStableProposal(t *testing.T) {
	nodes := []Node{{ID: "b", Generation: 1, Revision: 8, ObservedAt: 90, Capacity: Resources{8, 16}, Used: Resources{2, 4}, Ready: true, Labels: map[string]string{"zone": "a"}}, {ID: "a", Generation: 1, Revision: 8, ObservedAt: 90, Capacity: Resources{4, 8}, Used: Resources{1, 2}, Ready: true, Labels: map[string]string{"zone": "a"}}}
	allowed := map[string]Eligibility{"a": {1, 8}, "b": {1, 8}}
	task := Task{Revision: 12, Need: Resources{1, 2}, Labels: map[string]string{"zone": "a"}}
	a, err := Propose(task, nodes, allowed, 100, 10)
	if err != nil || a.Node != "a" || a.ExpectedRevision != 12 {
		t.Fatal(a, err)
	}
	b, err := Propose(task, []Node{nodes[1], nodes[0]}, allowed, 100, 10)
	if err != nil || b != a {
		t.Fatal("order-dependent placement")
	}
	before := append([]Node(nil), nodes...)
	_, _ = Propose(task, nodes, allowed, 100, 10)
	if !reflect.DeepEqual(before, nodes) {
		t.Fatal("proposal changed observations")
	}
	for _, mutate := range []func(*Node){func(n *Node) { n.ObservedAt = 89 }, func(n *Node) { n.ObservedAt = 101 }, func(n *Node) { n.Generation = 2 }, func(n *Node) { n.Revision = 7 }, func(n *Node) { n.Ready = false }, func(n *Node) { n.Draining = true }, func(n *Node) { n.Used = n.Capacity }, func(n *Node) { n.Used.CPU = ^uint64(0) }, func(n *Node) { n.Labels = nil }} {
		n := nodes[0]
		mutate(&n)
		if _, err := Propose(task, []Node{n}, allowed, 100, 10); err == nil {
			t.Fatal("ineligible placement", n)
		}
	}
	if _, err := Propose(task, []Node{nodes[0], nodes[0]}, allowed, 100, 10); err == nil {
		t.Fatal("ambiguous duplicate node")
	}
}
func TestExistingPlacementSurvivesMissingHealthAndExplicitMove(t *testing.T) {
	task := Task{Revision: 3, Current: "old", Need: Resources{1, 1}}
	p, err := Propose(task, nil, nil, 100, 10)
	if err != nil || p.Node != "old" || !p.Preserved || !p.Blocked {
		t.Fatal("stale report evicted existing task", p, err)
	}
	n := Node{ID: "new", Generation: 1, Revision: 1, ObservedAt: 100, Capacity: Resources{2, 2}, Ready: true}
	p, _ = Propose(task, []Node{n}, map[string]Eligibility{"new": {1, 1}}, 100, 10)
	if p.Node != "old" {
		t.Fatal("new capacity silently migrated task")
	}
	task.Move = true
	p, err = Propose(task, []Node{n}, map[string]Eligibility{"new": {1, 1}}, 100, 10)
	if err != nil || p.Node != "new" || p.Preserved {
		t.Fatal(p, err)
	}
	if ratioLess(^uint64(0)-1, ^uint64(0), ^uint64(0)-2, ^uint64(0)-1) <= 0 {
		t.Fatal("ratio product overflow")
	}
}
