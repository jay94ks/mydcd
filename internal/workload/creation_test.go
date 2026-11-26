// SPDX-License-Identifier: Apache-2.0

package workload

import "testing"

func TestCreationPlacementUsesZeroExpectedRevision(t *testing.T) {
	n := Node{ID: "a", Generation: 1, Revision: 2, ObservedAt: 100, Ready: true, Capacity: Resources{CPU: 2, Memory: 2}}
	task := Task{Need: Resources{CPU: 1, Memory: 1}}
	p, err := Propose(task, []Node{n}, map[string]Eligibility{"a": {Generation: 1, MinRevision: 2}}, 100, 10)
	if err != nil || p.ExpectedRevision != 0 || p.Node != "a" || p.Preserved {
		t.Fatal("new task requires a fabricated revision", p, err)
	}
	task.Current = "a"
	if _, err = Propose(task, []Node{n}, nil, 100, 10); err == nil {
		t.Fatal("existing assignment has no CAS revision")
	}
	task.Current = ""
	task.Move = true
	if _, err = Propose(task, []Node{n}, nil, 100, 10); err == nil {
		t.Fatal("move without an original assignment")
	}
}
