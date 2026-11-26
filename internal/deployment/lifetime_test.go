// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"encoding/json"
	"testing"
)

func TestExecutionInputBindingUsesCommittedTaskGenerationBeforeActivation(t *testing.T) {
	x := runFixture(t)
	task := ResourceKey("task", "tenant", "php-mysql", "db")
	input := ResourceKey("inputs", "tenant", "php-mysql", "db")
	_, err := x.e.Inputs("db", "db-task", public(private(30)))
	deny(t, err)
	x.before(task)
	cmd := x.prepare(task)
	x.send(task)
	r := x.apply(cmd)
	x.save(x.e.Commit(x.e.Revision(), task, cmd, r))
	n, err := x.e.Inputs("db", "db-task", public(private(30)))
	if err != nil || n.Generation != r.Generation || n.Generation == 0 {
		t.Fatal("not the original committed task generation", err)
	}
	x.f.approveAll(n)
	reservation := x.f.reserve(n)
	if _, err = reservation.Bindings[0].Materialize(reservation.Inventory, x.f.c, x.f.trees, reservation.Approvals, reservation.Volumes, 100, x.f.values(n), 4096); err != nil {
		t.Fatal(err)
	}
	_, err = x.e.Observe(x.e.Revision(), x.observation(task, true, false), 100)
	deny(t, err)
	x.prepare(input)
	inputCmd := x.send(input)
	var goal GoalCommand
	_ = json.Unmarshal([]byte(inputCmd.Value), &goal)
	bound := false
	for _, ref := range goal.Dependencies {
		bound = bound || ref == (ObjectRef{task, r.Revision, r.Generation})
	}
	if !bound {
		t.Fatal("input command lost committed task identity")
	}
	x.save(x.e.Commit(x.e.Revision(), input, inputCmd, x.apply(inputCmd)))
	x.observe(input, true, false)
	x.observe(task, true, false)
	positions := map[string]int{}
	for i, s := range x.b.ReleaseOrder() {
		positions[s.Key] = i
	}
	if positions[task] >= positions[input] || positions[input] >= positions[ResourceKey("volume", "tenant", "php-mysql", "mysql-data")] {
		t.Fatal("private input/volume released before task")
	}
}

func TestBlueprintRejectsUnboundOrCyclicActivationLifetimes(t *testing.T) {
	x := runFixture(t)
	raw, _ := x.b.Encode()
	for _, alter := range []func(*blueprintRecord){
		func(d *blueprintRecord) {
			for i := range d.Steps {
				if d.Steps[i].Kind == "inputs" {
					d.Steps[i].Identity = nil
					return
				}
			}
		},
		func(d *blueprintRecord) {
			for i := range d.Steps {
				if d.Steps[i].Kind == "task" {
					d.Steps[i].Activation = nil
					return
				}
			}
		},
		func(d *blueprintRecord) {
			for i := range d.Steps {
				if d.Steps[i].Kind == "inputs" {
					d.Steps[i].Identity[0] = "foreign"
					return
				}
			}
		},
		func(d *blueprintRecord) {
			for i := range d.Steps {
				if d.Steps[i].Kind == "bridge" {
					d.Steps[i].Activation = []Dependency{{d.Steps[i].Key, Applied}}
					return
				}
			}
		},
	} {
		var d blueprintRecord
		_ = json.Unmarshal(raw, &d)
		alter(&d)
		changed, _ := json.Marshal(d)
		_, err := DecodeBlueprint(changed)
		deny(t, err)
	}
}

func TestExecutionRejectsPrematureInputReleaseAndErasedActivation(t *testing.T) {
	x := runFixture(t)
	for _, s := range x.b.Steps() {
		x.completeStep(s.Key)
	}
	input := ResourceKey("inputs", "tenant", "php-mysql", "db")
	x.save(x.e.Stop(x.f.c, "admin", x.e.Revision()))
	_, err := x.e.Observe(x.e.Revision(), x.observation(input, false, true), 100)
	deny(t, err)
	raw, _ := x.e.Encode()
	var d executionRecord
	_ = json.Unmarshal(raw, &d)
	i := x.e.index(input)
	d.Stages[i].Command = nil
	d.Stages[i].Result = nil
	d.Stages[i].Observation = nil
	d.Stages[i].Journal = StageRecord{}.Journal
	bad, _ := json.Marshal(d)
	_, err = DecodeExecution(bad)
	deny(t, err)
}
