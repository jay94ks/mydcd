// SPDX-License-Identifier: Apache-2.0

package reconcile

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestRetiringGenerationWithoutApplyAndLateOriginal(t *testing.T) {
	drain := Desired{Revision: 8, Retiring: 3}
	s, err := SetDesired(State{}, drain)
	if err != nil || s.GenerationFloor != 3 {
		t.Fatal(s, err)
	}
	_, op, err := Plan(s)
	if err != nil || op != nil {
		t.Fatal("never-created Drain issued native work", op, err)
	}
	b, _ := json.Marshal(s)
	var restored State
	if err = json.Unmarshal(b, &restored); err != nil || Validate(restored) != nil || restored.Desired != drain {
		t.Fatal("retirement floor lost", err)
	}
	if _, err = SetDesired(restored, Desired{Revision: 9, Resource: Resource{Present: true, Generation: 3, Spec: "old"}}); err == nil {
		t.Fatal("drained generation reactivated")
	}
	if _, err = SetDesired(restored, Desired{Revision: 9, Retiring: 2}); err == nil {
		t.Fatal("retirement floor regressed")
	}
	active := Desired{Revision: 1, Resource: Resource{Present: true, Generation: 1, Spec: "original"}}
	s, err = SetDesired(State{}, active)
	if err != nil {
		t.Fatal(err)
	}
	s, op, err = Plan(s)
	if err != nil {
		t.Fatal(err)
	}
	s, err = Dispatch(s, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	s, err = SetDesired(s, Desired{Revision: 2, Retiring: 1})
	if err != nil || s.Pending == nil || s.Pending.Target != active.Resource {
		t.Fatal("Drain discarded accepted original", s, err)
	}
	s, err = Settle(s, op.ID, EffectApplied)
	if err != nil || s.Applied != active.Resource {
		t.Fatal("late original was lost", err)
	}
	s, remove, err := Plan(s)
	if err != nil || remove == nil || remove.Kind != Remove || remove.Target != active.Resource || remove.ID <= op.ID {
		t.Fatal("late original not retired", remove, err)
	}
	if Validate(s) != nil {
		t.Fatal("invalid late retirement state")
	}
	if _, err = SetDesired(State{}, Desired{Revision: 1, Retiring: 1, Resource: active.Resource}); err == nil {
		t.Fatal("active/retiring ambiguous Desired")
	}
}

func TestRealBoundaryNeverCreatedRetirementJournal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.db")
	j, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = j.Close() }()
	if err = j.Desired("never-created", Desired{Revision: 9, Retiring: 7}, 2); err != nil {
		t.Fatal(err)
	}
	d := &fileDriver{t: t, j: j, path: filepath.Join(t.TempDir(), "must-not-exist")}
	if err = j.Step(context.Background(), "never-created", d); err != nil || d.executions != 0 || d.inspections != 0 {
		t.Fatal("retirement manufactured an effect", err)
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	j, err = OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	r, err := j.Read("never-created")
	if err != nil || r.State.GenerationFloor != 7 || r.State.Pending != nil || r.State.LastID != 0 || r.State.Applied.Present || r.State.Desired.Retiring != 7 {
		t.Fatal("reopen lost never-created retirement", r, err)
	}
}
