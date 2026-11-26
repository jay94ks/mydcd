// SPDX-License-Identifier: Apache-2.0

package reconcile

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

func desired(t *testing.T, s State, revision, generation uint64, spec string) State {
	t.Helper()
	r := Resource{}
	if generation != 0 {
		r = Resource{Generation: generation, Spec: spec, Present: true}
	}
	n, err := SetDesired(s, Desired{Revision: revision, Resource: r})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func dispatched(t *testing.T, s State) (State, Operation) {
	t.Helper()
	n, op, err := Plan(s)
	if err != nil || op == nil {
		t.Fatal("no plan", err)
	}
	n, err = Dispatch(n, op.ID)
	if err != nil {
		t.Fatal(err)
	}
	return n, *op
}

func settle(t *testing.T, s State, id uint64, outcome Outcome) State {
	t.Helper()
	n, err := Settle(s, id, outcome)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

type mockJournal struct {
	data []byte
	fail bool
}

func (j *mockJournal) save(s State) error {
	if err := Validate(s); err != nil {
		return err
	}
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if j.fail {
		return errors.New("injected journal failure")
	}
	j.data = b
	return nil
}
func (j *mockJournal) restore(t *testing.T) State {
	t.Helper()
	var s State
	if err := json.Unmarshal(j.data, &s); err != nil {
		t.Fatal(err)
	}
	if err := Validate(s); err != nil {
		t.Fatal(err)
	}
	return s
}

type mockNative struct {
	resource Resource
	lastID   uint64
	calls    int
}

func (n *mockNative) execute(op Operation) {
	n.calls++
	n.lastID = op.ID
	if op.Kind == Remove {
		n.resource = Resource{}
	} else {
		n.resource = op.Target
	}
}
func (n *mockNative) inspect(op Operation) Outcome {
	if n.lastID == op.ID {
		return EffectApplied
	}
	return EffectUnknown
}

func TestDispatchedWorkSurvivesNewDesired(t *testing.T) {
	s := desired(t, State{}, 1, 1, "old")
	s, op := dispatched(t, s)
	original := *s.Pending
	s = desired(t, s, 2, 1, "new")
	if *s.Pending != original {
		t.Fatal("new Desired rewrote admitted work")
	}
	if _, _, err := Plan(s); !errors.Is(err, ErrPending) {
		t.Fatal("overlapping operation allowed")
	}
	s = settle(t, s, op.ID, EffectApplied)
	if s.Applied.Spec != "old" {
		t.Fatal("completed old effect relabeled as latest Desired")
	}
	s, next := dispatched(t, s)
	if next.ID == op.ID || next.Target.Spec != "new" {
		t.Fatal("next desired not reconciled")
	}
	s = settle(t, s, next.ID, EffectApplied)
	if _, op, err := Plan(s); err != nil || op != nil {
		t.Fatal("stable state repeated native operation")
	}
}

func TestRestartAfterEffectBeforeJournalCommit(t *testing.T) {
	s := desired(t, State{}, 1, 1, "old")
	s, op := dispatched(t, s)
	s = desired(t, s, 2, 2, "replacement")
	j := mockJournal{}
	if err := j.save(s); err != nil {
		t.Fatal(err)
	}
	native := mockNative{}
	native.execute(op)
	completed := settle(t, s, op.ID, EffectApplied)
	j.fail = true
	if err := j.save(completed); err == nil {
		t.Fatal("missing write failure")
	}
	restored := j.restore(t)
	if restored.Pending == nil || restored.Pending.ID != op.ID || restored.Desired.Generation != 2 {
		t.Fatal("restart lost original work or latest desired")
	}
	restored = settle(t, restored, op.ID, native.inspect(*restored.Pending))
	if native.calls != 1 || restored.Applied.Generation != 1 {
		t.Fatal("recovery reexecuted or relabeled effect")
	}
	restored, remove := dispatched(t, restored)
	if remove.Kind != Remove || remove.Target.Generation != 1 {
		t.Fatal("replacement skipped original cleanup")
	}
	restored = settle(t, restored, remove.ID, EffectApplied)
	_, create := dispatched(t, restored)
	if create.Kind != Apply || create.Target.Generation != 2 {
		t.Fatal("replacement reused old generation")
	}
}

func TestUnknownResultBlocksRetryUntilInspection(t *testing.T) {
	s := desired(t, State{}, 1, 1, "spec")
	s, op := dispatched(t, s)
	s = settle(t, s, op.ID, EffectUnknown)
	if _, _, err := Plan(s); !errors.Is(err, ErrPending) {
		t.Fatal("unknown result was retried")
	}
	if _, err := Dispatch(s, op.ID); !errors.Is(err, ErrOperation) {
		t.Fatal("unknown operation dispatched again")
	}
	s = settle(t, s, op.ID, EffectNotApplied)
	_, next := dispatched(t, s)
	if next.ID <= op.ID {
		t.Fatal("settled retry reused operation token")
	}
}

func TestDeleteRecreateWhileBlockedPreservesGenerationFloor(t *testing.T) {
	s := desired(t, State{}, 1, 1, "original")
	s, op := dispatched(t, s)
	s = settle(t, s, op.ID, EffectApplied)
	s = desired(t, s, 2, 0, "")
	s, op = dispatched(t, s)
	s = settle(t, s, op.ID, EffectUnknown)
	s = desired(t, s, 3, 3, "new")
	s = settle(t, s, op.ID, EffectApplied)
	s, create := dispatched(t, s)
	if create.Target.Generation != 3 || create.Kind != Apply {
		t.Fatal("blocked observation lost recreation generation")
	}
	s = settle(t, s, create.ID, EffectApplied)
	s = desired(t, s, 4, 0, "")
	if _, err := SetDesired(s, Desired{Revision: 5, Resource: Resource{Generation: 1, Spec: "stale", Present: true}}); !errors.Is(err, ErrDesired) {
		t.Fatal("deleted generation became reusable")
	}
}

func TestStopAndLateCompletion(t *testing.T) {
	s := desired(t, State{}, 1, 1, "spec")
	s, op := dispatched(t, s)
	s = Stop(s)
	if _, _, err := Plan(s); !errors.Is(err, ErrStopped) {
		t.Fatal("stop admitted new work")
	}
	if _, err := Settle(s, op.ID+1, EffectApplied); !errors.Is(err, ErrOperation) {
		t.Fatal("foreign completion accepted")
	}
	s = settle(t, s, op.ID, EffectApplied)
	if !s.Stopped || !s.Applied.Present {
		t.Fatal("stop lost admitted effect")
	}
	if _, err := Settle(s, op.ID, EffectApplied); !errors.Is(err, ErrOperation) {
		t.Fatal("duplicate completion accepted")
	}
}

func TestBoundedTransitionSequences(t *testing.T) {
	// Explore every legal/illegal action ordering through depth five, with no I/O.
	visited := 0
	var walk func(State, int)
	walk = func(s State, depth int) {
		visited++
		if err := Validate(s); err != nil {
			t.Fatal("invalid reachable state", err, s)
		}
		if depth == 0 {
			return
		}
		for action := 0; action < 8; action++ {
			before := copyState(s)
			var n State
			var err error
			switch action {
			case 0:
				n, err = SetDesired(s, Desired{Revision: s.Desired.Revision + 1, Resource: Resource{Generation: s.GenerationFloor + 1, Spec: "next", Present: true}})
			case 1:
				n, err = SetDesired(s, Desired{Revision: s.Desired.Revision + 1})
			case 2:
				n, _, err = Plan(s)
			case 3:
				n, err = Dispatch(s, s.LastID)
			case 4:
				n, err = Settle(s, s.LastID, EffectApplied)
			case 5:
				n, err = Settle(s, s.LastID, EffectUnknown)
			case 6:
				n, err = Settle(s, s.LastID, EffectNotApplied)
			case 7:
				n = Stop(s)
			}
			if !reflect.DeepEqual(s, before) {
				t.Fatal("transition mutated prior journal")
			}
			if err != nil {
				if !reflect.DeepEqual(n, s) {
					t.Fatal("error changed state")
				}
				continue
			}
			if s.Pending != nil && (action == 0 || action == 1 || action == 7) && (n.Pending == nil || *s.Pending != *n.Pending) {
				t.Fatal("desired/stop invalidated original operation")
			}
			walk(n, depth-1)
		}
	}
	walk(desired(t, State{}, 1, 1, "initial"), 5)
	t.Logf("checked %d reachable transition prefixes", visited)
}

func TestPreparedCannotCompleteAndRestoredJournalMustBeValid(t *testing.T) {
	s := desired(t, State{}, 1, 1, "spec")
	s, op, err := Plan(s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Settle(s, op.ID, EffectApplied); !errors.Is(err, ErrOperation) {
		t.Fatal("prepared journal counted as external effect")
	}
	op.Target.Spec = "adapter mutation"
	if s.Pending.Target.Spec != "spec" {
		t.Fatal("adapter owns journal alias")
	}
	bad := copyState(s)
	bad.Pending.ID = 0
	if Validate(bad) == nil {
		t.Fatal("malformed restored journal accepted")
	}
	bad = copyState(s)
	bad.LastID = ^uint64(0)
	bad.Pending = nil
	if _, _, err := Plan(bad); !errors.Is(err, ErrOperation) {
		t.Fatal("operation token wrapped")
	}
}
