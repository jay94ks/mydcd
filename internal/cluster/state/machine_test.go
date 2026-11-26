// SPDX-License-Identifier: Apache-2.0

package state

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

type mockStore struct {
	state State
	fail  bool
}

func (m *mockStore) commit(index uint64, c Command) (Result, error) {
	n, r, err := Apply(m.state, index, c)
	if err != nil {
		return r, err
	}
	if m.fail {
		return Result{}, errors.New("injected atomic write failure")
	}
	m.state = n
	return r, nil
}

func command(id, key, value string, expected uint64) Command {
	return Command{Actor: "admin", Epoch: 1, RequestID: id, Key: "workload/" + key, Value: value, Expected: expected}
}

func initial() State {
	s, _ := New("admin")
	s.principals["another-admin"] = principal{Rights: allRights, Epoch: 1}
	return s
}

func mustApply(t *testing.T, s *State, c Command) Result {
	t.Helper()
	n, r, err := Apply(*s, s.Index()+1, c)
	if err != nil {
		t.Fatal(err)
	}
	*s = n
	return r
}

func TestAtomicFailureAndReplay(t *testing.T) {
	store := mockStore{state: initial(), fail: true}
	c := command("create", "task", "spec", 0)
	if _, err := store.commit(1, c); err == nil {
		t.Fatal("missing write failure")
	}
	if store.state.Index() != 0 || store.state.Object("workload/task").Present || store.state.ReceiptCount() != 0 {
		t.Fatal("failed write published partial state")
	}
	store.fail = false
	r, err := store.commit(1, c)
	if err != nil || r.Code != Applied || store.state.Index() != 1 || store.state.ReceiptCount() != 1 {
		t.Fatal("replay did not atomically restore state/result/index", r, err)
	}
}

func TestDeduplicationAndIdentityConflict(t *testing.T) {
	s := initial()
	c := command("request", "task", "first", 0)
	original := mustApply(t, &s, c)
	if got := mustApply(t, &s, c); got != original || s.Index() != 2 || s.Object("workload/task").Revision != 1 {
		t.Fatal("duplicate changed original result or object", got)
	}
	c.Value = "other"
	if got := mustApply(t, &s, c); got.Code != RequestConflict || s.Object("workload/task").Value != "first" {
		t.Fatal("request ID reused for different command")
	}
	c.Value = "first"
	if got := mustApply(t, &s, c); got != original || s.ReceiptCount() != 1 {
		t.Fatal("conflict overwrote original receipt")
	}
	c.Actor = "another-admin"
	if got := mustApply(t, &s, c); got.Code != ConditionFailed || s.ReceiptCount() != 2 {
		t.Fatal("request IDs must be scoped to caller")
	}
}

func TestTombstoneRecreationAndUnrelatedCommit(t *testing.T) {
	s := initial()
	create := command("create", "task", "old", 0)
	mustApply(t, &s, create)
	mustApply(t, &s, command("unrelated", "network", "cidr", 0))
	if got := s.Object("workload/task"); got.Revision != 1 || got.Generation != 1 {
		t.Fatal("unrelated log entry changed task identity", got)
	}
	mustApply(t, &s, command("update", "task", "updated", 1))
	if s.Object("workload/task").Generation != 1 {
		t.Fatal("ordinary update changed creation generation")
	}
	remove := command("remove", "task", "", 3)
	remove.Delete = true
	mustApply(t, &s, remove)
	if got := s.Object("workload/task"); got.Present || got.Revision != 4 || got.Generation != 1 {
		t.Fatal("deletion evidence lost", got)
	}
	mustApply(t, &s, command("recreate", "task", "new", 4))
	if got := s.Object("workload/task"); !got.Present || got.Revision != 5 || got.Generation != 5 {
		t.Fatal("recreation reused deleted generation", got)
	}
	mustApply(t, &s, create)
	if s.Object("workload/task").Generation != 5 {
		t.Fatal("old request replay overwrote recreation")
	}
}

func TestFailedConditionRemainsFailedOnRetry(t *testing.T) {
	s := initial()
	stale := command("stale", "task", "bad", 1)
	r := mustApply(t, &s, stale)
	if r.Code != ConditionFailed {
		t.Fatal(r)
	}
	mustApply(t, &s, command("create", "task", "real", 0))
	if got := mustApply(t, &s, stale); got != r || s.Object("workload/task").Value != "real" {
		t.Fatal("retry reevaluated failed condition")
	}
}

func TestIndexAndInvalidInput(t *testing.T) {
	s := initial()
	for _, i := range []uint64{0, 2, 100} {
		if _, _, err := Apply(s, i, command("id", "key", "value", 0)); !errors.Is(err, ErrOrder) {
			t.Fatal("accepted gap", i)
		}
	}
	for _, c := range []Command{{}, Command{Actor: "admin", Epoch: 1, RequestID: "id"}, command("large", "key", strings.Repeat("x", 64*1024+1), 0), {Actor: "a", RequestID: "delete", Key: "key", Value: "bad", Delete: true}} {
		if r := mustApply(t, &s, c); r.Code != Invalid {
			t.Fatal("accepted invalid command", r)
		}
	}
	before := clone(s)
	_, _, _ = Apply(s, s.Index()+1, command("valid", "key", "value", 0))
	if !reflect.DeepEqual(s, before) {
		t.Fatal("candidate mutated published input")
	}
}
