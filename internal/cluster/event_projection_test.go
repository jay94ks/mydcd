// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/eventlog"
	"github.com/jay94ks/mydcd/internal/storage"

	"github.com/hashicorp/raft"
)

// Exercises the production FSM/outbox transaction. The small projection is a
// test callback, not an implementation of CD or task algorithms.
func TestCommittedDiagnosticOutboxIsAtomicAndNotDuplicatedByReplay(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	logs := raft.NewInmemStore()
	f, err := newFSM(db, logs, "cluster", "admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	projection := func(before, after state.State, c state.Command, r state.Result) ([]eventlog.Event, error) {
		if r.Code != state.Applied || r.Index != after.Index() {
			return nil, nil
		}
		return []eventlog.Event{{Kind: "quorum-degraded", Scope: "cluster", At: r.Index * 1000, Target: eventlog.Target{Node: "node-a", Term: 1}, Detail: eventlog.Detail{Code: "MODEL_COMMITTED_OBSERVATION"}}}, nil
	}
	f.project = projection
	command := state.Command{Kind: state.Mutate, Actor: "admin", Epoch: 1, RequestID: "one", Key: "workload/example", Value: "body-that-must-not-be-in-event"}
	raw, err := state.EncodeCommand(command)
	if err != nil {
		t.Fatal(err)
	}
	result := f.Apply(&raft.Log{Index: 1, Term: 1, Data: raw}).(application)
	if result.Err != nil || result.Result.Code != state.Applied {
		t.Fatal(result)
	}
	window, err := readProjected(db)
	if err != nil || len(window.Rows) != 1 || window.Rows[0].RaftIndex != 1 || window.Rows[0].Event.Authority == "" {
		t.Fatal("missing committed outbox", err)
	}
	if _, err := db.Get("fsm"); err != nil {
		t.Fatal("outbox existed without FSM checkpoint", err)
	}
	// Reopening reconstructs the same authoritative replay floor.
	replay, err := newFSM(db, logs, "cluster", "admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	replay.project = projection
	result = replay.Apply(&raft.Log{Index: 1, Term: 1, Data: raw}).(application)
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	window, err = readProjected(db)
	if err != nil || window.Next != 1 || len(window.Rows) != 1 {
		t.Fatal("replay invented another event", err)
	}
	// A duplicate original command is not a new state transition.
	result = replay.Apply(&raft.Log{Index: 2, Term: 1, Data: raw}).(application)
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	window, _ = readProjected(db)
	if window.Next != 1 {
		t.Fatal("original receipt replay emitted again")
	}
}

func TestDiagnosticProjectionFailureKeepsBusinessCommitAndSignalsGap(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	f, err := newFSM(db, raft.NewInmemStore(), "cluster", "admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	f.project = func(state.State, state.State, state.Command, state.Result) ([]eventlog.Event, error) {
		return nil, errors.New("private diagnostic failure")
	}
	command := state.Command{Kind: state.Mutate, Actor: "admin", Epoch: 1, RequestID: "commit", Key: "workload/example", Value: "value"}
	raw, _ := state.EncodeCommand(command)
	result := f.Apply(&raft.Log{Index: 1, Term: 1, Data: raw}).(application)
	if result.Err != nil || result.Result.Code != state.Applied {
		t.Fatal("observer changed business outcome", result)
	}
	window, err := readProjected(db)
	if err != nil || window.LostAt != 1 || len(window.Rows) != 0 {
		t.Fatal("diagnostic hole hidden", err)
	}
	view, _, _, err := f.view(true)
	if err != nil || !view.Object("workload/example").Present {
		t.Fatal("business state not published", err)
	}
}
