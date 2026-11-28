// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/storage"

	"github.com/hashicorp/raft"
	boltdb "github.com/hashicorp/raft-boltdb/v2"
)

// Replay reaches the stored checkpoint with the hooks that wrote it, and
// reports a build whose judgement differs, or a log it cannot start at 1.
func TestReplayStateRoot(t *testing.T) {
	id := [32]byte{9}
	root := func(t *testing.T) string {
		t.Helper()
		dir := t.TempDir()
		db, err := storage.Open(filepath.Join(dir, "control", "fsm.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		logs, err := boltdb.NewBoltStore(filepath.Join(dir, "control", "raft.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer logs.Close()
		f, err := newFSM(db, logs, hex.EncodeToString(id[:]), "admin", nil)
		if err != nil {
			t.Fatal(err)
		}
		f.trackConfiguration = true
		configuration := raft.Configuration{Servers: []raft.Server{{ID: "node", Address: "127.0.0.1:1", Suffrage: raft.Voter}}}
		entries := []*raft.Log{{Index: 1, Term: 1, Type: raft.LogConfiguration, Data: raft.EncodeConfiguration(configuration)}, {Index: 2, Term: 1, Type: raft.LogNoop}}
		var expected uint64
		for i, v := range []string{"a", "b"} {
			b, err := state.EncodeCommand(state.Command{Actor: "admin", Epoch: 1, RequestID: v, Key: "network/x", Value: v, Expected: expected})
			if err != nil {
				t.Fatal(err)
			}
			entries = append(entries, &raft.Log{Index: uint64(3 + i), Term: 1, Type: raft.LogCommand, Data: b})
			expected++
		}
		if err = logs.StoreLogs(entries); err != nil {
			t.Fatal(err)
		}
		f.StoreConfiguration(1, configuration)
		for _, e := range entries[2:] {
			if r := f.Apply(e).(application); r.Err != nil || r.Result.Code != state.Applied {
				t.Fatal(r)
			}
		}
		return dir
	}
	s, err := Replay(Options{Root: root(t), Admin: "admin", Cluster: id, TrackConfiguration: true})
	if err != nil || s.Object("network/x").Value != "b" {
		t.Fatal(s.Object("network/x"), err)
	}
	refuse := func(_, next state.State, c state.Command) error {
		if c.Value == "b" {
			return errors.New("this build refuses b")
		}
		return nil
	}
	if _, err = Replay(Options{Root: root(t), Admin: "admin", Cluster: id, TrackConfiguration: true, Validate: refuse}); !errors.Is(err, ErrReplay) {
		t.Fatal("a differing judgement replayed", err)
	}
	compacted := root(t)
	logs, err := boltdb.NewBoltStore(filepath.Join(compacted, "control", "raft.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err = logs.DeleteRange(1, 2); err != nil {
		t.Fatal(err)
	}
	_ = logs.Close()
	if _, err = Replay(Options{Root: compacted, Admin: "admin", Cluster: id, TrackConfiguration: true}); err == nil {
		t.Fatal("a compacted log replayed")
	}

	// The dry run continues from a compacted log's checkpoint and applies
	// the tail; a build that refuses a stored record fails on the checkpoint.
	tailed := root(t)
	logs, err = boltdb.NewBoltStore(filepath.Join(tailed, "control", "raft.db"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := state.EncodeCommand(state.Command{Actor: "admin", Epoch: 1, RequestID: "c", Key: "network/x", Value: "c", Expected: 2})
	if err != nil {
		t.Fatal(err)
	}
	if err = logs.StoreLog(&raft.Log{Index: 5, Term: 1, Type: raft.LogCommand, Data: b}); err == nil {
		err = logs.DeleteRange(1, 2)
	}
	_ = logs.Close()
	if err != nil {
		t.Fatal(err)
	}
	r, err := DryRun(Options{Root: tailed, Admin: "admin", Cluster: id, TrackConfiguration: true})
	if err != nil || r.Replayed || r.FirstLog != 3 || r.Checkpoint != 4 || r.Tail != 1 || r.State.Object("network/x").Value != "c" {
		t.Fatal(r.Replayed, r.FirstLog, r.Checkpoint, r.Tail, r.State.Object("network/x"), err)
	}
	stored := func(before, _ state.State, c state.Command) error {
		if c.RequestID == "" && before.Object("network/x").Value == "b" {
			return errors.New("this build no longer reads b")
		}
		return nil
	}
	if _, err = DryRun(Options{Root: root(t), Admin: "admin", Cluster: id, TrackConfiguration: true, Validate: stored}); !errors.Is(err, ErrReplay) {
		t.Fatal("a stored record this build refuses passed", err)
	}
	// The refusal names the check (stage) that refused, as a start does.
	stage := func(before, _ state.State, c state.Command) (string, error) {
		if err := stored(before, before, c); err != nil {
			return "network", err
		}
		return "", nil
	}
	if _, err = DryRun(Options{Root: root(t), Admin: "admin", Cluster: id, TrackConfiguration: true, Validate: stored, ValidateStage: stage}); !errors.Is(err, ErrReplay) || !strings.Contains(err.Error(), "(stage network)") {
		t.Fatal("the refusing stage is not named", err)
	}
}
