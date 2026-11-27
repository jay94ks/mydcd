// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"errors"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/storage"
	"path/filepath"
	"testing"

	"github.com/hashicorp/raft"
)

func TestRealBoundaryOfflineCheckpointAndReplayFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fsm.db")
	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	f, err := newFSM(db, raft.NewInmemStore(), "cluster", "admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	command := state.Command{Actor: "admin", Epoch: 1, RequestID: "original", Key: "network/original", Value: "committed"}
	b, err := state.EncodeCommand(command)
	if err != nil {
		t.Fatal(err)
	}
	if reply := f.Apply(&raft.Log{Index: 2, Term: 1, Type: raft.LogCommand, Data: b}).(application); reply.Err != nil || reply.Result.Code != state.Applied {
		t.Fatal(reply)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	f, err = newFSM(db, raft.NewInmemStore(), "cluster", "admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	s, index, term, err := f.view(false)
	if err != nil || index != 2 || term != 1 || s.Object(command.Key).Value != "committed" {
		t.Fatal("offline committed checkpoint unavailable", s, index, term, err)
	}
	if _, _, _, err = f.view(true); !errors.Is(err, ErrRecovering) {
		t.Fatal("local checkpoint granted replay completion", err)
	}
	// Corruption in the replay prefix is fatal, even to local readers. Do not
	// keep serving the checkpoint after contradictory durable evidence.
	command.Value = "different"
	b, _ = state.EncodeCommand(command)
	if reply := f.Apply(&raft.Log{Index: 2, Term: 1, Type: raft.LogCommand, Data: b}).(application); reply.Err == nil {
		t.Fatal("mismatched checkpoint replay accepted")
	}
	for _, strict := range []bool{false, true} {
		if _, _, _, err = f.view(strict); err == nil {
			t.Fatal("failed replay remained readable", strict)
		}
	}
}
