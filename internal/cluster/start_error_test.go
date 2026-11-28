// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/raft"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/storage"
)

// A stored state the new validator refuses names the refusing stage in the
// start error, and only there.
func TestStartErrorNamesTheRefusingStage(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "fsm.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	f, err := newFSM(db, raft.NewInmemStore(), "cluster", "admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := state.EncodeCommand(state.Command{Actor: "admin", Epoch: 1, RequestID: "a", Key: "network/a", Value: "v"})
	if reply := f.Apply(&raft.Log{Index: 1, Term: 1, Type: raft.LogCommand, Data: raw}).(application); reply.Err != nil {
		t.Fatal(reply.Err)
	}
	refused := errors.New("invalid committed control catalog")
	o := Options{
		Validate:      func(before, after state.State, c state.Command) error { return refused },
		ValidateStage: func(before, after state.State, c state.Command) (string, error) { return "apps", refused },
	}
	_, err = newFSM(db, raft.NewInmemStore(), "cluster", "admin", o.Validate)
	err = o.startError(db, err)
	if !errors.Is(err, refused) || !strings.Contains(err.Error(), "(stage apps)") {
		t.Fatal(err)
	}
	if o.startError(db, nil) != nil {
		t.Fatal("a clean start got an error")
	}
}
