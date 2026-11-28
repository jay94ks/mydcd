// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/storage"

	"github.com/hashicorp/raft"
	boltdb "github.com/hashicorp/raft-boltdb/v2"
)

// ErrReplay means a stopped state root's Raft log, replayed from its first
// entry by this build, does not end in the state its own FSM checkpoint holds.
var ErrReplay = errors.New("Raft log replay does not reach the stored state")

// Replay is the upgrade compatibility check (devel/design/upgrades.md 3-8):
// it replays o.Root's whole Raft log (control/raft.db, from index 1) with
// o's validator and module hooks up to the root's durable FSM checkpoint
// (control/fsm.db), which the FSM then compares byte for byte, and returns
// that state. The root must be a stopped server's copy: Replay opens its
// files and the FSM may write to them. A log that a snapshot compacted no
// longer starts at 1 and cannot be checked.
func Replay(o Options) (state.State, error) {
	if o.Root == "" || o.Admin == "" || o.Cluster == ([32]byte{}) {
		return state.State{}, errors.New("incomplete replay options")
	}
	db, err := storage.Open(filepath.Join(o.Root, "control", "fsm.db"))
	if err != nil {
		return state.State{}, err
	}
	defer db.Close()
	logs, err := boltdb.NewBoltStore(filepath.Join(o.Root, "control", "raft.db"))
	if err != nil {
		return state.State{}, err
	}
	defer logs.Close()
	f, err := newFSM(db, logs, hex.EncodeToString(o.Cluster[:]), o.Admin, o.Validate)
	err = o.startError(db, err)
	if err != nil {
		return state.State{}, err
	}
	f.reduce, f.admitModule, f.admitMutation, f.admitPatch = o.Reduce, o.AdmitModule, o.AdmitMutation, o.AdmitModulePatch
	f.trackConfiguration = o.TrackConfiguration
	floor := f.durable.RaftIndex
	if floor == 0 {
		return state.State{}, errors.New("replay: the state root has no FSM checkpoint")
	}
	first, err := logs.FirstIndex()
	if err != nil {
		return state.State{}, err
	}
	if first != 1 {
		return state.State{}, fmt.Errorf("replay: the Raft log starts at %d, not 1 (compacted by a snapshot)", first)
	}
	for index := uint64(1); index <= floor; index++ {
		var entry raft.Log
		if err = logs.GetLog(index, &entry); err != nil {
			return state.State{}, fmt.Errorf("replay: Raft entry %d: %w", index, err)
		}
		switch entry.Type {
		case raft.LogCommand:
			if r := f.Apply(&entry).(application); r.Err != nil {
				return state.State{}, fmt.Errorf("%w: entry %d: %v", ErrReplay, index, r.Err)
			}
		case raft.LogConfiguration:
			f.StoreConfiguration(index, raft.DecodeConfiguration(entry.Data))
		}
		if f.failed != nil {
			return state.State{}, fmt.Errorf("%w: entry %d: %v", ErrReplay, index, f.failed)
		}
	}
	if !f.ready {
		return state.State{}, fmt.Errorf("%w: replay stopped before the checkpoint at %d", ErrReplay, floor)
	}
	return f.published, nil
}
