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

// DryRunResult says what a DryRun checked.
type DryRunResult struct {
	// Checkpoint is the Raft index of the root's FSM checkpoint, which this
	// build read and validated.
	Checkpoint uint64
	// FirstLog is the first Raft entry the root still holds. When it is 1
	// the whole log was replayed up to the checkpoint (Replayed).
	FirstLog uint64
	Replayed bool
	// Tail is how many entries after the checkpoint this build applied
	// (the log can hold a few uncommitted ones at its end).
	Tail  uint64
	State state.State
}

// Replay is the upgrade compatibility check (devel/design/upgrades.md 3-8):
// it replays o.Root's whole Raft log (control/raft.db, from index 1) with
// o's validator and module hooks up to the root's durable FSM checkpoint
// (control/fsm.db), which the FSM then compares byte for byte, and returns
// that state. The root must be a stopped server's copy: Replay opens its
// files and the FSM may write to them. A log that a snapshot compacted no
// longer starts at 1 and cannot be checked.
func Replay(o Options) (state.State, error) {
	r, err := dryRun(o, true, false)
	return r.State, err
}

// DryRun is what starting this build on o.Root would do to its control
// state, on a copy: it reads and validates the FSM checkpoint with o's hooks
// (a build that no longer accepts stored records fails here), replays the
// whole log up to it when the log still starts at 1, and then applies the
// entries after it. o.Root must be a copy; DryRun may write to it.
func DryRun(o Options) (DryRunResult, error) {
	return dryRun(o, false, true)
}

func dryRun(o Options, requireFull, tail bool) (DryRunResult, error) {
	var out DryRunResult
	if o.Root == "" || o.Admin == "" || o.Cluster == ([32]byte{}) {
		return out, errors.New("incomplete replay options")
	}
	db, err := storage.Open(filepath.Join(o.Root, "control", "fsm.db"))
	if err != nil {
		return out, err
	}
	defer db.Close()
	logs, err := boltdb.NewBoltStore(filepath.Join(o.Root, "control", "raft.db"))
	if err != nil {
		return out, err
	}
	defer logs.Close()
	f, err := newFSM(db, logs, hex.EncodeToString(o.Cluster[:]), o.Admin, o.Validate)
	if err != nil {
		return out, fmt.Errorf("%w: stored checkpoint: %v", ErrReplay, o.startError(db, err))
	}
	f.reduce, f.admitModule, f.admitMutation, f.admitPatch = o.Reduce, o.AdmitModule, o.AdmitMutation, o.AdmitModulePatch
	f.trackConfiguration = o.TrackConfiguration
	floor := f.durable.RaftIndex
	if floor == 0 {
		return out, errors.New("replay: the state root has no FSM checkpoint")
	}
	out.Checkpoint = floor
	first, err := logs.FirstIndex()
	if err != nil {
		return out, err
	}
	last, err := logs.LastIndex()
	if err != nil {
		return out, err
	}
	out.FirstLog = first
	apply := func(index uint64) error {
		var entry raft.Log
		if err := logs.GetLog(index, &entry); err != nil {
			return fmt.Errorf("replay: Raft entry %d: %w", index, err)
		}
		switch entry.Type {
		case raft.LogCommand:
			if r := f.Apply(&entry).(application); r.Err != nil {
				return fmt.Errorf("%w: entry %d: %v", ErrReplay, index, r.Err)
			}
		case raft.LogConfiguration:
			f.StoreConfiguration(index, raft.DecodeConfiguration(entry.Data))
		}
		if f.failed != nil {
			return fmt.Errorf("%w: entry %d: %v", ErrReplay, index, f.failed)
		}
		return nil
	}
	if first > floor+1 {
		return out, fmt.Errorf("replay: the Raft log starts at %d, after the checkpoint at %d", first, floor)
	}
	switch {
	case first == 1:
		for index := uint64(1); index <= floor; index++ {
			if err = apply(index); err != nil {
				return out, err
			}
		}
		if !f.ready {
			return out, fmt.Errorf("%w: replay stopped before the checkpoint at %d", ErrReplay, floor)
		}
		out.Replayed = true
	case requireFull:
		return out, fmt.Errorf("replay: the Raft log starts at %d, not 1 (compacted by a snapshot)", first)
	default:
		// The entries before the checkpoint are gone (a snapshot covers
		// them): continue from the validated checkpoint itself.
		f.work, f.position, f.term = f.published, floor, f.durable.Term
		f.configuration, f.configurationIndex = f.durable.Configuration, f.durable.ConfigurationIndex
		f.dirty, f.ready = state.NewChanges(), true
	}
	if tail {
		for index := max(floor+1, first); index <= last; index++ {
			if err = apply(index); err != nil {
				return out, err
			}
			out.Tail++
		}
	}
	out.State = f.published
	return out, nil
}
