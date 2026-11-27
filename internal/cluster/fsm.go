// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/eventlog"
	"github.com/jay94ks/seafield/internal/storage"
	"sync"
	"sync/atomic"

	raft "github.com/hashicorp/raft"
)

var ErrRecovering = errors.New("FSM replay has not reached durable checkpoint")

// fsmRecord is the checkpoint row. The state itself is stored as rows under
// state.StoredPrefix; Head is its small head row, written with every apply.
type fsmRecord struct {
	Schema              uint8
	Cluster             string
	RaftIndex, Term     uint64
	Configuration, Head []byte
	ConfigurationIndex  uint64 `json:",omitempty"`
}
type application struct {
	Result          state.Result
	RaftIndex, Term uint64
	Err             error
}

// Readers share the immutable, last synced generation. A future candidate's
// serialization or disk I/O must not stall packet admission to this state.
type fsmReadView struct {
	state                state.State
	index, term          uint64
	configuration        string
	configurationIndex   uint64
	configurationTracked bool
	changes              <-chan struct{}
	ready                bool
	err                  error
}
type fsm struct {
	project            EventProjection
	pendingEvents      []eventlog.Event
	pendingEventError  error
	projectionRestore  uint64
	mu                 sync.RWMutex
	db                 *storage.DB
	logs               raft.LogStore
	snapshots          raft.SnapshotStore
	cluster, admin     string
	work, published    state.State
	position, term     uint64
	configuration      []byte
	configurationIndex uint64
	trackConfiguration bool
	durable            fsmRecord
	// dirty holds the rows changed since the last write. Replay below the
	// durable floor collects them too; reaching the floor clears them.
	dirty         *state.Changes
	ready         bool
	failed        error
	failure       chan error
	validate      state.Validator
	reduce        state.Reducer
	admitModule   state.ModuleAuthorizer
	admitMutation state.MutationAuthorizer
	admitPatch    state.ModulePatchAuthorizer
	changes       chan struct{}
	readView      atomic.Pointer[fsmReadView]
}

func newFSM(db *storage.DB, logs raft.LogStore, cluster, admin string, validate state.Validator) (*fsm, error) {
	initial, err := state.New(admin)
	if err != nil {
		return nil, err
	}
	f := &fsm{db: db, logs: logs, cluster: cluster, admin: admin, work: initial, published: initial, dirty: state.NewChanges(), ready: true, failure: make(chan error, 1), validate: validate, changes: make(chan struct{})}
	b, err := db.Get("fsm")
	if errors.Is(err, storage.ErrMissing) {
		f.publishReadView()
		return f, nil
	}
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(b, &f.durable); err != nil || f.durable.Schema != 1 || f.durable.Cluster != cluster || f.durable.RaftIndex == 0 || f.durable.Term == 0 {
		return nil, errors.New("invalid FSM binding/checkpoint")
	}
	rows, err := db.Scan(state.StoredPrefix)
	if err != nil {
		return nil, err
	}
	f.published, err = state.DecodeStored(f.durable.Head, rows)
	if err != nil {
		return nil, err
	}
	f.ready = false
	if validate != nil {
		if err = validate(f.published, f.published, state.Command{}); err != nil {
			return nil, err
		}
	}
	f.publishReadView()
	return f, nil
}

// Called by the sole writer under mu, or during constructor initialization.
// Only f.published/f.durable belong here; f.work can be unsynced replay input.
func (f *fsm) publishReadView() {
	f.readView.Store(&fsmReadView{
		state: f.published, index: f.durable.RaftIndex, term: f.durable.Term,
		configuration: string(f.durable.Configuration), configurationIndex: f.durable.ConfigurationIndex,
		configurationTracked: f.configurationTracking(f.published), changes: f.changes,
		ready: f.ready, err: f.failed,
	})
}
func (f *fsm) fail(err error) error {
	if f.failed == nil {
		f.failed = err
		f.publishReadView()
		f.failure <- err
	}
	return f.failed
}
func (f *fsm) record(writes map[string][]byte) (fsmRecord, error) {
	head, err := state.StoredWrites(f.work, f.dirty, writes)
	var index uint64
	if f.configurationTracking(f.work) {
		index = f.configurationIndex
	}
	return fsmRecord{Schema: 1, Cluster: f.cluster, RaftIndex: f.position, Term: f.term, Configuration: append([]byte(nil), f.configuration...), Head: head, ConfigurationIndex: index}, err
}

func (f *fsm) configurationTracking(s state.State) bool {
	return f.trackConfiguration
}
func (f *fsm) publish() error {
	// Replay still decodes and validates every command, but its prefix cannot
	// replace the synced checkpoint. Encode only at that floor or beyond it;
	// repeatedly serializing older candidates makes recovery quadratic in the
	// retained log/state size without producing any publishable evidence.
	if f.position < f.durable.RaftIndex {
		return nil
	}
	writes := map[string][]byte{}
	if f.position == f.durable.RaftIndex && f.position != 0 {
		// Replay reached the stored checkpoint: the replayed state must be
		// exactly the stored one. Compared once, at start-up.
		var index uint64
		if f.configurationTracking(f.work) {
			index = f.configurationIndex
		}
		replayed, err := state.Encode(f.work)
		stored, err2 := state.Encode(f.published)
		if err != nil || err2 != nil || f.term != f.durable.Term || index != f.durable.ConfigurationIndex || !bytes.Equal(replayed, stored) || !bytes.Equal(f.configuration, f.durable.Configuration) {
			return f.fail(errors.New("durable FSM differs from Raft replay"))
		}
		f.dirty = state.NewChanges()
		f.ready = true
		f.published = f.work
		f.publishReadView()
		return nil
	}
	r, err := f.record(writes)
	if err != nil {
		return f.fail(err)
	}
	b, err := json.Marshal(r)
	if err != nil {
		return f.fail(err)
	}
	writes["fsm"] = b
	f.projectWrites(writes, r.RaftIndex)
	if err = f.db.Write(writes); err != nil {
		return f.fail(fmt.Errorf("FSM atomic sync: %w", err))
	}
	f.durable = r
	f.dirty = state.NewChanges()
	f.pendingEvents, f.pendingEventError, f.projectionRestore = nil, nil, 0
	f.published = f.work
	f.ready = true
	previousChanges := f.changes
	f.changes = make(chan struct{})
	f.publishReadView()
	// Publish the new state AND its open subscription before waking previous
	// readers. A subscriber must never inherit an already closed generation.
	close(previousChanges)
	return nil
}
func (f *fsm) Apply(log *raft.Log) any {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failed != nil {
		return application{Err: f.failed}
	}
	if log.Index <= f.position {
		return application{Err: f.fail(errors.New("Raft FSM apply order regressed"))}
	}
	command, err := state.DecodeCommand(log.Data)
	if err != nil {
		return application{Err: f.fail(err)}
	}
	// Core Index is the management-command ordinal, independent of Raft config,
	// no-op/barrier positions. Expose the real RaftIndex separately to callers.
	reduce, admit := f.reduce, f.admitModule
	mutation, patch := f.admitMutation, f.admitPatch
	n, result, err := state.ApplyTransactional(f.work, f.work.Index()+1, command, f.validate, reduce, admit, mutation, patch)
	if err != nil {
		return application{Err: f.fail(err)}
	}
	if f.project != nil && log.Index > f.durable.RaftIndex {
		f.pendingEvents, f.pendingEventError = f.project(f.work, n, command, result)
	}
	f.work = n
	f.dirty.Add(n)
	f.position = log.Index
	f.term = log.Term
	err = f.publish()
	return application{result, log.Index, log.Term, err}
}
func (f *fsm) StoreConfiguration(index uint64, configuration raft.Configuration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failed != nil {
		return
	}
	if index <= f.position {
		f.fail(errors.New("configuration order regressed"))
		return
	}
	var log raft.Log
	if err := f.logs.GetLog(index, &log); err != nil {
		f.fail(err)
		return
	}
	f.configuration = raft.EncodeConfiguration(configuration)
	// Keep the actual callback observation in memory even for a static prefix.
	// record/Snapshot omit it until its policy explicitly enables tracking.
	f.configurationIndex = index
	f.position = index
	f.term = log.Term
	_ = f.publish()
}

// Local readers may use the last atomically synced committed checkpoint while
// Raft reconstructs work. This never publishes replay candidates or grants a
// management barrier; strict users must wait for the original replay floor.
func (f *fsm) view(requireReplay bool) (state.State, uint64, uint64, error) {
	v := f.readView.Load()
	if v == nil {
		return state.State{}, 0, 0, ErrRecovering
	}
	if v.err != nil {
		return state.State{}, 0, 0, v.err
	}
	if requireReplay && !v.ready {
		return state.State{}, 0, 0, ErrRecovering
	}
	return v.state, v.index, v.term, nil
}
