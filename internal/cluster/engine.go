// SPDX-License-Identifier: Apache-2.0

// Package cluster joins the preverified FSM/recovery core to real Raft and DBs.
package cluster

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/storage"
	"io"
	"log"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	raft "github.com/hashicorp/raft"
	boltdb "github.com/hashicorp/raft-boltdb/v2"
)

var ErrUnknown = errors.New("management outcome unknown; query original request, do not retry automatically")

type Options struct {
	// IdentityTransitions is the retained dual-signed lineage of this node's
	// current mesh key. It preserves the original DB identity, not TLS authority.
	IdentityTransitions  []lifecycle.IdentityTransition
	EventProjection      EventProjection
	Prepared             func(*Engine)
	ID, Root, Admin      string
	Cluster              [32]byte
	Mesh                 *mydcp.Transport
	Resolve              PeerResolver
	Servers              []raft.Server
	Bootstrap            bool
	TrackConfiguration   bool
	Manifest             [32]byte
	Validate             state.Validator
	Reduce               state.Reducer
	AdmitModule          state.ModuleAuthorizer
	AdmitMutation        state.MutationAuthorizer
	AdmitModulePatch     state.ModulePatchAuthorizer
	AllowMutationUpgrade bool
	AllowPatchUpgrade    bool
	CommandModule        func(string, string, []byte, View) (state.Command, error)
	ModuleID             [32]byte
	ReadModule           func(context.Context, string, string, []byte, View) (json.RawMessage, error)
	NodeCLIAllowed       func(state.State) bool
}
type Engine struct {
	appliedMu        sync.Mutex
	barrierTerm      atomic.Uint64
	writes           writeCounts
	appliedDurable   uint64
	appliedCovered   uint64
	compactMu        sync.Mutex
	contactMaxAge    time.Duration
	observations     raftObservations
	root             string
	snapshotInterval time.Duration
	trailingLogs     uint64
	hasModule        bool
	raft             *raft.Raft
	fsm              *fsm
	db               *storage.DB
	log              *boltdb.BoltStore
	snapshots        raft.SnapshotStore
	lock             *storage.Lock
	transport        *raftTransport
	mu               sync.Mutex
	closed           bool
	stopOnce         sync.Once
	stopErr          error
	stopped          chan struct{} // closed once native raft has shut down
	closeOnce        sync.Once
	closeErr         error
	pending          chan struct{}
	wg               sync.WaitGroup
	done             chan struct{}
	id               string
	cluster          [32]byte
	mesh             *mydcp.Transport
	resolve          PeerResolver
	fatal            chan error
	readModule       func(context.Context, string, string, []byte, View) (json.RawMessage, error)
	commandModule    func(string, string, []byte, View) (state.Command, error)
	nodeCLIAllowed   func(state.State) bool
}

func Open(o Options) (*Engine, error) {
	if o.ID == "" || o.Root == "" || o.Admin == "" || o.Cluster == [32]byte{} || o.Mesh == nil || o.Mesh.Addr() == nil || o.Resolve == nil {
		return nil, errors.New("incomplete engine options")
	}
	if o.Reduce == nil && (o.ModuleID != ([32]byte{}) || o.AdmitModule != nil || o.AdmitMutation != nil || o.AdmitModulePatch != nil) || o.Reduce != nil && (o.ModuleID == ([32]byte{}) || o.Validate == nil) {
		return nil, errors.New("module reducer requires an explicit bound policy ID and checkpoint validator")
	}
	var identityErr error
	o, identityErr = ownEngineIdentity(o)
	if identityErr != nil {
		return nil, identityErr
	}
	e := &Engine{root: o.Root, pending: make(chan struct{}, 64), done: make(chan struct{}), stopped: make(chan struct{}), id: o.ID, cluster: o.Cluster, mesh: o.Mesh, resolve: o.Resolve, fatal: make(chan error, 1), readModule: o.ReadModule, commandModule: o.CommandModule}
	e.nodeCLIAllowed = o.NodeCLIAllowed
	ok := false
	defer func() {
		if !ok {
			_ = e.Close()
		}
	}()
	e.hasModule = o.Reduce != nil
	var err error
	e.lock, err = storage.LockRoot(o.Root)
	if err != nil {
		return nil, err
	}
	e.db, err = storage.Open(filepath.Join(o.Root, "control", "fsm.db"))
	if err != nil {
		return nil, err
	}
	if o.AdmitMutation != nil && o.AdmitModule == nil {
		return nil, errors.New("delegated mutations require authenticated module admission")
	}
	if o.AdmitModulePatch != nil && o.AdmitModule == nil {
		return nil, errors.New("related module patches require authenticated module admission")
	}
	binding := engineBinding(o)
	upgradeMutation := false
	upgradePatch := false
	var originalBinding []byte
	old, err := e.db.Get("binding")
	missingBinding := errors.Is(err, storage.ErrMissing)
	if missingBinding {
		err = nil
	}
	if err == nil && missingBinding && len(o.IdentityTransitions) != 0 {
		return nil, errors.New("rotated node requires its original state root binding")
	}
	if err == nil && !missingBinding && string(old) != string(binding) {
		withoutPatch := bytes.TrimSuffix(binding, []byte("/related-control-patches-1"))
		if o.AllowPatchUpgrade && o.AdmitModulePatch != nil && bytes.Equal(old, withoutPatch) {
			upgradePatch = true
			originalBinding = bytes.Clone(old)
		} else if o.AllowMutationUpgrade && o.AdmitMutation != nil && (o.AdmitModulePatch == nil || o.AllowPatchUpgrade) && bytes.Equal(old, bytes.TrimSuffix(withoutPatch, []byte("/delegated-mutations-1"))) {
			upgradeMutation = true
			upgradePatch = o.AdmitModulePatch != nil
			originalBinding = bytes.Clone(old)
		} else {
			err = errors.New("state root identity/cluster mismatch")
		}
	}
	if err != nil {
		return nil, err
	}
	e.log, err = boltdb.NewBoltStore(filepath.Join(o.Root, "control", "raft.db"))
	if err != nil {
		return nil, err
	}
	e.fsm, err = newFSM(e.db, e.log, hex.EncodeToString(o.Cluster[:]), o.Admin, o.Validate)
	if err != nil {
		return nil, err
	}
	e.fsm.project = o.EventProjection
	if upgradeMutation || upgradePatch {
		if o.Validate == nil {
			return nil, errors.New("mutation policy upgrade needs checkpoint validation")
		}
		if err = o.Validate(e.fsm.published, e.fsm.published, state.Command{}); err != nil {
			return nil, err
		}
		marker, _ := json.Marshal(struct {
			Schema            uint8
			Cluster           [32]byte
			Original, Current []byte
			CommandIndex      uint64
		}{1, o.Cluster, originalBinding, binding, e.fsm.published.Index()})
		writes := map[string][]byte{"binding": binding}
		if upgradeMutation {
			writes["mutation-policy-upgrade-1"] = marker
		}
		if upgradePatch {
			writes["module-patch-policy-upgrade-1"] = marker
		}
		if err = e.db.Write(writes); err != nil {
			return nil, err
		}
	}
	e.fsm.reduce = o.Reduce
	e.fsm.admitModule = o.AdmitModule
	e.fsm.admitMutation = o.AdmitMutation
	e.fsm.admitPatch = o.AdmitModulePatch
	e.fsm.trackConfiguration = o.TrackConfiguration
	// Configuration-tracking policy is now fixed, before the SDK or external
	// readers can observe this engine. No writer exists during construction.
	e.fsm.publishReadView()
	snapshots, err := raft.NewFileSnapshotStore(filepath.Join(o.Root, "control"), 2, io.Discard)
	if err != nil {
		return nil, err
	}
	e.snapshots = snapshots
	e.fsm.snapshots = snapshots
	e.transport, err = newRaftTransport(o.Mesh, raft.ServerAddress(o.Mesh.Addr().String()), o.Resolve, filepath.Join(o.Root, "control", "staging"))
	if err != nil {
		return nil, err
	}
	cfg := raft.DefaultConfig()
	cfg.LocalID = raft.ServerID(o.ID)
	// Idle cost: the patched SDK (3rd-party/raft) sends an empty
	// AppendEntries only when a follower reports a commit index behind the
	// leader's, and wakes replication as soon as the commit index advances,
	// so a follower applies an entry right after commit and an idle cluster
	// sends none. CommitTimeout is now only the local re-check for a wake-up
	// that could not be delivered.
	//
	// Failure detection is the MYDCP connection's job: QUIC PINGs every 1s
	// and closes after 3s of silence, and OnPeerLost below turns that into
	// an election on a follower (after a random wait up to ElectionTimeout/2)
	// or a lease re-check on the leader. A Raft heartbeat therefore only goes
	// out every 10s. HeartbeatTimeout and LeaderLeaseTimeout are the backstop
	// for a peer whose connection stays up while its Raft does not answer.
	// Reads and writes still confirm leadership with real AppendEntries
	// (confirmLeader), so none of these timers affect correctness.
	cfg.CommitTimeout = time.Second
	cfg.HeartbeatInterval = 10 * time.Second
	cfg.HeartbeatTimeout = 30 * time.Second
	cfg.ElectionTimeout = 2 * time.Second
	cfg.LeaderLeaseTimeout = 20 * time.Second
	cfg.MaxAppendEntries = 1
	// The durable FSM still verifies the SDK snapshot's suffix before Ready.
	// Keep that suffix bounded instead of replaying a long command history
	// whenever a daemon restarts. Snapshot creation/retention stays in Raft.
	cfg.SnapshotInterval = 10 * time.Second
	cfg.SnapshotThreshold = 256
	cfg.TrailingLogs = 512
	e.contactMaxAge = cfg.HeartbeatTimeout
	e.snapshotInterval, e.trailingLogs = cfg.SnapshotInterval, cfg.TrailingLogs
	// Keep SDK failure diagnostics visible without logging routine heartbeats.
	// Losing the first lease/RPC error makes a later Unknown uninterpretable.
	cfg.LogOutput = log.Writer()
	cfg.LogLevel = "WARN"
	hasState, err := raft.HasExistingState(e.log, e.log, snapshots)
	if err != nil {
		return nil, err
	}
	if !hasState && e.fsm.durable.RaftIndex != 0 {
		return nil, errors.New("durable FSM exists but Raft state is missing; refusing reinitialization")
	}
	if missingBinding {
		if hasState || e.fsm.durable.RaftIndex != 0 {
			return nil, errors.New("existing Raft/FSM root is missing its binding; refusing initialization")
		}
		if err = e.db.Write(map[string][]byte{"binding": binding}); err != nil {
			return nil, err
		}
	}
	if o.Bootstrap && !hasState {
		if len(o.Servers) == 0 {
			return nil, errors.New("bootstrap requires an explicit voting configuration")
		}
		if err = raft.BootstrapCluster(cfg, e.log, e.log, snapshots, e.transport, raft.Configuration{Servers: o.Servers}); err != nil {
			return nil, err
		}
	}
	if o.Prepared != nil {
		o.Prepared(e)
	}
	e.raft, err = raft.NewRaft(cfg, e.fsm, e.log, e.log, snapshots, e.transport)
	if err != nil {
		return nil, err
	}
	if err = e.observeRaft(); err != nil {
		return nil, err
	}
	// A lost MYDCP connection is the fast failure signal (see the timers above).
	r := e.raft
	o.Mesh.OnPeerLost(func(p mydcp.Peer) { r.PeerConnectionLost(raft.ServerID(p.ID)) })
	// A member that comes back (restart) gets a heartbeat from the leader at
	// once instead of after HeartbeatInterval (10s), so it learns its leader.
	o.Mesh.OnPeerConnected(func(p mydcp.Peer) { r.PeerConnected(raft.ServerID(p.ID)) })
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		select {
		case failure := <-e.fsm.failure:
			// SDK shutdown can wait for an outstanding owner. Preserve the
			// first failure before that wait; the public failure notification
			// still follows native shutdown as before.
			log.Printf("raft FSM failure before shutdown: node=%s cause=%v", e.id, failure)
			_ = e.stopNative()
			e.fatal <- failure
		case <-e.done:
		}
	}()
	ok = true
	return e, nil
}
func (e *Engine) Leader() (raft.ServerAddress, raft.ServerID) { return e.raft.LeaderWithID() }
func (e *Engine) IsLeader() bool                              { return e.raft.State() == raft.Leader }

// LeaderPeer resolves only the currently known leader's approved ID/address.
// It does not establish quorum or authorize any forwarded user operation.
func (e *Engine) LeaderPeer() (mydcp.Peer, bool) {
	address, id := e.Leader()
	if id == "" || address == "" {
		return mydcp.Peer{}, false
	}
	peer, ok := e.resolve(id, address)
	return peer, ok && peer.Member
}
func (e *Engine) Failure() <-chan error { return e.fatal }
func (e *Engine) Changes() <-chan struct{} {
	if view := e.fsm.readView.Load(); view != nil {
		return view.changes
	}
	return nil
}
func (e *Engine) await(ctx context.Context, start func() raft.Future) error {
	select {
	case e.pending <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	case <-e.done:
		return raft.ErrRaftShutdown
	}
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		<-e.pending
		return raft.ErrRaftShutdown
	}
	e.wg.Add(1)
	e.mu.Unlock()
	result := make(chan error, 1)
	go func() {
		defer e.wg.Done()
		defer func() { <-e.pending }()
		if err := ctx.Err(); err != nil {
			result <- err
			return
		}
		// A future raft accepted but never answers before its shutdown (one
		// handed to the FSM queue the FSM no longer reads) would hold Close
		// forever; it is given up once native raft has stopped.
		future := start()
		answer := make(chan error, 1)
		go func() { answer <- future.Error() }()
		select {
		case err := <-answer:
			result <- err
		case <-e.stopped:
			select {
			case err := <-answer:
				result <- err
			default:
				result <- raft.ErrRaftShutdown
			}
		}
	}()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
func remaining(ctx context.Context) time.Duration {
	if deadline, ok := ctx.Deadline(); ok {
		d := time.Until(deadline)
		if d > 0 {
			return d
		}
		return time.Nanosecond
	}
	return 5 * time.Second
}

type Committed struct {
	Result          state.Result
	RaftIndex, Term uint64
}

func (e *Engine) Submit(ctx context.Context, c state.Command) (Committed, error) {
	if _, _, _, err := e.fsm.view(true); err != nil {
		return Committed{}, fmt.Errorf("submit durable view: %w", err)
	}
	if err := e.await(ctx, func() raft.Future { return e.raft.VerifyLeader() }); err != nil {
		return Committed{}, fmt.Errorf("submit verify leader: %w", err)
	}
	// Apply itself commits this command in log order and waits for the FSM.
	// No state is read here after VerifyLeader, so a preceding Barrier only
	// adds another durable, replicated log entry without fencing a consumer.
	b, err := state.EncodeCommand(c)
	if err != nil {
		return Committed{}, err
	}
	var future raft.ApplyFuture
	term := e.raft.CurrentTerm()
	if err = e.await(ctx, func() raft.Future { future = e.raft.Apply(b, remaining(ctx)); return future }); err != nil {
		return Committed{}, fmt.Errorf("%w: submit apply: %w", ErrUnknown, err)
	}
	result, ok := future.Response().(application)
	// A rejected command is still a log entry; its label says so, because
	// CAS conflicts between reports are writes R14 wants to remove too.
	label := writeLabel(c)
	if !ok || result.Err != nil || result.Result.Code != state.Applied {
		label += " rejected"
	}
	e.writes.add(term, label)
	if !ok {
		return Committed{}, fmt.Errorf("%w: unexpected FSM response", ErrUnknown)
	}
	if result.Err != nil {
		return Committed{}, fmt.Errorf("%w: submit FSM: %w", ErrUnknown, result.Err)
	}
	return Committed{result.Result, result.RaftIndex, result.Term}, nil
}

type View struct {
	State           state.State
	RaftIndex, Term uint64
	Local           bool
}

func (e *Engine) Read(ctx context.Context, latest bool) (View, error) {
	var started time.Time
	var barrierTime, viewTime time.Duration
	phase := "barrier"
	if latest {
		started = time.Now()
		cpuStart := processCPUTime()
		defer func() {
			if elapsed := time.Since(started); elapsed >= 200*time.Millisecond {
				_, durable, _, _ := e.fsm.view(false)
				// SDK getters are atomic observations. Stats() also enqueues a
				// configuration future; diagnostics must not wait on the SDK loop.
				log.Printf("raft latest read slow: node=%s elapsed=%s process_cpu=%s barrier=%s view=%s phase=%s sdk_state=%s sdk_term=%d sdk_last=%d sdk_commit=%d sdk_sent_to_fsm=%d durable_fsm=%d", e.id, elapsed, processCPUUsed(cpuStart), barrierTime, viewTime, phase, e.raft.State(), e.raft.CurrentTerm(), e.raft.LastIndex(), e.raft.CommitIndex(), e.raft.AppliedIndex(), durable)
			}
		}()
		phase = "read-index"
		before := time.Now()
		err := e.readIndex(ctx)
		barrierTime = time.Since(before)
		if err != nil {
			return View{}, fmt.Errorf("read barrier: %w", err)
		}
	}
	phase = "view"
	var before time.Time
	if latest {
		before = time.Now()
	}
	s, index, term, err := e.fsm.view(latest)
	if latest {
		viewTime = time.Since(before)
	}
	if err == nil {
		phase = "complete"
	}
	return View{s, index, term, !latest}, err
}

// readIndex makes the next local view linearizable without writing to the
// Raft log. A LogBarrier per latest read appended one replicated entry per
// permit or work read, so an idle cluster's commit index kept rising
// (R14). Only the first latest read of each leader term commits a barrier:
// it proves this term's leader no-op is committed and applied. After that,
// the commit index sampled before a fresh quorum acknowledgement is a safe
// read index, and the view must cover the last FSM-visible entry at or below it.
func (e *Engine) readIndex(ctx context.Context) error {
	term := e.raft.CurrentTerm()
	if e.barrierTerm.Load() != term {
		if err := e.await(ctx, func() raft.Future { return e.raft.Barrier(remaining(ctx)) }); err != nil {
			return err
		}
		e.writes.add(term, "read-barrier")
		e.barrierTerm.Store(term)
		return nil
	}
	started := time.Now()
	index := e.raft.CommitIndex()
	if err := e.confirmLeader(ctx, term, started); err != nil {
		return err
	}
	if e.raft.CurrentTerm() != term {
		// Leadership moved between sampling and confirmation; the sample
		// may belong to an older term. Start over with this term's barrier.
		return e.readIndex(ctx)
	}
	floor, err := e.lastStateEntry(index)
	if err != nil {
		return err
	}
	for {
		changed := e.Changes()
		_, durable, _, err := e.fsm.view(true)
		if err != nil {
			return err
		}
		if durable >= floor {
			return nil
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		case <-e.done:
			return raft.ErrRaftShutdown
		}
	}
}

// confirmLeader waits until a voter quorum accepted this term's
// AppendEntries sent no earlier than started. VerifyLeader alone is not
// enough: the SDK counts a heartbeat already in flight before the call, so
// a leader cut off just before the read could still pass it.
func (e *Engine) confirmLeader(ctx context.Context, term uint64, started time.Time) error {
	for {
		if err := e.await(ctx, func() raft.Future { return e.raft.VerifyLeader() }); err != nil {
			return err
		}
		// Read the configuration after each round: a voter added during the
		// read must count toward the quorum, or a stale smaller majority
		// could confirm a read that misses the join's own commit.
		var configuration raft.ConfigurationFuture
		if err := e.await(ctx, func() raft.Future { configuration = e.raft.GetConfiguration(); return configuration }); err != nil {
			return err
		}
		voters, acked := 0, 0
		for _, server := range configuration.Configuration().Servers {
			if server.Suffrage != raft.Voter {
				continue
			}
			voters++
			if string(server.ID) == e.id || e.transport.ackedSince(server.ID, term, started) {
				acked++
			}
		}
		if voters > 0 && acked > voters/2 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-e.done:
			return raft.ErrRaftShutdown
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// lastStateEntry finds the newest log entry at or below index that the FSM
// records (command or configuration). No-op and barrier entries never reach
// the FSM, so waiting for their own index would never finish. A compacted
// prefix is already covered by the snapshot the FSM was restored from.
func (e *Engine) lastStateEntry(index uint64) (uint64, error) {
	first, err := e.log.FirstIndex()
	if err != nil {
		return 0, err
	}
	for i := index; i >= first && i > 0; i-- {
		var entry raft.Log
		if err := e.log.GetLog(i, &entry); err != nil {
			if errors.Is(err, raft.ErrLogNotFound) {
				return 0, nil
			}
			return 0, err
		}
		if entry.Type == raft.LogCommand || entry.Type == raft.LogConfiguration {
			return i, nil
		}
	}
	return 0, nil
}

// ReadAtLeast waits for the locally durable management-command ordinal from
// an already obtained quorum permit. It does not contact a leader, renew the
// permit, or substitute the Raft log position for State.Index.
func (e *Engine) ReadAtLeast(ctx context.Context, minimum uint64) (View, error) {
	if e == nil || ctx == nil {
		return View{}, errors.New("local read requires engine and context")
	}
	for {
		if err := ctx.Err(); err != nil {
			return View{}, err
		}
		select {
		case <-e.done:
			return View{}, raft.ErrRaftShutdown
		default:
		}
		// Subscribe before reading so a publication between these operations
		// cannot be missed. The existing channel broadcasts to every reader.
		changed := e.Changes()
		view, err := e.Read(ctx, false)
		if err != nil {
			return View{}, err
		}
		if view.State.Index() >= minimum {
			if err := ctx.Err(); err != nil {
				return View{}, err
			}
			return view, nil
		}
		select {
		case <-ctx.Done():
			return View{}, ctx.Err()
		case <-e.done:
			return View{}, raft.ErrRaftShutdown
		case <-changed:
		}
	}
}
func (e *Engine) Snapshot(ctx context.Context) error {
	return e.await(ctx, func() raft.Future { return e.raft.Snapshot() })
}
func (e *Engine) Configuration(ctx context.Context) (raft.Configuration, error) {
	var future raft.ConfigurationFuture
	err := e.await(ctx, func() raft.Future { future = e.raft.GetConfiguration(); return future })
	if err != nil {
		return raft.Configuration{}, err
	}
	return future.Configuration(), nil
}

type InstalledConfiguration struct {
	Configuration       raft.Configuration
	Index, AppliedIndex uint64
}

// InstalledConfiguration proves the SDK's configuration is in the durable FSM
// prefix. GetConfiguration's latest value alone may still be uncommitted.
func (e *Engine) InstalledConfiguration(ctx context.Context, latest bool) (InstalledConfiguration, error) {
	if _, err := e.Read(ctx, latest); err != nil {
		return InstalledConfiguration{}, err
	}
	var future raft.ConfigurationFuture
	if err := e.await(ctx, func() raft.Future { future = e.raft.GetConfiguration(); return future }); err != nil {
		return InstalledConfiguration{}, err
	}
	configuration := future.Configuration()
	encoded := string(raft.EncodeConfiguration(configuration))
	published := e.fsm.readView.Load()
	if published == nil {
		return InstalledConfiguration{}, ErrRecovering
	}
	if published.err != nil {
		return InstalledConfiguration{}, published.err
	}
	index, position := published.configurationIndex, published.index
	tracked, ready := published.configurationTracked, published.ready
	matches := published.configuration == encoded
	if !ready || !matches {
		return InstalledConfiguration{}, fmt.Errorf("%w: configuration_tracking=%t replay_ready=%t checkpoint_position=%d configuration_index=%d configuration_matches=%t", ErrRecovering, tracked, ready, position, index, matches)
	}
	if !tracked || index == 0 || position < index {
		return InstalledConfiguration{}, ErrRecovering
	}
	// The SDK log/Snapshot proof can span another durable publication. Recheck
	// its exact configuration/floor without waiting for an unrelated candidate.
	current := e.fsm.readView.Load()
	if current == nil {
		return InstalledConfiguration{}, ErrRecovering
	}
	if current.err != nil {
		return InstalledConfiguration{}, current.err
	}
	if !current.ready || current.index < position || current.configuration != encoded || current.configurationTracked != tracked || tracked && current.configurationIndex != index || !tracked && current.index != position {
		return InstalledConfiguration{}, ErrRecovering
	}
	return InstalledConfiguration{Configuration: configuration, Index: index, AppliedIndex: position}, nil
}
func (e *Engine) Close() error {
	e.closeOnce.Do(func() {
		e.mu.Lock()
		e.closed = true
		close(e.done)
		e.mu.Unlock()
		if e.raft != nil {
			e.closeErr = e.stopNative()
		}
		if e.transport != nil {
			_ = e.transport.Close()
		}
		e.wg.Wait()
		if e.log != nil {
			if err := e.log.Close(); e.closeErr == nil {
				e.closeErr = err
			}
		}
		if e.db != nil {
			if err := e.db.Close(); e.closeErr == nil {
				e.closeErr = err
			}
		}
		if e.lock != nil {
			if err := e.lock.Close(); e.closeErr == nil {
				e.closeErr = err
			}
		}
	})
	return e.closeErr
}

// MarshalView gives callers an owned shared snapshot, not writable DB access.
func (v View) MarshalView() ([]byte, error) {
	b, err := state.Encode(v.State)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Schema          uint8
		RaftIndex, Term uint64
		Local           bool
		State           json.RawMessage
	}{1, v.RaftIndex, v.Term, v.Local, b})
}

// Every shutdown caller waits for the same native owner termination. A second
// Raft.Shutdown future alone may return before the first shutdown has finished.
func (e *Engine) stopNative() error {
	e.stopOnce.Do(func() { e.stopErr = e.raft.Shutdown().Error(); close(e.stopped) })
	return e.stopErr
}
