// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"sync"

	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/reconcile"
	bolt "go.etcd.io/bbolt"
)

var nativeBucket = []byte("imagebuild-native-jobs-1")
var ErrNativeMissing = errors.New("original native build journal missing")

// NativeRecord names the original effects. Sent without a matching positive
// result remains uncertain, even if Docker currently reports absence.
type NativeRecord struct {
	Schema                              uint8
	Spec                                JobSpec
	State                               reconcile.State
	Index, Revision                     uint64
	ImageID, NativeID                   string
	CreateSent, CreateNotSent           bool
	ContextSent, ContextDone            bool
	ControlsSent, ControlsDone          bool
	StartSent, Exited, Waited           bool
	ExitCode                            int64
	RemoveSent, Removed, AbsentObserved bool
	Cancel                              bool
	Workspace                           *NativeWorkspace   `json:",omitempty"`
	Publication                         *NativePublication `json:",omitempty"`
	Root                                *NativeRootHold    `json:",omitempty"`
	Completion                          *JobClosure        `json:",omitempty"`
	Outcome                             *JobResult         `json:",omitempty"`
	Solve                               *NativeSolve       `json:",omitempty"`
}

func nativeKey(spec JobSpec) []byte {
	digest := spec.Digest()
	return []byte(hex.EncodeToString(digest[:]))
}
func (r NativeRecord) Validate() error {
	digest := r.Spec.Digest()
	resource := reconcile.Resource{Present: true, Generation: 1, Spec: hex.EncodeToString(digest[:])}
	if r.Schema != 1 || r.Spec.Validate() != nil || reconcile.Validate(r.State) != nil || r.State.Desired.Resource != resource || r.State.Desired.Revision != 1 || r.Index == 0 || r.Revision == 0 || r.NativeID != "" && (!nativeID(r.NativeID) || !r.CreateSent) || r.ImageID != "" && !nativeImageID(r.ImageID) || r.CreateSent && r.ImageID == "" || r.CreateNotSent && !r.CreateSent || r.ContextSent && r.NativeID == "" || r.ContextDone && !r.ContextSent || r.ControlsSent && !r.ContextDone || r.ControlsDone && !r.ControlsSent || r.StartSent && (!r.ContextDone || !r.ControlsDone || r.NativeID == "") || r.Exited && !r.StartSent || r.Waited && r.NativeID == "" || r.RemoveSent && (r.NativeID == "" || !r.Waited) || r.AbsentObserved && r.NativeID == "" || r.Removed && !r.RemoveSent && !r.AbsentObserved {
		return ErrStorage
	}
	if r.CreateNotSent && (!r.Cancel || r.NativeID != "" || r.ContextSent || r.StartSent) || r.Exited && (!r.Waited || r.ExitCode < 0 || r.ExitCode > 255) || !r.Exited && r.ExitCode != 0 {
		return ErrStorage
	}
	if r.Workspace != nil && (r.Workspace.validate() != nil || r.CreateSent && !r.Workspace.Ready || r.Workspace.Removing && (!r.CreateSent && !r.Cancel || r.CreateSent && !r.CreateNotSent && !r.Removed)) {
		return ErrStorage
	}
	if r.Publication != nil {
		if !nativeOutputSucceeded(r) || r.Workspace == nil || !r.Workspace.Ready || r.Publication.validate(r.Spec) != nil {
			return ErrStorage
		}
		if _, closed := r.Publication.result(r.Spec); r.Workspace.Removing && !closed {
			return ErrStorage
		}
	}
	if r.Solve != nil && !r.Solve.valid(r) {
		return ErrStorage
	}
	if r.Root != nil && r.Root.validate(r.Spec.Scope.Root.Generation) != nil {
		return ErrStorage
	}
	if r.Root != nil && r.Root.Returning && (r.Workspace != nil && !r.Workspace.Closed || r.CreateSent && !r.CreateNotSent && !r.Removed) {
		return ErrStorage
	}
	if r.Completion != nil && (!r.Completion.Valid(r.Spec) || !nativeClosed(r) || r.Completion.Native != nativeCompletionWitness(r)) {
		return ErrStorage
	}
	if r.Outcome != nil && (!r.Outcome.Valid(r.Spec) || r.Completion != nil && r.Completion.Result != *r.Outcome) {
		return ErrStorage
	}
	if r.Outcome != nil && r.Publication != nil {
		result, closed := r.Publication.result(r.Spec)
		if !closed || result != *r.Outcome && !(r.Outcome.Code == "CANCELLED" && result.Code != "OK") {
			return ErrStorage
		}
	}
	if r.Outcome != nil && r.Outcome.Code == "OK" && r.Publication == nil {
		return ErrStorage
	}
	return nil
}
func nativeID(id string) bool {
	raw, err := hex.DecodeString(id)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == id
}
func nativeImageID(id string) bool { return len(id) == 71 && id[:7] == "sha256:" && nativeID(id[7:]) }

// NativeJobs borrows the existing synchronous node DB/Engine. No independent
// DB, worker, lifetime or credentials are created by this journal.
type NativeJobs struct {
	mu         sync.Mutex
	db         Transactions
	docker     *engine.Client
	authorize  NativeAuthority
	readers    map[[32]byte]int
	publishing map[[32]byte]bool
	logging    map[[32]byte]bool
	logWriters map[[32]byte]bool
	solving    map[[32]byte]bool
}
type NativeGrant struct {
	Run          JobRun
	Index, Epoch uint64
	Allowed      bool
}
type NativeAuthority func(context.Context, JobSpec, bool) (NativeGrant, error)

func OpenNativeJobs(db Transactions, docker *engine.Client, authorize NativeAuthority) (*NativeJobs, error) {
	if db == nil || docker == nil || docker.API == nil || docker.Owner == "" || authorize == nil {
		return nil, ErrInvalid
	}
	err := db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(nativeBucket)
		if err != nil {
			return err
		}
		if owner := b.Get([]byte("owner")); owner != nil && string(owner) != docker.Owner {
			return ErrStorage
		}
		return b.Put([]byte("owner"), []byte(docker.Owner))
	})
	if err != nil {
		return nil, ErrStorage
	}
	return &NativeJobs{db: db, docker: docker, authorize: authorize, readers: map[[32]byte]int{}, publishing: map[[32]byte]bool{}, logging: map[[32]byte]bool{}, logWriters: map[[32]byte]bool{}, solving: map[[32]byte]bool{}}, nil
}
func (n *NativeJobs) load(spec JobSpec) (NativeRecord, error) {
	var r NativeRecord
	err := n.db.View(func(tx *bolt.Tx) error {
		var err error
		r, err = readNativeRecord(tx, spec, n.docker.Owner)
		return err
	})
	return r, err
}

func readNativeRecord(tx *bolt.Tx, spec JobSpec, owner string) (NativeRecord, error) {
	var r NativeRecord
	b := tx.Bucket(nativeBucket)
	if b == nil || string(b.Get([]byte("owner"))) != owner {
		return r, ErrStorage
	}
	raw := b.Get(nativeKey(spec))
	if raw == nil {
		return r, ErrNativeMissing
	}
	if len(raw) > 128<<10 || json.Unmarshal(raw, &r) != nil || r.Validate() != nil || r.Spec.Digest() != spec.Digest() {
		return r, ErrStorage
	}
	canonical, err := json.Marshal(r)
	if err != nil || string(canonical) != string(raw) {
		return r, ErrStorage
	}
	return r, nil
}
func (n *NativeJobs) save(r NativeRecord) error {
	if r.Validate() != nil {
		return ErrStorage
	}
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > 128<<10 {
		return ErrStorage
	}
	return n.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(nativeBucket)
		if b == nil || string(b.Get([]byte("owner"))) != n.docker.Owner {
			return ErrStorage
		}
		return b.Put(nativeKey(r.Spec), raw)
	})
}
func (n *NativeJobs) current(ctx context.Context, r *NativeRecord, recover bool) (NativeGrant, error) {
	g, err := n.authorize(ctx, r.Spec.Own(), recover)
	if err != nil {
		return g, err
	}
	if g.Run.Shape() != nil || g.Run.Spec.Digest() != r.Spec.Digest() || g.Index < r.Index || g.Run.Revision < r.Revision || g.Epoch == 0 || !recover && (!g.Allowed || g.Run.Cancel || g.Run.Terminal() || g.Run.Phase != "running") {
		return g, ErrConflict
	}
	if g.Index != r.Index || g.Run.Revision != r.Revision {
		r.Index, r.Revision = g.Index, g.Run.Revision
		if err := n.save(*r); err != nil {
			return g, err
		}
	}
	return g, nil
}
func (n *NativeJobs) Accept(grant NativeGrant) error {
	return n.accept(grant, false)
}

// A queued job may expire or lose its grant before this node accepted it.
// This records cleanup-only identity, never permission for native dispatch.
func (n *NativeJobs) AcceptForCleanup(grant NativeGrant) error {
	return n.accept(grant, true)
}
func (n *NativeJobs) accept(grant NativeGrant, cleanup bool) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	spec := grant.Run.Spec
	if grant.Run.Shape() != nil || spec.Validate() != nil || n.docker.Owner != engine.Owner(spec.Cluster, spec.Scope.Root.Key) || grant.Index == 0 || grant.Run.Revision == 0 || grant.Epoch == 0 {
		return ErrInvalid
	}
	r, err := n.load(spec)
	if err == nil {
		if !reflect.DeepEqual(r.Spec, spec) {
			return ErrConflict
		}
		return nil
	}
	if !errors.Is(err, ErrNativeMissing) {
		return err
	}
	// A shared begin is published only AFTER this original local record. A
	// missing record for running/unknown is corruption, never a fresh create.
	// Queued cancellation may create a cleanup-only record: no native effect
	// has been dispatched, but the accepted Secret grants still need closure.
	if grant.Run.Phase != "queued" || !cleanup && !grant.Allowed && !grant.Run.Cancel {
		return ErrNativeMissing
	}
	digest := spec.Digest()
	state, err := reconcile.SetDesired(reconcile.State{}, reconcile.Desired{Revision: 1, Resource: reconcile.Resource{Present: true, Generation: 1, Spec: hex.EncodeToString(digest[:])}})
	if err != nil {
		return err
	}
	state, _, err = reconcile.Plan(state)
	if err != nil || state.Pending == nil {
		return ErrStorage
	}
	r = NativeRecord{Schema: 1, Spec: spec.Own(), State: state, Index: grant.Index, Revision: grant.Run.Revision, Cancel: cleanup || grant.Run.Cancel}
	return n.save(r)
}
func (n *NativeJobs) Record(spec JobSpec) (NativeRecord, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.load(spec)
}

// Records discovers originals even if shared metadata is absent. It never
// initializes a missing job; a corrupt journal cannot authorize a new effect.
func (n *NativeJobs) Records() ([]NativeRecord, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	var records []NativeRecord
	err := n.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(nativeBucket)
		if b == nil || string(b.Get([]byte("owner"))) != n.docker.Owner {
			return ErrStorage
		}
		return b.ForEach(func(key, raw []byte) error {
			if len(key) != 64 {
				return nil
			}
			if _, err := hex.DecodeString(string(key)); err != nil {
				return nil
			}
			var r NativeRecord
			if raw == nil || len(raw) > 128<<10 || json.Unmarshal(raw, &r) != nil {
				return ErrStorage
			}
			r, err := readNativeRecord(tx, r.Spec, n.docker.Owner)
			if err != nil || string(nativeKey(r.Spec)) != string(key) {
				return ErrStorage
			}
			records = append(records, r)
			return nil
		})
	})
	return records, err
}

func (n *NativeJobs) RecordOutcome(spec JobSpec, result JobResult) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !result.Valid(spec) {
		return ErrInvalid
	}
	r, err := n.load(spec)
	if err != nil {
		return err
	}
	if r.Outcome != nil {
		if *r.Outcome != result {
			return ErrConflict
		}
		return nil
	}
	if r.Completion != nil && r.Completion.Result != result {
		return ErrConflict
	}
	if r.Publication != nil {
		published, closed := r.Publication.result(spec)
		if !closed || published != result && !(result.Code == "CANCELLED" && published.Code != "OK") {
			return ErrUsed
		}
	} else if result.Code == "OK" {
		return ErrConflict
	}
	r.Outcome = &result
	return n.save(r)
}
