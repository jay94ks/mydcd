// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"context"
	"errors"
	"testing"

	"github.com/jay94ks/seafield/internal/reconcile"
)

// Real native DB/files and SDK fixture, with explicitly injected RootManager
// leases. This does not claim a Docker/BuildKit execution or Raft quorum.
func TestNativeCompletionRequiresClosedWorkspaceAndOriginalRootReturn(t *testing.T) {
	f := newNativeFixture(t, false)
	ctx := f.ctx()
	_, key := testScope(1, [32]byte{1})
	result := JobResult{Code: "BUILD_FAILED"}
	if err := f.jobs.BeginRootReturn(f.spec, JobRoot); !errors.Is(err, ErrUsed) {
		t.Fatal("root returned while workspace open", err)
	}
	if _, err := f.jobs.SealCompletion(f.grant, result, 103, key); !errors.Is(err, ErrUsed) {
		t.Fatal("open workspace became completion", err)
	}
	if err := f.jobs.BindRootHold(f.spec, JobRoot, reconcile.Lease{Generation: f.spec.Scope.Root.Generation, Token: 99}); !errors.Is(err, ErrStorage) {
		t.Fatal("replaced original lease", err)
	}
	if err := f.jobs.ObserveExit(ctx, f.spec, true); err != nil {
		t.Fatal(err)
	}
	if _, err := f.jobs.FinishWorkspace(ctx, f.spec); err != nil {
		t.Fatal(err)
	}
	if _, err := f.jobs.SealCompletion(f.grant, result, 103, key); !errors.Is(err, ErrUsed) {
		t.Fatal("closure preceded root return", err)
	}
	if err := f.jobs.BeginRootReturn(f.spec, JobRoot); err != nil {
		t.Fatal(err)
	}
	f.reopen() // recover an interrupted Return acknowledgement
	if err := f.jobs.BindRootHold(f.spec, JobRoot, reconcile.Lease{Generation: f.spec.Scope.Root.Generation, Token: 1}); !errors.Is(err, ErrConflict) {
		t.Fatal("returning hold reopened for allocation", err)
	}
	if err := f.jobs.FinishRootReturn(f.spec, JobRoot); err != nil {
		t.Fatal(err)
	}
	closure, err := f.jobs.SealCompletion(f.grant, result, 103, key)
	if err != nil || !closure.Valid(f.spec) {
		t.Fatal(closure, err)
	}
	closure.Signature[0] ^= 1
	f.reopen()
	again, err := f.jobs.SealCompletion(f.grant, result, 999, key)
	if err != nil || again.At != 103 || !again.Valid(f.spec) {
		t.Fatal("original closure changed after lost report", again, err)
	}
	if _, err := f.jobs.SealCompletion(f.grant, JobResult{Code: "TIMEOUT"}, 999, key); !errors.Is(err, ErrConflict) {
		t.Fatal("terminal result replaced", err)
	}
	hold, exists, err := f.jobs.RootHold(f.spec, CacheRoot)
	if err != nil || !exists || hold.Returning || hold.Returned || hold.Lease.Token != uint64(CacheRoot) {
		t.Fatal("job completion returned reusable cache root", hold, exists, err)
	}
	if err := f.jobs.BeginRootReturn(f.spec, CacheRoot); !errors.Is(err, ErrUsed) {
		t.Fatal("cache bytes lost their root dependency", err)
	}
}

func TestNativeQueuedCancellationCanCloseWithoutAllocatingWorkspace(t *testing.T) {
	f := newNativeFixture(t, false)
	spec := f.spec.Own()
	spec.ID = "queued-cancel"
	run, err := NewJob(spec)
	if err != nil {
		t.Fatal(err)
	}
	run, err = run.RequestCancel(run.Revision)
	if err != nil {
		t.Fatal(err)
	}
	grant := NativeGrant{Run: run, Index: 1, Epoch: 1}
	if err := f.jobs.Accept(grant); err != nil {
		t.Fatal(err)
	}
	_, key := testScope(1, [32]byte{1})
	closure, err := f.jobs.SealCompletion(grant, JobResult{Code: "CANCELLED"}, 103, key)
	if err != nil || !closure.Valid(spec) {
		t.Fatal(closure, err)
	}
	r, err := f.jobs.Record(spec)
	if err != nil || r.Root != nil || r.Workspace != nil || r.CreateSent {
		t.Fatal("cleanup-only job allocated resources", r, err)
	}
	run, err = NewJob(spec)
	if err != nil {
		t.Fatal(err)
	}
	run.Spec.ID = "lost-running"
	run, err = run.Begin(run.Revision, 101, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.jobs.Accept(NativeGrant{Run: run, Index: 2, Epoch: 1, Allowed: true}); !errors.Is(err, ErrNativeMissing) {
		t.Fatal("missing running journal recreated", err)
	}
}

func TestNativeRootBorrowIntentSurvivesLostAcknowledgement(t *testing.T) {
	f := newNativeFixture(t, false)
	n, spec := anotherWorkspaceJob(t, f, "borrow-loss")
	// The original acknowledgement is deliberately absent, as when Borrow
	// commits in RootManager but the native-journal write never completes.
	n.mu.Lock()
	r, err := n.load(spec)
	if err == nil {
		r.Root = &NativeRootHold{}
		err = n.save(r)
	}
	n.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err := n.PlanRootHold(context.Background(), spec, JobRoot); err != nil {
		t.Fatal(err)
	}
	original := reconcile.Lease{Generation: spec.Scope.Root.Generation, Token: 41}
	if err := n.BindRootHold(spec, JobRoot, original); err != nil {
		t.Fatal(err)
	}
	hold, exists, err := n.RootHold(spec, JobRoot)
	if err != nil || !exists || hold.Lease != original {
		t.Fatal(hold, exists, err)
	}
	wrong := original
	wrong.Generation++
	if err := n.BindRootHold(spec, JobRoot, wrong); !errors.Is(err, ErrInvalid) {
		t.Fatal("changed root generation", err)
	}
	consumer, err := n.RootConsumer(spec, JobRoot)
	cache, cacheErr := n.RootConsumer(spec, CacheRoot)
	if err != nil || cacheErr != nil || consumer == cache {
		t.Fatal("job/cache consumer identity collision", err, cacheErr)
	}
}
