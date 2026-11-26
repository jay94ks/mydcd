// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
)

func TestNativeCleanupDoesNotWaitForQuorumBeforeOriginalStopAndRemove(t *testing.T) {
	f := newNativeFixture(t, false)
	ctx := f.ctx()
	f.prepare(ctx)
	if err := f.jobs.Start(ctx, f.spec); err != nil {
		t.Fatal(err)
	}
	var called atomic.Int32
	f.jobs.authorize = func(ctx context.Context, _ JobSpec, _ bool) (NativeGrant, error) {
		called.Add(1)
		<-ctx.Done()
		return NativeGrant{}, ctx.Err()
	}
	// Keep the existing fixture budget, which admits the frozen 10s Docker
	// grace plus reply allowance. A 3s deadline refuses Stop before I/O.
	cleanup, cancel := context.WithCancel(ctx)
	defer cancel()
	if err := f.jobs.ObserveExit(cleanup, f.spec, true); err != nil {
		t.Fatal("cleanup waited on unavailable quorum", err)
	}
	if err := f.jobs.Remove(cleanup, f.spec); err != nil {
		t.Fatal(err)
	}
	if called.Load() != 0 {
		t.Fatal("cleanup queried new authority", called.Load())
	}
	record, err := f.jobs.Record(f.spec)
	if err != nil || !record.Waited || !record.Removed || !record.Cancel {
		t.Fatal(record, err)
	}
}

func TestNativeWorkerKeepsChosenOutcomeBeforeActualClosureAndAfterRestart(t *testing.T) {
	f := newNativeFixture(t, false)
	ctx := f.ctx()
	chosen := JobResult{Code: "TIMEOUT"}
	if err := f.jobs.RecordOutcome(f.spec, chosen); err != nil {
		t.Fatal(err)
	}
	_, key := testScope(1, [32]byte{1})
	if _, err := f.jobs.SealCompletion(f.grant, chosen, 103, key); !errors.Is(err, ErrUsed) {
		t.Fatal("desired outcome fabricated actual cleanup", err)
	}
	f.reopen()
	if err := f.jobs.RecordOutcome(f.spec, JobResult{Code: "BUILD_FAILED"}); !errors.Is(err, ErrConflict) {
		t.Fatal("restart replaced original reason", err)
	}
	if err := f.jobs.ObserveExit(ctx, f.spec, true); err != nil {
		t.Fatal(err)
	}
	if _, err := f.jobs.FinishWorkspace(ctx, f.spec); err != nil {
		t.Fatal(err)
	}
	if err := f.jobs.BeginRootReturn(f.spec, JobRoot); err != nil {
		t.Fatal(err)
	}
	if err := f.jobs.FinishRootReturn(f.spec, JobRoot); err != nil {
		t.Fatal(err)
	}
	if _, err := f.jobs.SealCompletion(f.grant, JobResult{Code: "BUILD_FAILED"}, 104, key); !errors.Is(err, ErrConflict) {
		t.Fatal("closure changed chosen outcome", err)
	}
	closure, err := f.jobs.SealCompletion(f.grant, chosen, 104, key)
	if err != nil || closure.Result != chosen {
		t.Fatal(closure, err)
	}
	records, err := f.jobs.Records()
	if err != nil || len(records) != 1 || records[0].Spec.Digest() != f.spec.Digest() || records[0].Outcome == nil || *records[0].Outcome != chosen {
		t.Fatal("original journal discovery", records, err)
	}
}

func TestExpiredQueuedJobCanAcceptOnlyCleanupIdentity(t *testing.T) {
	f := newNativeFixture(t, false)
	spec := f.spec.Own()
	spec.ID = "expired-queued"
	run, err := NewJob(spec)
	if err != nil {
		t.Fatal(err)
	}
	grant := NativeGrant{Run: run, Index: 2, Epoch: 1}
	if err := f.jobs.Accept(grant); !errors.Is(err, ErrNativeMissing) {
		t.Fatal("expired job granted new dispatch", err)
	}
	if err := f.jobs.AcceptForCleanup(grant); err != nil {
		t.Fatal(err)
	}
	record, err := f.jobs.Record(spec)
	if err != nil || !record.Cancel || record.CreateSent || record.Root != nil || record.Workspace != nil {
		t.Fatal("cleanup identity allocated native resources", record, err)
	}
	if err := f.jobs.RecordOutcome(spec, JobResult{Code: "TIMEOUT"}); err != nil {
		t.Fatal(err)
	}
	_, key := testScope(1, [32]byte{1})
	if closure, err := f.jobs.SealCompletion(grant, JobResult{Code: "TIMEOUT"}, spec.CreatedAt+spec.Policy.Seconds, key); err != nil || !closure.Valid(spec) {
		t.Fatal(closure, err)
	}
	running, err := run.Begin(run.Revision, spec.CreatedAt+1, nil)
	if err != nil {
		t.Fatal(err)
	}
	running.Spec.ID = "missing-running-cleanup"
	if err := f.jobs.AcceptForCleanup(NativeGrant{Run: running, Index: 3, Epoch: 1}); !errors.Is(err, ErrNativeMissing) {
		t.Fatal("lost dispatched journal recreated for cleanup", err)
	}
}
