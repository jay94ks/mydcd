// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	controlapi "github.com/moby/buildkit/api/services/control"
	bolt "go.etcd.io/bbolt"
)

type cachePruneCloseFailure struct {
	Transactions
	key  []byte
	fail bool
}

func (s *cachePruneCloseFailure) Update(edit func(*bolt.Tx) error) error {
	return s.Transactions.Update(func(tx *bolt.Tx) error {
		if err := edit(tx); err != nil {
			return err
		}
		var r NativeCachePruneRecord
		if s.fail && json.Unmarshal(tx.Bucket(nativeBucket).Get(s.key), &r) == nil && r.Closed {
			return errors.New("injected close commit loss")
		}
		return nil
	})
}

// Actual confined unlink/fsync and bbolt, with fixture Engine/shared grants.
// Native closure here is not proof of real Docker/Raft execution.
func TestNativeCachePruneCloseReturnsOnlyItsCacheClaimAfterRealSDKJoinAndRemoval(t *testing.T) {
	f, g, authorize := cachePruneDaemonFixture(t)
	cache := nativeWorkspacePaths(f.spec, f.plan)[2]
	preserved := filepath.Join(cache, "retained-data")
	if err := os.WriteFile(preserved, []byte("retain cache bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.jobs.CreateCachePrune(f.ctx(), g.Spec, authorize); err != nil {
		t.Fatal(err)
	}
	if err := f.jobs.StartCachePrune(f.ctx(), g.Spec, authorize); err != nil {
		t.Fatal(err)
	}
	if err := f.jobs.RecordCachePruneOutcome(g.Spec, "OK"); !errors.Is(err, ErrInvalid) {
		t.Fatal("daemon start fabricated prune success", err)
	}
	server := &cachePruneControlFixture{rows: map[string]*controlapi.UsageRecord{"one": {ID: "one", Size: 7}}}
	cachePruneDaemonSDK(t, f, g, server)
	if err := f.jobs.RunCachePrune(f.ctx(), g.Spec, authorize); err != nil {
		t.Fatal(err)
	}
	if err := f.jobs.RecordCachePruneOutcome(g.Spec, "OK"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.jobs.FinishCachePrune(f.ctx(), g.Spec); !errors.Is(err, ErrUsed) {
		t.Fatal("live native closed", err)
	}
	if err := f.jobs.StopCachePrune(f.ctx(), g.Spec, nil, true); err != nil {
		t.Fatal(err)
	}
	f.jobs.readers[g.Spec.Intent] = 1 // Model a still-owned SDK/FD consumer.
	if err := f.jobs.RemoveCachePrune(f.ctx(), g.Spec); !errors.Is(err, ErrConflict) {
		t.Fatal("reader lost its native", err)
	}
	if _, err := f.jobs.FinishCachePrune(f.ctx(), g.Spec); !errors.Is(err, ErrUsed) {
		t.Fatal("reader lost its cache", err)
	}
	delete(f.jobs.readers, g.Spec.Intent)
	if err := f.jobs.RemoveCachePrune(f.ctx(), g.Spec); err != nil {
		t.Fatal(err)
	}
	failing := &cachePruneCloseFailure{Transactions: f.db, key: nativeCachePruneKey(g.Spec.Intent), fail: true}
	f.jobs.db = failing
	if _, err := f.jobs.FinishCachePrune(f.ctx(), g.Spec); err == nil {
		t.Fatal("close commit failure hidden")
	}
	row, err := f.jobs.CachePruneRecord(g.Spec)
	if err != nil || !row.Removing || row.Closed {
		t.Fatal(row, err)
	}
	if err := f.db.View(func(tx *bolt.Tx) error {
		c, err := readNativeCache(tx, f.spec, f.plan)
		if err != nil || c.Owner != g.Spec.Intent {
			t.Fatal("uncommitted close returned cache", c.Owner, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	failing.fail = false
	f.reopen()
	witness, err := f.jobs.FinishCachePrune(f.ctx(), g.Spec)
	if err != nil || witness == ([32]byte{}) {
		t.Fatal(witness, err)
	}
	if again, err := f.jobs.FinishCachePrune(f.ctx(), g.Spec); err != nil || again != witness {
		t.Fatal("original close changed", again, err)
	}
	if _, err := os.Stat(filepath.Join(f.spec.Scope.Root.Path, cachePruneWorkspaceNames(g.Spec)[0])); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("maintenance workspace retained", err)
	}
	if data, err := os.ReadFile(preserved); err != nil || string(data) != "retain cache bytes" {
		t.Fatal("shared cache deleted", string(data), err)
	}
	if err := f.db.View(func(tx *bolt.Tx) error {
		c, err := readNativeCache(tx, f.spec, f.plan)
		if err != nil || c.Owner != ([32]byte{}) || c.RootHold == nil || c.RootHold.Returned {
			t.Fatal("cache lease incorrectly returned", c, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_, private := testScope(1, [32]byte{1})
	c, err := f.jobs.SealCachePruneCompletion(g.Spec, 500, private)
	if err != nil || !c.Valid(g.Spec) || c.Native != witness || c.Result.Code != "OK" || c.Result.RemovedCount != 1 || c.Result.ReportedBytes != 7 {
		t.Fatal(c, err)
	}
	c.Signature[0] ^= 1
	again, err := f.jobs.SealCachePruneCompletion(g.Spec, 900, private)
	if err != nil || !again.Valid(g.Spec) || again.At != 500 {
		t.Fatal("closure time/signature changed", again, err)
	}
	if err := f.jobs.RecordCachePruneOutcome(g.Spec, "FAILED"); !errors.Is(err, ErrConflict) {
		t.Fatal("original outcome overwritten", err)
	}
}

func TestNativeCachePruneCloseRejectsUnplannedDirectoryLossAndNeverDeletesAnotherOwner(t *testing.T) {
	f, g, _ := cachePruneDaemonFixture(t)
	if err := f.jobs.RecordCachePruneOutcome(g.Spec, "FAILED"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.spec.Scope.Root.Path, cachePruneWorkspaceNames(g.Spec)[0])
	if err := os.RemoveAll(path); err != nil {
		t.Fatal(err)
	}
	if _, err := f.jobs.FinishCachePrune(f.ctx(), g.Spec); !errors.Is(err, ErrStorage) {
		t.Fatal("directory loss became planned close", err)
	}
	row, err := f.jobs.CachePruneRecord(g.Spec)
	if err != nil || row.Removing || row.Closed {
		t.Fatal(row, err)
	}
	if err := f.db.View(func(tx *bolt.Tx) error {
		c, err := readNativeCache(tx, f.spec, f.plan)
		if err != nil || c.Owner != g.Spec.Intent {
			t.Fatal(c, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestNativeCachePruneUnclaimedFailureClosesWithoutReadingOrBorrowingCache(t *testing.T) {
	f := newNativeFixture(t, false)
	g := nativeCachePruneTestGrant(f, 90)
	g.Allowed = false
	if err := f.jobs.AcceptCachePruneForCleanup(g); err != nil {
		t.Fatal(err)
	}
	if err := f.jobs.RecordCachePruneOutcome(g.Spec, "PERMISSION_REVOKED"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.jobs.FinishCachePrune(context.Background(), g.Spec); err != nil {
		t.Fatal(err)
	}
	if _, err := f.jobs.cacheBorrow(f.spec, f.plan, false); err != nil {
		t.Fatal("other build's cache owner changed", err)
	}
	_, private := testScope(1, [32]byte{1})
	c, err := f.jobs.SealCachePruneCompletion(g.Spec, 200, private)
	if err != nil || c.Result.RemovedCount != 0 || c.Result.ReportedBytes != 0 || c.Result.Code != "PERMISSION_REVOKED" {
		t.Fatal(c, err)
	}
}

func TestNativeCachePruneSealedUndispatchedWorkspaceRemainsImmutableDuringCleanupRetry(t *testing.T) {
	f, g, _ := cachePruneDaemonFixture(t)
	if err := f.jobs.RecordCachePruneOutcome(g.Spec, "FAILED"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.jobs.FinishCachePrune(f.ctx(), g.Spec); err != nil {
		t.Fatal(err)
	}
	_, private := testScope(1, [32]byte{1})
	original, err := f.jobs.SealCachePruneCompletion(g.Spec, 200, private)
	if err != nil {
		t.Fatal(err)
	}
	f.reopen()
	if err := f.jobs.StopCachePrune(f.ctx(), g.Spec, nil, true); err != nil {
		t.Fatal("closed retry changed stopping flag/witness", err)
	}
	again, err := f.jobs.SealCachePruneCompletion(g.Spec, 300, private)
	if err != nil || again.Native != original.Native || again.At != original.At {
		t.Fatal(again, err)
	}
}

func TestNativeCachePruneUsesExistingRootLeaseWithARepresentativeWithoutNativeJob(t *testing.T) {
	f := newNativeFixture(t, false)
	nativeCachePruneTestIdle(t, f)
	g := nativeCachePruneTestGrant(f, 90)
	g.Spec.Source.ID = "new-queued-representative"
	if _, err := f.jobs.Record(g.Spec.Source); !errors.Is(err, ErrNativeMissing) {
		t.Fatal("fixture already has native representative", err)
	}
	if err := f.jobs.AcceptCachePrune(g); err != nil {
		t.Fatal(err)
	}
	hold, err := f.jobs.CachePruneRootHold(g.Spec)
	if err != nil || hold.Lease.Token == 0 || hold.Returned {
		t.Fatal("original cache required fake build/root lease", hold, err)
	}
	g.Phase, g.Revision, g.Index = "running", 2, 11
	root := nativeTestRoot(t, f.spec)
	if err := f.jobs.ClaimCachePrune(g, int(root.Fd())); err != nil {
		t.Fatal(err)
	}
}
