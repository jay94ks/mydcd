// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func nativeCachePruneTestGrant(f *nativeFixture, intent byte) NativeCachePruneGrant {
	return NativeCachePruneGrant{Spec: NativeCachePruneSpec{Schema: 1, Intent: [32]byte{intent}, ID: "cleanup-one", At: f.spec.CreatedAt, Source: f.spec.Own(), Filter: CachePruneFilter{Mode: "all"}}, Index: 10, Revision: 1, Epoch: 1, Phase: "queued", Allowed: true}
}
func nativeCachePruneTestIdle(t *testing.T, f *nativeFixture) {
	t.Helper()
	if err := f.jobs.ObserveExit(f.ctx(), f.spec, true); err != nil {
		t.Fatal(err)
	}
	if _, err := f.jobs.FinishWorkspace(f.ctx(), f.spec); err != nil {
		t.Fatal(err)
	}
}

type cachePruneRollbackStore struct {
	Transactions
	fail bool
}

func (s *cachePruneRollbackStore) Update(edit func(*bolt.Tx) error) error {
	return s.Transactions.Update(func(tx *bolt.Tx) error {
		if err := edit(tx); err != nil {
			return err
		}
		if s.fail {
			return errors.New("injected pre-commit failure")
		}
		return nil
	})
}

// Actual root/cache files and bbolt; shared grants and Docker are fixture
// inputs. No maintenance container or SDK deletion is claimed by these tests.
func TestNativeCachePruneBorrowsExistingCacheAtomicallyAndKeepsOriginalBuildSeparate(t *testing.T) {
	f := newNativeFixture(t, false)
	g := nativeCachePruneTestGrant(f, 90)
	if err := f.jobs.AcceptCachePrune(g); err != nil {
		t.Fatal(err)
	}
	root := nativeTestRoot(t, f.spec)
	running := g
	running.Index++
	running.Revision = 2
	running.Phase = "running"
	if err := f.jobs.ClaimCachePrune(running, int(root.Fd())); !errors.Is(err, ErrUsed) {
		t.Fatal("active build cache stolen", err)
	}
	nativeCachePruneTestIdle(t, f)
	wrapped := &cachePruneRollbackStore{Transactions: f.db, fail: true}
	f.jobs.db = wrapped
	if err := f.jobs.ClaimCachePrune(running, int(root.Fd())); err == nil {
		t.Fatal("injected transaction committed")
	}
	wrapped.fail = false
	row, err := f.jobs.CachePruneRecord(g.Spec)
	if err != nil || row.Claimed {
		t.Fatal("partial cache borrow survived rollback", row, err)
	}
	if err := f.db.View(func(tx *bolt.Tx) error {
		c, err := readNativeCache(tx, f.spec, f.plan)
		if err != nil || c.Owner != ([32]byte{}) {
			t.Fatal("rollback left cache owner", c.Owner, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.jobs.ClaimCachePrune(running, int(root.Fd())); err != nil {
		t.Fatal(err)
	}
	f.reopen()
	if err := f.jobs.ClaimCachePrune(running, int(root.Fd())); err != nil {
		t.Fatal("original borrow failed after reopen", err)
	}
	row, err = f.jobs.CachePruneRecord(g.Spec)
	if err != nil || !row.Claimed || row.Spec.Source.Digest() != f.spec.Digest() || row.Spec.Intent == f.spec.Digest() {
		t.Fatal(row, err)
	}
	if _, err := f.jobs.cacheBorrow(f.spec, f.plan, true); !errors.Is(err, ErrUsed) {
		t.Fatal("original build took maintenance cache", err)
	}
	// Re-reading an old build closure does not free the maintenance's borrow.
	if _, err := f.jobs.FinishWorkspace(f.ctx(), f.spec); err != nil {
		t.Fatal(err)
	}
	other := nativeCachePruneTestGrant(f, 91)
	if err := f.jobs.AcceptCachePrune(other); err != nil {
		t.Fatal(err)
	}
	other.Phase, other.Revision, other.Index = "running", 2, 11
	if err := f.jobs.ClaimCachePrune(other, int(root.Fd())); !errors.Is(err, ErrUsed) {
		t.Fatal("second maintenance stole cache", err)
	}
	if rows, err := f.jobs.CachePruneRecords(); err != nil || len(rows) != 2 {
		t.Fatal("maintenance originals not discovered", rows, err)
	}
	if rows, err := f.jobs.Records(); err != nil || len(rows) != 1 || rows[0].Spec.Digest() != f.spec.Digest() {
		t.Fatal("maintenance fabricated another build", rows, err)
	}
	changed := g.Spec.Own()
	changed.Filter = CachePruneFilter{Mode: "unused", UnusedDays: 1}
	if _, err := f.jobs.CachePruneRecord(changed); !errors.Is(err, ErrStorage) {
		t.Fatal("changed original accepted", err)
	}
}

func TestNativeCachePruneNeverRecreatesMissingRunningJournalOrReplacedDirectories(t *testing.T) {
	f := newNativeFixture(t, false)
	nativeCachePruneTestIdle(t, f)
	g := nativeCachePruneTestGrant(f, 90)
	root := nativeTestRoot(t, f.spec)
	missing := g
	missing.Phase, missing.Revision = "running", 2
	if err := f.jobs.AcceptCachePrune(missing); !errors.Is(err, ErrNativeMissing) {
		t.Fatal("missing running journal recreated", err)
	}
	if err := f.jobs.AcceptCachePrune(g); err != nil {
		t.Fatal(err)
	}
	wrong, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer wrong.Close()
	if err := f.jobs.ClaimCachePrune(missing, int(wrong.Fd())); !errors.Is(err, ErrStorage) {
		t.Fatal("foreign root FD accepted", err)
	}
	original := nativeWorkspacePaths(f.spec, f.plan)[2]
	if err := os.Rename(original, original+"-old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(original, 0700); err != nil {
		t.Fatal(err)
	}
	if err := f.jobs.ClaimCachePrune(missing, int(root.Fd())); !errors.Is(err, ErrStorage) {
		t.Fatal("replaced cache inode adopted", err)
	}
	if _, err := os.Stat(filepath.Join(original + "-old")); err != nil {
		t.Fatal("original cache removed", err)
	}
}

func TestNativeCachePruneCleanupOnlyDoesNotAuthorizeLaterDispatch(t *testing.T) {
	f := newNativeFixture(t, false)
	nativeCachePruneTestIdle(t, f)
	g := nativeCachePruneTestGrant(f, 90)
	g.Allowed = false
	if err := f.jobs.AcceptCachePrune(g); !errors.Is(err, ErrNativeMissing) {
		t.Fatal("revoked fresh execution accepted", err)
	}
	if err := f.jobs.AcceptCachePruneForCleanup(g); err != nil {
		t.Fatal(err)
	}
	g.Phase, g.Revision, g.Index, g.Allowed = "running", 2, 11, true
	root := nativeTestRoot(t, f.spec)
	if err := f.jobs.ClaimCachePrune(g, int(root.Fd())); !errors.Is(err, ErrConflict) {
		t.Fatal("cleanup-only record became execution", err)
	}
}
