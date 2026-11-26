// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"errors"
	"testing"

	bolt "go.etcd.io/bbolt"
)

// Real original node DB and the no-dispatch cleanup path. No SDK or running
// Docker process is fabricated as completed by this metadata collection test.
func closedAutomaticMetadataFixture(t *testing.T) (*nativeFixture, NativeCachePruneSpec) {
	t.Helper()
	f := newNativeFixture(t, false)
	nativeCachePruneTestIdle(t, f)
	g := nativeCachePruneTestGrant(f, 90)
	policy := g.Spec.Source.Policy.Own()
	g.Spec.Automatic = &policy
	g.Spec.Filter = CachePruneFilter{Mode: "policy"}
	g.Allowed = false
	if err := f.jobs.AcceptCachePruneForCleanup(g); err != nil {
		t.Fatal(err)
	}
	if err := f.jobs.RecordCachePruneOutcome(g.Spec, "PERMISSION_REVOKED"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.jobs.FinishCachePrune(f.ctx(), g.Spec); err != nil {
		t.Fatal(err)
	}
	_, private := testScope(1, [32]byte{1})
	if _, err := f.jobs.SealCachePruneCompletion(g.Spec, 110, private); err != nil {
		t.Fatal(err)
	}
	return f, g.Spec
}

func TestAutomaticMetadataCollectionKeepsCurrentAheadAndActiveEvidenceAndRollsBack(t *testing.T) {
	f, spec := closedAutomaticMetadataFixture(t)
	if rows, err := f.jobs.CollectClosedAutomaticCachePrunes(100, map[[32]byte]bool{spec.Intent: true}); err != nil || len(rows) != 0 {
		t.Fatal("shared current evidence removed", rows, err)
	}
	if rows, err := f.jobs.CollectClosedAutomaticCachePrunes(1, nil); err != nil || len(rows) != 0 {
		t.Fatal("locally ahead evidence removed", rows, err)
	}
	f.jobs.solving[spec.Intent] = true
	if rows, err := f.jobs.CollectClosedAutomaticCachePrunes(100, nil); err != nil || len(rows) != 0 {
		t.Fatal("active original consumer removed", rows, err)
	}
	delete(f.jobs.solving, spec.Intent)
	f.jobs.readers[spec.Intent] = 1
	if rows, err := f.jobs.CollectClosedAutomaticCachePrunes(100, nil); err != nil || len(rows) != 0 {
		t.Fatal("original reader evidence removed", rows, err)
	}
	delete(f.jobs.readers, spec.Intent)
	rollback := &cachePruneRollbackStore{Transactions: f.db, fail: true}
	f.jobs.db = rollback
	if rows, err := f.jobs.CollectClosedAutomaticCachePrunes(100, nil); err == nil || len(rows) != 0 {
		t.Fatal("failed deletion exposed committed results", rows, err)
	}
	if _, err := f.jobs.CachePruneRecord(spec); err != nil {
		t.Fatal("original lost on rollback", err)
	}
	rollback.fail = false
	rows, err := f.jobs.CollectClosedAutomaticCachePrunes(100, nil)
	if err != nil || len(rows) != 1 || rows[0] != spec.Intent {
		t.Fatal(rows, err)
	}
	if _, err := f.jobs.CachePruneRecord(spec); !errors.Is(err, ErrNativeMissing) {
		t.Fatal("retired automatic row retained", err)
	}
	if err := f.db.View(func(tx *bolt.Tx) error {
		cache, err := readNativeCache(tx, f.spec, f.plan)
		if err != nil || !cache.Directory.valid() || cache.RootHold == nil || cache.RootHold.Returned {
			t.Fatal("metadata GC returned original cache lease or data", cache, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestAutomaticMetadataCollectionNeverRemovesManualOriginals(t *testing.T) {
	f := newNativeFixture(t, false)
	nativeCachePruneTestIdle(t, f)
	g := nativeCachePruneTestGrant(f, 91)
	g.Allowed = false
	if err := f.jobs.AcceptCachePruneForCleanup(g); err != nil {
		t.Fatal(err)
	}
	if err := f.jobs.RecordCachePruneOutcome(g.Spec, "PERMISSION_REVOKED"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.jobs.FinishCachePrune(f.ctx(), g.Spec); err != nil {
		t.Fatal(err)
	}
	_, private := testScope(1, [32]byte{1})
	if _, err := f.jobs.SealCachePruneCompletion(g.Spec, 110, private); err != nil {
		t.Fatal(err)
	}
	if rows, err := f.jobs.CollectClosedAutomaticCachePrunes(100, nil); err != nil || len(rows) != 0 {
		t.Fatal("manual original collected by recurring retention", rows, err)
	}
}
