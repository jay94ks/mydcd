// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"encoding/json"
	"errors"
	"testing"

	bolt "go.etcd.io/bbolt"
)

// Actual native DB/files and existing Docker protocol fixture. RootManager
// acknowledgements are injected; these are census tests, not tenant teardown
// or actual Docker/BuildKit execution evidence.
func TestNativeTenantCensusKeepsUnclosedJobsAndRetainedCacheLease(t *testing.T) {
	f := newNativeFixture(t, false)
	activity, err := f.jobs.TenantActivity(f.spec.Tenant)
	if err != nil || activity.Resources == 0 || activity.Leases != 2 {
		t.Fatal("unclosed original omitted", activity, err)
	}
	if stored, err := StoredTenantActivity(f.db, f.docker.Owner, f.spec.Tenant); err != nil || stored != activity {
		t.Fatal("disabled adapter omitted stored obligations", stored, err)
	}
	if _, err := StoredTenantActivity(f.db, "foreign-owner", f.spec.Tenant); !errors.Is(err, ErrStorage) {
		t.Fatal("read-only census accepted foreign owner", err)
	}
	if other, err := f.jobs.TenantActivity("other-tenant"); err != nil || !other.Empty() {
		t.Fatal("other tenant's work counted", other, err)
	}
	nativeCachePruneTestIdle(t, f)
	if err := f.jobs.BeginRootReturn(f.spec, JobRoot); err != nil {
		t.Fatal(err)
	}
	if err := f.jobs.FinishRootReturn(f.spec, JobRoot); err != nil {
		t.Fatal(err)
	}
	_, private := testScope(1, [32]byte{1})
	if _, err := f.jobs.SealCompletion(f.grant, JobResult{Code: "BUILD_FAILED"}, 110, private); err != nil {
		t.Fatal(err)
	}
	f.reopen()
	activity, err = f.jobs.TenantActivity(f.spec.Tenant)
	if err != nil || activity.Resources != 0 || activity.Leases != 1 || activity.Empty() {
		t.Fatal("job completion erased retained cache root", activity, err)
	}
	g := nativeCachePruneTestGrant(f, 92)
	g.Allowed = false
	if err := f.jobs.AcceptCachePruneForCleanup(g); err != nil {
		t.Fatal(err)
	}
	activity, err = f.jobs.TenantActivity(f.spec.Tenant)
	if err != nil || activity.Resources != 1 || activity.Leases != 1 {
		t.Fatal("undispatched but unclosed maintenance omitted", activity, err)
	}
	if err := f.jobs.RecordCachePruneOutcome(g.Spec, "PERMISSION_REVOKED"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.jobs.FinishCachePrune(f.ctx(), g.Spec); err != nil {
		t.Fatal(err)
	}
	if _, err := f.jobs.SealCachePruneCompletion(g.Spec, 111, private); err != nil {
		t.Fatal(err)
	}
	f.jobs.readers[g.Spec.Intent] = 1
	f.jobs.logging[f.spec.Digest()] = true
	activity, err = f.jobs.TenantActivity(f.spec.Tenant)
	if err != nil || activity.Resources != 0 || activity.Leases != 1 || activity.Flows != 1 || activity.Writers != 1 {
		t.Fatal("live reader/log writer omitted after closure", activity, err)
	}
	delete(f.jobs.readers, g.Spec.Intent)
	delete(f.jobs.logging, f.spec.Digest())
}

func TestNativeTenantCensusNeverTurnsMissingOriginalOrOrphanIOIntoEmpty(t *testing.T) {
	for _, cause := range []string{"missing-source", "missing-cache-lease", "orphan-reader", "orphan-solve"} {
		t.Run(cause, func(t *testing.T) {
			f := newNativeFixture(t, false)
			switch cause {
			case "missing-source":
				if err := f.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(nativeBucket).Delete(nativeKey(f.spec)) }); err != nil {
					t.Fatal(err)
				}
			case "orphan-reader":
				f.jobs.readers[[32]byte{222}] = 1
			case "missing-cache-lease":
				if err := f.db.Update(func(tx *bolt.Tx) error {
					cache, err := readNativeCache(tx, f.spec, f.plan)
					if err != nil {
						return err
					}
					cache.RootHold = nil
					raw, err := json.Marshal(cache)
					if err != nil {
						return err
					}
					return tx.Bucket(nativeBucket).Put(nativeCacheKey(f.plan.Cache), raw)
				}); err != nil {
					t.Fatal(err)
				}
			case "orphan-solve":
				f.jobs.solving[[32]byte{222}] = true
			}
			if _, err := f.jobs.TenantActivity("other-tenant"); !errors.Is(err, ErrStorage) {
				t.Fatal("unknown original became a positive empty census", err)
			}
		})
	}
}
