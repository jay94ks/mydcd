// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jay94ks/seafield/internal/reconcile"
	bolt "go.etcd.io/bbolt"
)

// Native files/DB and the existing Docker protocol fixture are real. Tenant
// grant and RootManager lease acknowledgements are injected here; the actual
// RootManager adapter and user/Raft grant are covered at their own boundaries.
func closedTenantCacheFixture(t *testing.T) (*nativeFixture, NativeCacheRetirementGrant) {
	t.Helper()
	f := newNativeFixture(t, false)
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
	return f, NativeCacheRetirementGrant{Source: f.spec.Own(), Operation: "tenant-retire", InventoryHash: [32]byte{2}, OwnersHash: [32]byte{3}, StartedRevision: 2, Index: 20, Epoch: 1}
}

type cacheReadyCommitFailure struct {
	Transactions
	spec JobSpec
}

func (s *cacheReadyCommitFailure) Update(edit func(*bolt.Tx) error) error {
	return s.Transactions.Update(func(tx *bolt.Tx) error {
		if err := edit(tx); err != nil {
			return err
		}
		var row NativeRecord
		if json.Unmarshal(tx.Bucket(nativeBucket).Get(nativeKey(s.spec)), &row) != nil {
			return ErrStorage
		}
		if row.Workspace != nil && row.Workspace.Ready {
			return errors.New("injected Ready commit loss")
		}
		return nil
	})
}

func TestTenantCacheRetirementRecoversOnlyEmptyOriginalPreReadyAllocation(t *testing.T) {
	for _, unknownData := range []bool{false, true} {
		t.Run(map[bool]string{false: "empty", true: "unknown-data"}[unknownData], func(t *testing.T) {
			f, _ := closedTenantCacheFixture(t)
			spec := f.spec.Own()
			spec.ID, spec.Context.ID, spec.Scope.Context = "partial-build", "partial", "partial"
			_, private := testScope(1, [32]byte{1})
			spec.Seal.Scope = spec.Scope.Hash()
			spec.Seal.Signature = ed25519.Sign(private, SealReceiptBytes(spec.Seal))
			spec.Version = VersionID(spec.Seal)
			run, err := NewJob(spec)
			if err != nil {
				t.Fatal(err)
			}
			grant := NativeGrant{Run: run, Index: 3, Epoch: 1, Allowed: true}
			native, err := OpenNativeJobs(f.db, f.docker, func(context.Context, JobSpec, bool) (NativeGrant, error) { return grant, nil })
			if err != nil {
				t.Fatal(err)
			}
			if err := native.Accept(grant); err != nil {
				t.Fatal(err)
			}
			for _, use := range []RootUse{JobRoot, CacheRoot} {
				if err := native.PlanRootHold(f.ctx(), spec, use); err != nil {
					t.Fatal(err)
				}
				if err := native.BindRootHold(spec, use, reconcile.Lease{Generation: spec.Scope.Root.Generation, Token: 20 + uint64(use)}); err != nil {
					t.Fatal(err)
				}
			}
			root := nativeTestRoot(t, spec)
			native.db = &cacheReadyCommitFailure{Transactions: f.db, spec: spec}
			if err := native.PrepareWorkspace(f.ctx(), spec, int(root.Fd())); err == nil {
				t.Fatal("Ready commit failure missing")
			}
			native.db = f.db
			if err := native.ObserveExit(f.ctx(), spec, true); err != nil {
				t.Fatal(err)
			}
			if _, err := native.FinishWorkspace(f.ctx(), spec); err != nil {
				t.Fatal(err)
			}
			if err := native.BeginRootReturn(spec, JobRoot); err != nil {
				t.Fatal(err)
			}
			if err := native.FinishRootReturn(spec, JobRoot); err != nil {
				t.Fatal(err)
			}
			if _, err := native.SealCompletion(grant, JobResult{Code: "BUILD_FAILED"}, 110, private); err != nil {
				t.Fatal(err)
			}
			plan, err := PlanNative(spec, f.docker.Owner)
			if err != nil {
				t.Fatal(err)
			}
			cachePath := nativeWorkspacePaths(spec, plan)[2]
			if unknownData {
				if err := os.WriteFile(filepath.Join(cachePath, "unrecorded"), []byte("preserve"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			retirement := NativeCacheRetirementGrant{Source: spec, Operation: "retire-tenant", InventoryHash: [32]byte{2}, OwnersHash: [32]byte{3}, StartedRevision: 2, Index: 20, Epoch: 1}
			err = native.RetireTenantCache(f.ctx(), retirement, reconcile.Lease{Generation: spec.Scope.Root.Generation, Token: 22}, int(root.Fd()))
			if unknownData {
				if !errors.Is(err, ErrStorage) {
					t.Fatal("unrecorded data adopted as empty allocation", err)
				}
				if data, err := os.ReadFile(filepath.Join(cachePath, "unrecorded")); err != nil || string(data) != "preserve" {
					t.Fatal("unknown data deleted", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(cachePath); !os.IsNotExist(err) {
				t.Fatal("empty pre-Ready allocation not removed", err)
			}
		})
	}
}

func originalCacheLease(f *nativeFixture) reconcile.Lease {
	return reconcile.Lease{Generation: f.spec.Scope.Root.Generation, Token: uint64(CacheRoot)}
}

func TestTenantCacheRetirementUnlinksOnlyOriginalAndReturnsLeaseSeparately(t *testing.T) {
	f, g := closedTenantCacheFixture(t)
	root := nativeTestRoot(t, f.spec)
	cachePath := nativeWorkspacePaths(f.spec, f.plan)[2]
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(cachePath, "external-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cachePath, "cache-bytes"), []byte("discardable cache"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.jobs.RetireTenantCache(f.ctx(), g, originalCacheLease(f), int(root.Fd())); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(cachePath); !os.IsNotExist(err) {
		t.Fatal("original cache not removed", err)
	}
	if data, err := os.ReadFile(outside); err != nil || string(data) != "preserve" {
		t.Fatal("confined deletion followed an external symlink", err)
	}
	hold, _, err := f.jobs.RootHold(f.spec, CacheRoot)
	if err != nil || !hold.Returning || hold.Returned || hold.Lease != originalCacheLease(f) {
		t.Fatal("unlink fabricated root Return acknowledgement", hold, err)
	}
	activity, err := f.jobs.TenantActivity(f.spec.Tenant)
	if err != nil || activity.Leases != 1 || activity.Resources != 0 {
		t.Fatal("unacknowledged root return vanished", activity, err)
	}
	wrong := g
	wrong.Operation = "another-retirement"
	if err := f.jobs.FinishCacheRetirement(wrong); !errors.Is(err, ErrConflict) {
		t.Fatal("foreign retirement finalized original", err)
	}
	// This call models the separate RootManager acknowledgement, not an
	// actual root return performed by this native-only fixture.
	if err := f.jobs.FinishCacheRetirement(g); err != nil {
		t.Fatal(err)
	}
	f.reopen()
	if err := f.jobs.RetireTenantCache(f.ctx(), g, originalCacheLease(f), -1); err != nil {
		t.Fatal("closed original tried to reopen/recreate files", err)
	}
	activity, err = f.jobs.TenantActivity(f.spec.Tenant)
	if err != nil || !activity.Empty() {
		t.Fatal("settled original still active", activity, err)
	}
	if _, err := f.jobs.cacheBorrow(f.spec, f.plan, true); !errors.Is(err, ErrUsed) {
		t.Fatal("old job recreated a retired tenant cache", err)
	}
	if summary, err := f.jobs.ReadCacheSummary(f.spec); err != nil || !summary.Recorded || summary.Allocated || summary.Available || summary.Borrowed {
		t.Fatal("retired cache became an observed empty cache", summary, err)
	}
	if record, err := f.jobs.Record(f.spec); err != nil || record.Completion == nil || !record.Completion.Valid(f.spec) {
		t.Fatal("cache disposal changed original job closure", err)
	}
}

type cacheRetirementFailStore struct {
	Transactions
	stage string
	cache [32]byte
}

func (s *cacheRetirementFailStore) Update(edit func(*bolt.Tx) error) error {
	return s.Transactions.Update(func(tx *bolt.Tx) error {
		if err := edit(tx); err != nil {
			return err
		}
		var cache nativeCacheBorrow
		if json.Unmarshal(tx.Bucket(nativeBucket).Get(nativeCacheKey(s.cache)), &cache) != nil {
			return ErrStorage
		}
		if cache.Retirement != nil && (s.stage == "intent" && !cache.Retirement.Unlinked || s.stage == "unlink" && cache.Retirement.Unlinked && !cache.RootHold.Returned || s.stage == "return" && cache.RootHold.Returned) {
			return errors.New("injected cache retirement commit failure")
		}
		return nil
	})
}

func TestTenantCacheRetirementResumesOriginalIntentAcrossEveryCommitBoundary(t *testing.T) {
	for _, stage := range []string{"intent", "unlink", "return"} {
		t.Run(stage, func(t *testing.T) {
			f, g := closedTenantCacheFixture(t)
			root := nativeTestRoot(t, f.spec)
			cachePath := nativeWorkspacePaths(f.spec, f.plan)[2]
			rollback := &cacheRetirementFailStore{Transactions: f.db, stage: stage, cache: f.plan.Cache}
			f.jobs.db = rollback
			err := f.jobs.RetireTenantCache(f.ctx(), g, originalCacheLease(f), int(root.Fd()))
			if stage == "return" {
				if err != nil {
					t.Fatal(err)
				}
				err = f.jobs.FinishCacheRetirement(g)
			}
			if err == nil {
				t.Fatal("injected failure lost", stage)
			}
			_, pathErr := os.Stat(cachePath)
			if stage == "intent" && pathErr != nil || stage != "intent" && !os.IsNotExist(pathErr) {
				t.Fatal("wrong physical effect boundary", stage, pathErr)
			}
			hold, _, err := f.jobs.RootHold(f.spec, CacheRoot)
			if err != nil || hold.Returned || hold.Lease != originalCacheLease(f) {
				t.Fatal("failed commit released/replaced original root", hold, err)
			}
			f.reopen()
			if err := f.jobs.RetireTenantCache(f.ctx(), g, originalCacheLease(f), int(root.Fd())); err != nil {
				t.Fatal("original could not resume after commit loss", stage, err)
			}
			if err := f.jobs.FinishCacheRetirement(g); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(cachePath); !os.IsNotExist(err) {
				t.Fatal("resume recreated cache", err)
			}
		})
	}
}

func TestTenantCacheRetirementRejectsIOAheadStateWrongLeaseAndReplacedOrMissingFiles(t *testing.T) {
	for _, cause := range []string{"reader", "log-writer", "ahead", "lease", "root", "replacement", "missing"} {
		t.Run(cause, func(t *testing.T) {
			f, g := closedTenantCacheFixture(t)
			root := nativeTestRoot(t, f.spec)
			fd, lease := int(root.Fd()), originalCacheLease(f)
			cachePath := nativeWorkspacePaths(f.spec, f.plan)[2]
			switch cause {
			case "reader":
				f.jobs.readers[f.spec.Digest()] = 1
			case "log-writer":
				f.jobs.logWriters[f.spec.Digest()] = true
			case "ahead":
				g.Index = 1
			case "lease":
				lease.Token++
			case "root":
				foreign, err := os.Open(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				defer foreign.Close()
				fd = int(foreign.Fd())
			case "replacement":
				if err := os.Rename(cachePath, cachePath+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(cachePath, 0700); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err := os.Remove(cachePath); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.jobs.RetireTenantCache(f.ctx(), g, lease, fd); err == nil {
				t.Fatal("unsafe retirement accepted", cause)
			}
			if err := f.db.View(func(tx *bolt.Tx) error {
				cache, err := readNativeCache(tx, f.spec, f.plan)
				if err != nil || cache.Retirement != nil || cache.RootHold.Returning {
					t.Fatal("refusal changed original delete/return intent", cache, err)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
