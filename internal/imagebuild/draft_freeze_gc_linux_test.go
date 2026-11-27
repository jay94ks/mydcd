// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/sys/unix"
)

// Original partial ZIP/inode and source authority are injected, as in the
// existing interrupted-freeze fixture. Native files and bbolt are real.
func unpreparedFreezeFixture(t *testing.T) (*DraftStore, *Spool, DraftFreezePlan, string) {
	t.Helper()
	store, spool, plan := frozenDraftFixture(t)
	name := filepath.Join(plan.Scope.Root.Path, ".sfc-imagebuild", string(store.key), freezeName(plan))
	if err := os.WriteFile(name, []byte("partial ZIP"), 0600); err != nil {
		t.Fatal(err)
	}
	var stat unix.Stat_t
	if err := unix.Fstatat(int(store.dir.Fd()), freezeName(plan), &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		t.Fatal(err)
	}
	if err := store.saveFreeze(nativeDraftFreeze{Plan: plan, Device: uint64(stat.Dev), Inode: stat.Ino}); err != nil {
		t.Fatal(err)
	}
	return store, spool, plan, name
}

func obsoleteFreezeFixture(DraftFreezePlan) (bool, error) { return true, nil }

func TestObsoleteUnpreparedFreezeCollectionUnblocksUnusedBodiesWithoutReusingOriginal(t *testing.T) {
	store, _, plan, name := unpreparedFreezeFixture(t)
	ctx := context.Background()
	if n, err := store.CollectUnpreparedFreezes(ctx, func(DraftFreezePlan) (bool, error) { return false, nil }, 16); err != nil || n != 0 {
		t.Fatal("current freeze removed", n, err)
	}
	if _, err := store.Edit(ctx, DraftEdit{ID: "remove", Kind: "delete", Path: "Dockerfile", Expected: plan.Revision}, nil); err != nil {
		t.Fatal(err)
	}
	if n, err := store.CollectUnused(ctx, 16); err != nil || n != 0 {
		t.Fatal("unfinished freeze lost its input", n, err)
	}
	if n, err := store.CollectUnpreparedFreezes(ctx, obsoleteFreezeFixture, 16); err != nil || n != 1 {
		t.Fatal("obsolete partial not collected", n, err)
	}
	if _, err := os.Stat(name); !os.IsNotExist(err) {
		t.Fatal("partial bytes retained", err)
	}
	h, found, err := store.loadFreeze(plan)
	if err != nil || !found || !h.Removing || !h.Removed || h.Scope != nil || h.Plan != plan || h.Inode == 0 {
		t.Fatal("original tombstone lost", h, err)
	}
	if _, err := store.PrepareFreeze(ctx, plan); !errors.Is(err, ErrUsed) {
		t.Fatal("old freeze regenerated after collection", err)
	}
	if n, err := store.CollectUnused(ctx, 16); err != nil || n != 1 {
		t.Fatal("removed partial still retained unused input", n, err)
	}
	originalEdit := draftFileEdit("dockerfile", "Dockerfile", "FROM scratch\n", 1)
	if result, err := store.Edit(ctx, originalEdit, nil); err != nil || result.Revision != plan.Revision {
		t.Fatal("collection changed original edit result", result, err)
	}
}

func TestUnpreparedFreezeCollectionPreservesOriginalAcrossIntentAndUnlinkCommitLoss(t *testing.T) {
	for _, failAt := range []int{1, 2} {
		t.Run(map[int]string{1: "intent", 2: "completion"}[failAt], func(t *testing.T) {
			store, spool, plan, name := unpreparedFreezeFixture(t)
			original := spool.db
			spool.db = &draftGCFailureDB{Transactions: original, failAt: failAt}
			if n, err := store.CollectUnpreparedFreezes(context.Background(), obsoleteFreezeFixture, 16); !errors.Is(err, errDraftGCCommit) || n != 0 {
				t.Fatal("commit failure hidden", n, err)
			}
			_, pathErr := os.Stat(name)
			if failAt == 1 && pathErr != nil || failAt == 2 && !os.IsNotExist(pathErr) {
				t.Fatal("wrong physical failure boundary", pathErr)
			}
			spool.db = original
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			resumed, err := OpenDraftStore(spool, plan.Scope, false)
			if err != nil {
				t.Fatal(err)
			}
			defer resumed.Close()
			check := obsoleteFreezeFixture
			if failAt == 2 {
				check = func(DraftFreezePlan) (bool, error) {
					return false, errors.New("current authority is unavailable; original unlink already accepted")
				}
			}
			if n, err := resumed.CollectUnpreparedFreezes(context.Background(), check, 16); err != nil || n != 1 {
				t.Fatal("original intent did not resume", n, err)
			}
			if _, err := resumed.PrepareFreeze(context.Background(), plan); !errors.Is(err, ErrUsed) {
				t.Fatal("resumed collection allowed old regeneration", err)
			}
		})
	}
}

func TestUnpreparedFreezeCollectionKeepsPreparedArchiveAndRejectsForeignEvidence(t *testing.T) {
	for _, cause := range []string{"prepared", "replacement", "missing", "archive-header", "reader"} {
		t.Run(cause, func(t *testing.T) {
			store, spool, plan, name := unpreparedFreezeFixture(t)
			switch cause {
			case "prepared":
				// Prepare a separate complete original through the actual ZIP path.
				plan.ID = "prepared"
				if _, err := store.PrepareFreeze(context.Background(), plan); err != nil {
					t.Fatal(err)
				}
				name = filepath.Join(plan.Scope.Root.Path, ".sfc-imagebuild", string(store.key), freezeName(plan))
			case "replacement":
				if err := os.Rename(name, name+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(name, []byte("preserve replacement"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err := os.Remove(name); err != nil {
					t.Fatal(err)
				}
			case "archive-header":
				scope := plan.ArchiveScope(10, [32]byte{8})
				hash := plan.Digest()
				if err := spool.db.Update(func(tx *bolt.Tx) error {
					parent := store.parent(tx)
					bucket, err := parent.CreateBucket([]byte(scopeName(scope)))
					if err != nil {
						return err
					}
					raw, _ := json.Marshal(localUpload{Scope: scope, Generated: &hash})
					return bucket.Put(spoolHeader, raw)
				}); err != nil {
					t.Fatal(err)
				}
			case "reader":
				other, err := OpenDraftStore(spool, store.scope, false)
				if err != nil {
					t.Fatal(err)
				}
				defer other.Close()
			}
			n, err := store.CollectUnpreparedFreezes(context.Background(), func(candidate DraftFreezePlan) (bool, error) { return candidate.ID == plan.ID, nil }, 16)
			if cause == "prepared" {
				if err != nil || n != 0 {
					t.Fatal("prepared original collected", n, err)
				}
				if _, err := os.Stat(name); err != nil {
					t.Fatal("prepared bytes lost", err)
				}
			} else if err == nil || n != 0 {
				t.Fatal("foreign/missing evidence accepted", cause, n, err)
			}
			h, found, err := store.loadFreeze(plan)
			if err != nil || !found || h.Removing || h.Removed {
				t.Fatal("refusal changed source identity", h, err)
			}
		})
	}
}
