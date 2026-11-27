// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jay94ks/seafield/internal/reconcile"
	bolt "go.etcd.io/bbolt"
)

func unusedDraftFile(t *testing.T) (*DraftStore, *Spool, DraftEdit, DraftEditResult) {
	t.Helper()
	store, spool := draftStoreFixture(t)
	edit := draftFileEdit("original", "payload", "original body", 1)
	result, err := store.Edit(context.Background(), edit, bytes.NewBufferString("original body"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Edit(context.Background(), DraftEdit{ID: "remove", Kind: "delete", Path: edit.Path, Expected: result.Revision}, nil); err != nil {
		t.Fatal(err)
	}
	return store, spool, edit, result
}

func TestDraftCollectionRemovesOnlyUnusedBodiesAndKeepsOriginalEditResults(t *testing.T) {
	store, _, edit, result := unusedDraftFile(t)
	if n, err := store.CollectUnused(context.Background(), 16); err != nil || n != 1 {
		t.Fatal("unused original not collected", n, err)
	}
	name := filepath.Join(store.scope.Root.Path, ".sfc-imagebuild", string(store.key), string(draftBlobKey(edit.File.Digest)))
	if _, err := os.Stat(name); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("body retained", err)
	}
	if got, err := store.Edit(context.Background(), edit, nil); err != nil || got != result {
		t.Fatal("GC changed original edit result", got, err)
	}
	if got, err := store.CommitFile(context.Background(), edit); err != nil || got != result {
		t.Fatal("completed seal recreated source", got, err)
	}
	if _, err := store.StageFilePart(context.Background(), edit, 0, []byte("original body")); err == nil {
		t.Fatal("old completed edit recreated collected body")
	}
	if _, err := os.Stat(name); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("original edit retry allocated new inode", err)
	}
	newEdit := draftFileEdit("new-explicit-edit", "restored", "original body", 3)
	if _, err := store.Edit(context.Background(), newEdit, bytes.NewBufferString("original body")); err != nil {
		t.Fatal("new explicit edit could not reuse same content", err)
	}
	if n, err := store.CollectUnused(context.Background(), 16); err != nil || n != 0 {
		t.Fatal("new live content collected", n, err)
	}
}

func TestDraftCollectionKeepsSharedContentUntilEveryPathIsRemoved(t *testing.T) {
	store, _ := draftStoreFixture(t)
	ctx := context.Background()
	for i, name := range []string{"first", "second"} {
		if _, err := store.Edit(ctx, draftFileEdit(name, name, "shared", uint64(i+1)), bytes.NewBufferString("shared")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.Edit(ctx, DraftEdit{ID: "remove-first", Kind: "delete", Path: "first", Expected: 3}, nil); err != nil {
		t.Fatal(err)
	}
	if n, err := store.CollectUnused(ctx, 16); err != nil || n != 0 {
		t.Fatal("another path's shared body collected", n, err)
	}
	if _, err := store.Edit(ctx, DraftEdit{ID: "remove-second", Kind: "delete", Path: "second", Expected: 4}, nil); err != nil {
		t.Fatal(err)
	}
	if n, err := store.CollectUnused(ctx, 16); err != nil || n != 1 {
		t.Fatal("last reference removal did not free body", n, err)
	}
}

func TestDraftCollectionProtectsPendingMultipartWhileCollectingOtherBodies(t *testing.T) {
	store, _, _, _ := unusedDraftFile(t)
	ctx := context.Background()
	edit := draftFileEdit("pending", "next", "staged input", 3)
	if _, err := store.StageFilePart(ctx, edit, 0, []byte("staged input")); err != nil {
		t.Fatal(err)
	}
	if n, err := store.CollectUnused(ctx, 16); err != nil || n != 1 {
		t.Fatal("pending input blocked unrelated garbage or was collected", n, err)
	}
	if _, err := store.CommitFile(ctx, edit); err != nil {
		t.Fatal("pending original could not commit after GC", err)
	}
	if _, err := store.Edit(ctx, DraftEdit{ID: "remove-next", Kind: "delete", Path: edit.Path, Expected: 4}, nil); err != nil {
		t.Fatal(err)
	}
	if n, err := store.CollectUnused(ctx, 16); err != nil || n != 1 {
		t.Fatal("completed multipart body not reclaimed", n, err)
	}
	if err := store.spool.db.View(func(tx *bolt.Tx) error {
		prefix := append(draftBlobKey(edit.File.Digest), '/')
		key, _ := store.bucket(tx).Cursor().Seek(prefix)
		if bytes.HasPrefix(key, prefix) {
			return ErrStorage
		}
		return nil
	}); err != nil {
		t.Fatal("collected file's part slots remain", err)
	}
}

func TestDraftCollectionRetainsBodiesWhenLegacyPendingFileIsUnknown(t *testing.T) {
	store, spool, _, _ := unusedDraftFile(t)
	if err := spool.db.Update(func(tx *bolt.Tx) error {
		raw, _ := json.Marshal(draftEditRecord{Edit: [32]byte{7}})
		return store.bucket(tx).Put([]byte("edit-legacy-pending"), raw)
	}); err != nil {
		t.Fatal(err)
	}
	if n, err := store.CollectUnused(context.Background(), 16); err != nil || n != 0 {
		t.Fatal("unknown legacy pending source reclaimed", n, err)
	}
}

func TestDraftCollectionProtectsPartialFreezeAndKeepsCompletedArchiveIndependent(t *testing.T) {
	for _, partial := range []bool{false, true} {
		t.Run(map[bool]string{false: "completed", true: "partial"}[partial], func(t *testing.T) {
			store, _, plan := frozenDraftFixture(t)
			ctx := context.Background()
			if partial {
				if err := store.saveFreeze(nativeDraftFreeze{Plan: plan}); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := store.PrepareFreeze(ctx, plan); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := store.Edit(ctx, DraftEdit{ID: "remove", Kind: "delete", Path: "Dockerfile", Expected: plan.Revision}, nil); err != nil {
				t.Fatal(err)
			}
			want := 1
			if partial {
				want = 0
			}
			if n, err := store.CollectUnused(ctx, 16); err != nil || n != want {
				t.Fatal("freeze/body ownership boundary", n, err)
			}
			if !partial {
				_, key := testScope(1, [32]byte{1})
				if frozen, err := store.AdoptFreeze(ctx, plan, key); err != nil || !frozen.Valid() {
					t.Fatal("independent original archive altered by body GC", err)
				}
			}
		})
	}
}

type draftGCFailureDB struct {
	Transactions
	calls, failAt int
}

var errDraftGCCommit = errors.New("injected draft GC completion commit failure")

func (d *draftGCFailureDB) Update(fn func(*bolt.Tx) error) error {
	d.calls++
	return d.Transactions.Update(func(tx *bolt.Tx) error {
		if err := fn(tx); err != nil {
			return err
		}
		if d.calls == d.failAt {
			return errDraftGCCommit
		}
		return nil
	})
}

func TestDraftCollectionReopensOriginalUnlinkIntentAfterCommitLoss(t *testing.T) {
	store, spool, edit, _ := unusedDraftFile(t)
	ctx := context.Background()
	spool.db = &draftGCFailureDB{Transactions: spool.db, failAt: 2}
	if n, err := store.CollectUnused(ctx, 16); !errors.Is(err, errDraftGCCommit) || n != 0 {
		t.Fatal("completion failure hidden", n, err)
	}
	name := filepath.Join(store.scope.Root.Path, ".sfc-imagebuild", string(store.key), string(draftBlobKey(edit.File.Digest)))
	if _, err := os.Stat(name); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failure was not after actual unlink", err)
	}
	newEdit := draftFileEdit("new-during-gc", "restored", "original body", 3)
	if _, err := store.Edit(ctx, newEdit, bytes.NewBufferString("original body")); !errors.Is(err, reconcile.ErrPending) {
		t.Fatal("new edit pinned an unsettled missing body", err)
	}
	if _, err := store.StageFilePart(ctx, newEdit, 0, []byte("original body")); !errors.Is(err, reconcile.ErrPending) {
		t.Fatal("multipart input pinned an unsettled missing body", err)
	}
	if err := spool.db.View(func(tx *bolt.Tx) error {
		if store.bucket(tx).Get([]byte("edit-"+newEdit.ID)) != nil {
			return ErrStorage
		}
		return nil
	}); err != nil {
		t.Fatal("blocked edit left a reference preventing GC recovery", err)
	}
	scope := store.scope
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := OpenDraftStore(spool, scope, false)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if n, err := store.CollectUnused(ctx, 16); err != nil || n != 1 {
		t.Fatal("original unlink intent could not settle after reopen", n, err)
	}
	if n, err := store.CollectUnused(ctx, 16); err != nil || n != 0 {
		t.Fatal("settled body counted twice", n, err)
	}
	if _, err := store.Edit(ctx, newEdit, bytes.NewBufferString("original body")); err != nil {
		t.Fatal("same explicit edit did not proceed after original GC settled", err)
	}
}

func TestDraftCollectionRejectsMissingOrReplacedOriginalBeforeIntent(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing", true: "replaced"}[replace], func(t *testing.T) {
			store, spool, edit, _ := unusedDraftFile(t)
			name := filepath.Join(store.scope.Root.Path, ".sfc-imagebuild", string(store.key), string(draftBlobKey(edit.File.Digest)))
			if err := os.Rename(name, name+"-original"); err != nil {
				t.Fatal(err)
			}
			if replace {
				if err := os.WriteFile(name, []byte("original body"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if n, err := store.CollectUnused(context.Background(), 16); err == nil || n != 0 {
				t.Fatal("unknown absence/replacement treated as GC success", n, err)
			}
			if err := spool.db.View(func(tx *bolt.Tx) error {
				b := store.bucket(tx)
				if b.Get(draftBlobKey(edit.File.Digest)) == nil || b.Get(append([]byte("gc-"), draftBlobKey(edit.File.Digest)...)) != nil {
					return ErrStorage
				}
				return nil
			}); err != nil {
				t.Fatal("GC erased original evidence or fabricated unlink intent", err)
			}
		})
	}
}

func stagePartialDraftGCFile(t *testing.T, store *DraftStore, kind string) (DraftEdit, []byte) {
	t.Helper()
	ctx := context.Background()
	data := bytes.Repeat([]byte{29}, PartBytes+17)
	edit := draftFileEdit("interrupted", "payload", string(data), 1)
	switch kind {
	case "inline-short":
		if _, err := store.Edit(ctx, edit, bytes.NewReader(data[:7])); !errors.Is(err, ErrDigest) {
			t.Fatal("interrupted inline write not retained", err)
		}
	case "multipart-short":
		if _, err := store.StageFilePart(ctx, edit, 0, data[:PartBytes]); err != nil {
			t.Fatal(err)
		}
	case "multipart-sparse":
		if _, err := store.StageFilePart(ctx, edit, 1, data[PartBytes:]); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("unknown partial fixture", kind)
	}
	return edit, data
}

func TestDraftCollectionReclaimsSupersededPartialEditsWithoutChangingOriginalIntent(t *testing.T) {
	for _, kind := range []string{"inline-short", "multipart-short", "multipart-sparse"} {
		t.Run(kind, func(t *testing.T) {
			store, spool := draftStoreFixture(t)
			ctx := context.Background()
			edit, data := stagePartialDraftGCFile(t, store, kind)
			if n, err := store.CollectUnused(ctx, 16); err != nil || n != 0 {
				t.Fatal("still-current partial input collected", n, err)
			}
			if _, err := store.Edit(ctx, DraftEdit{ID: "advance", Kind: "mkdir", Path: "other", Expected: 1}, nil); err != nil {
				t.Fatal(err)
			}
			var original []byte
			if err := spool.db.View(func(tx *bolt.Tx) error {
				original = bytes.Clone(store.bucket(tx).Get([]byte("edit-" + edit.ID)))
				if len(original) == 0 {
					return ErrStorage
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if n, err := store.CollectUnused(ctx, 16); err != nil || n != 1 {
				t.Fatal("superseded original partial not collected", n, err)
			}
			name := filepath.Join(store.scope.Root.Path, ".sfc-imagebuild", string(store.key), string(draftBlobKey(edit.File.Digest)))
			if _, err := os.Stat(name); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("partial body remains", err)
			}
			if err := spool.db.View(func(tx *bolt.Tx) error {
				b := store.bucket(tx)
				var expected draftEditRecord
				if json.Unmarshal(original, &expected) != nil {
					return ErrStorage
				}
				expected.Abandoned = true
				raw, _ := json.Marshal(expected)
				if !bytes.Equal(raw, b.Get([]byte("edit-"+edit.ID))) || b.Get(draftBlobKey(edit.File.Digest)) != nil {
					return ErrStorage
				}
				prefix := append(draftBlobKey(edit.File.Digest), '/')
				key, _ := b.Cursor().Seek(prefix)
				if bytes.HasPrefix(key, prefix) {
					return ErrStorage
				}
				return nil
			}); err != nil {
				t.Fatal("partial collection changed original intent or retained slots", err)
			}
			if _, err := store.StageFilePart(ctx, edit, 0, data[:PartBytes]); !errors.Is(err, ErrConflict) {
				t.Fatal("stale original allocated new bytes", err)
			}
			if _, err := store.FileStatus(ctx, edit, 0); !errors.Is(err, ErrConflict) {
				t.Fatal("stale original pretended resumable", err)
			}
			if _, err := store.CommitFile(ctx, edit); !errors.Is(err, ErrConflict) {
				t.Fatal("stale original committed after collection", err)
			}
			if _, err := store.Edit(ctx, edit, bytes.NewReader(data)); !errors.Is(err, ErrConflict) {
				t.Fatal("inline stale original re-created collected body", err)
			}
			if _, err := os.Stat(name); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("rejected original retry touched source", err)
			}
			fresh := edit
			fresh.ID, fresh.Expected = "explicit-new", 2
			for _, index := range []uint32{1, 0} {
				start := int(index) * PartBytes
				if _, err := store.StageFilePart(ctx, fresh, index, data[start:start+DraftFilePartLength(fresh, index)]); err != nil {
					t.Fatal("new explicit edit could not upload collected content", err)
				}
			}
			if result, err := store.CommitFile(ctx, fresh); err != nil || result.Revision != 3 {
				t.Fatal("new explicit edit could not commit", result, err)
			}
			if n, err := store.CollectUnused(ctx, 16); err != nil || n != 0 {
				t.Fatal("new live source collected", n, err)
			}
		})
	}
}

func TestDraftCollectionKeepsPartialBodySharedWithCurrentPendingEdit(t *testing.T) {
	store, _ := draftStoreFixture(t)
	ctx := context.Background()
	edit, data := stagePartialDraftGCFile(t, store, "multipart-short")
	if _, err := store.Edit(ctx, DraftEdit{ID: "advance", Kind: "mkdir", Path: "other", Expected: 1}, nil); err != nil {
		t.Fatal(err)
	}
	active := edit
	active.ID, active.Expected = "active-shared", 2
	if _, err := store.StageFilePart(ctx, active, 0, data[:PartBytes]); err != nil {
		t.Fatal(err)
	}
	if n, err := store.CollectUnused(ctx, 16); err != nil || n != 0 {
		t.Fatal("stale intent erased another edit's active input", n, err)
	}
	if _, err := store.StageFilePart(ctx, active, 1, data[PartBytes:]); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitFile(ctx, active); err != nil {
		t.Fatal("shared original could not commit", err)
	}
}

func TestDraftPartialCollectionResumesUnlinkIntentAndBlocksNewReferences(t *testing.T) {
	store, spool := draftStoreFixture(t)
	ctx := context.Background()
	edit, data := stagePartialDraftGCFile(t, store, "multipart-short")
	if _, err := store.Edit(ctx, DraftEdit{ID: "advance", Kind: "mkdir", Path: "other", Expected: 1}, nil); err != nil {
		t.Fatal(err)
	}
	spool.db = &draftGCFailureDB{Transactions: spool.db, failAt: 2}
	if n, err := store.CollectUnused(ctx, 16); !errors.Is(err, errDraftGCCommit) || n != 0 {
		t.Fatal("unlink completion loss hidden", n, err)
	}
	active := edit
	active.ID, active.Expected = "new-during-partial-gc", 2
	if _, err := store.StageFilePart(ctx, active, 0, data[:PartBytes]); !errors.Is(err, reconcile.ErrPending) {
		t.Fatal("new pending edit blocked original collection recovery", err)
	}
	scope := store.scope
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := OpenDraftStore(spool, scope, false)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if n, err := store.CollectUnused(ctx, 16); err != nil || n != 1 {
		t.Fatal("original partial unlink could not settle", n, err)
	}
	if _, err := store.StageFilePart(ctx, edit, 0, data[:PartBytes]); !errors.Is(err, ErrConflict) {
		t.Fatal("superseded original became resumable after reopen", err)
	}
	if _, err := store.StageFilePart(ctx, active, 0, data[:PartBytes]); err != nil {
		t.Fatal("explicit new edit stayed blocked after collection", err)
	}
}

func TestDraftPartialCollectionIntentFailureDoesNotAbandonOriginal(t *testing.T) {
	store, spool := draftStoreFixture(t)
	ctx := context.Background()
	edit, data := stagePartialDraftGCFile(t, store, "multipart-short")
	if _, err := store.Edit(ctx, DraftEdit{ID: "advance", Kind: "mkdir", Path: "other", Expected: 1}, nil); err != nil {
		t.Fatal(err)
	}
	spool.db = &draftGCFailureDB{Transactions: spool.db, failAt: 1}
	if n, err := store.CollectUnused(ctx, 16); !errors.Is(err, errDraftGCCommit) || n != 0 {
		t.Fatal("intent transaction failure hidden", n, err)
	}
	if _, err := store.StageFilePart(ctx, edit, 1, data[PartBytes:]); err != nil {
		t.Fatal("rolled-back collection abandoned original input", err)
	}
	if _, err := store.CommitFile(ctx, edit); !errors.Is(err, ErrConflict) {
		t.Fatal("old CAS changed after rolled-back collection", err)
	}
	if n, err := store.CollectUnused(ctx, 16); err != nil || n != 1 {
		t.Fatal("unstarted collection could not proceed", n, err)
	}
}

func TestDraftPartialCollectionRequiresRecordedOriginalInode(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing", true: "replaced"}[replace], func(t *testing.T) {
			store, spool := draftStoreFixture(t)
			ctx := context.Background()
			edit, data := stagePartialDraftGCFile(t, store, "multipart-short")
			if _, err := store.Edit(ctx, DraftEdit{ID: "advance", Kind: "mkdir", Path: "other", Expected: 1}, nil); err != nil {
				t.Fatal(err)
			}
			name := filepath.Join(store.scope.Root.Path, ".sfc-imagebuild", string(store.key), string(draftBlobKey(edit.File.Digest)))
			if err := os.Rename(name, name+"-original"); err != nil {
				t.Fatal(err)
			}
			if replace {
				if err := os.WriteFile(name, data[:PartBytes], 0600); err != nil {
					t.Fatal(err)
				}
			}
			if n, err := store.CollectUnused(ctx, 16); err == nil || n != 0 {
				t.Fatal("unproven partial identity collected", n, err)
			}
			if err := spool.db.View(func(tx *bolt.Tx) error {
				b := store.bucket(tx)
				var original draftEditRecord
				if json.Unmarshal(b.Get([]byte("edit-"+edit.ID)), &original) != nil || original.Abandoned || b.Get(draftBlobGCKey(edit.File.Digest)) != nil || b.Get(draftBlobKey(edit.File.Digest)) == nil {
					return ErrStorage
				}
				return nil
			}); err != nil {
				t.Fatal("unproven partial absence changed original evidence", err)
			}
		})
	}
}
