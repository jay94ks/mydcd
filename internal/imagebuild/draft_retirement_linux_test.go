// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/jay94ks/seafield/internal/reconcile"
	bolt "go.etcd.io/bbolt"
)

func draftRetirementFixture(t *testing.T) (*DraftStore, *Spool, DraftRetirementGrant, reconcile.Lease) {
	t.Helper()
	store, spool := draftStoreFixture(t)
	if _, err := store.Edit(context.Background(), draftFileEdit("original", "payload", "original bytes", 1), bytes.NewBufferString("original bytes")); err != nil {
		t.Fatal(err)
	}
	g := DraftRetirementGrant{Scope: store.scope, ContextRevision: store.scope.ContextRevision + 1, Generation: store.scope.Data().Generation, Deleted: true, Index: 20, Epoch: 1}
	return store, spool, g, reconcile.Lease{Generation: store.scope.Root.Generation, Token: 7}
}

// Native files/DB are real. Shared deletion/generation authority and the root
// lease are injected; the real FSM and RootManager adapter are separate tests.
func TestDraftLifetimeRetirementKeepsMetadataNewLifetimeAndOriginalConsumer(t *testing.T) {
	store, spool, grant, lease := draftRetirementFixture(t)
	ctx := context.Background()
	if err := spool.RetireDraft(ctx, grant, lease); !errors.Is(err, ErrUsed) {
		t.Fatal("live store was retired", err)
	}
	var stateBefore, editBefore []byte
	if err := spool.db.View(func(tx *bolt.Tx) error {
		stateBefore = bytes.Clone(store.bucket(tx).Get([]byte("state")))
		editBefore = bytes.Clone(store.bucket(tx).Get([]byte("edit-original")))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if len(stateBefore) == 0 || len(editBefore) == 0 {
		t.Fatal("original state/edit evidence missing before retirement")
	}
	newScope := grant.Scope
	newScope.ContextRevision += 2
	newScope.Generation = newScope.ContextRevision
	next, err := OpenDraftStore(spool, newScope, true)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if _, err := next.Edit(ctx, draftFileEdit("new", "keep", "new bytes", 1), bytes.NewBufferString("new bytes")); err != nil {
		t.Fatal(err)
	}
	if err := spool.RetireDraft(ctx, grant, lease); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(grant.Scope.Root.Path, ".sfc-imagebuild", string(store.key))
	if _, err := os.Stat(name); !os.IsNotExist(err) {
		t.Fatal("old private namespace not removed", err)
	}
	if _, err := OpenDraftStore(spool, grant.Scope, true); !errors.Is(err, ErrUsed) {
		t.Fatal("old data lifetime recreated", err)
	}
	if draft, err := next.Read(); err != nil || draft.Revision != 2 || len(draft.Entries) != 1 || draft.Entries[0].Path != "keep" {
		t.Fatal("new lifetime changed", draft, err)
	}
	if err := spool.db.View(func(tx *bolt.Tx) error {
		if !bytes.Equal(store.bucket(tx).Get([]byte("state")), stateBefore) || !bytes.Equal(store.bucket(tx).Get([]byte("edit-original")), editBefore) {
			t.Fatal("original state/edit evidence removed or rewritten")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	owners, err := StoredInputRootOwners(spool.db, grant.Scope.Root)
	owner := owners[DraftRootConsumer(grant.Scope)]
	if err != nil || owner.Required || !owner.Pending {
		t.Fatal("unsettled Return acknowledgement lost", owner, err)
	}
	selected, err := StoredDraftLifetimes(spool.db, grant.Scope.Root, grant.Scope.Tenant, grant.Scope.Context, func(scope DraftScope, original *DraftRetirement) (bool, error) {
		if scope == grant.Scope && (original == nil || !original.Removed || original.Root.Returned) {
			t.Fatal("discovery lost original pending retirement", original)
		}
		return true, nil
	}, 16)
	if err != nil || len(selected) != 2 {
		t.Fatal("discovery omitted old/new independent lifetime", selected, err)
	}
	wrong := lease
	wrong.Token++
	if err := FinishDraftRetirement(spool.db, grant.Scope, wrong); err == nil {
		t.Fatal("replacement lease finalized old lifetime")
	}
	if err := FinishDraftRetirement(spool.db, grant.Scope, lease); err != nil {
		t.Fatal(err)
	}
	owners, err = StoredInputRootOwners(spool.db, grant.Scope.Root)
	if owner := owners[DraftRootConsumer(grant.Scope)]; err != nil || owner.Required || owner.Pending {
		t.Fatal("original settlement still pending", owner, err)
	}
	selected, err = StoredDraftLifetimes(spool.db, grant.Scope.Root, grant.Scope.Tenant, grant.Scope.Context, func(DraftScope, *DraftRetirement) (bool, error) { return true, nil }, 16)
	if err != nil || len(selected) != 1 || selected[0] != newScope {
		t.Fatal("discovery revisited returned data or hid current data", selected, err)
	}
}

func TestDraftLifetimeRetirementKeepsAdoptedSiblingArchive(t *testing.T) {
	store, spool, plan := frozenDraftFixture(t)
	ctx := context.Background()
	if _, err := store.PrepareFreeze(ctx, plan); err != nil {
		t.Fatal(err)
	}
	_, key := testScope(1, [32]byte{1})
	frozen, err := store.AdoptFreeze(ctx, plan, key)
	if err != nil {
		t.Fatal(err)
	}
	grant := DraftRetirementGrant{Scope: store.scope, ContextRevision: store.scope.ContextRevision + 1, Generation: store.scope.Data().Generation, Deleted: true, Index: 20, Epoch: 1}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := spool.RetireDraft(ctx, grant, reconcile.Lease{Generation: store.scope.Root.Generation, Token: 7}); err != nil {
		t.Fatal(err)
	}
	reader, err := spool.Open(ctx, frozen.Scope, frozen.Fact)
	if err != nil {
		t.Fatal("adopted archive lost with draft directory", err)
	}
	n, readErr := io.Copy(io.Discard, reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || n != frozen.Scope.Length {
		t.Fatal(n, readErr, closeErr)
	}
	owners, err := StoredInputRootOwners(spool.db, grant.Scope.Root)
	if err != nil || !owners[ArtifactRootConsumer(frozen.Scope)].Required {
		t.Fatal("independent archive dependency lost", owners, err)
	}
}

func TestDraftLifetimeRetirementPreservesPreparedArchiveUntilIndependentSettlement(t *testing.T) {
	store, spool, plan := frozenDraftFixture(t)
	ctx := context.Background()
	if _, err := store.PrepareFreeze(ctx, plan); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	g := DraftRetirementGrant{Scope: store.scope, ContextRevision: store.scope.ContextRevision + 1, Generation: store.scope.Data().Generation, Deleted: true, Index: 20, Epoch: 1}
	if err := spool.RetireDraft(ctx, g, reconcile.Lease{Generation: store.scope.Root.Generation, Token: 7}); !errors.Is(err, ErrUsed) {
		t.Fatal("prepared source deleted before its archive settlement", err)
	}
	name := filepath.Join(g.Scope.Root.Path, ".sfc-imagebuild", string(store.key), freezeName(plan))
	if info, err := os.Stat(name); err != nil || info.Size() == 0 {
		t.Fatal("prepared original source lost", info, err)
	}
	if _, started, err := DraftRetirementState(spool.db, g.Scope); err != nil || started {
		t.Fatal("blocked archive created whole-directory delete intent", started, err)
	}
}

func TestDraftLifetimeRetirementResumesOriginalAcrossEveryCommitBoundary(t *testing.T) {
	for _, failAt := range []int{1, 2, 3} {
		t.Run(map[int]string{1: "intent", 2: "unlink", 3: "return"}[failAt], func(t *testing.T) {
			store, spool, grant, lease := draftRetirementFixture(t)
			name := filepath.Join(grant.Scope.Root.Path, ".sfc-imagebuild", string(store.key))
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			original := spool.db
			spool.db = &draftGCFailureDB{Transactions: original, failAt: failAt}
			err := spool.RetireDraft(context.Background(), grant, lease)
			if failAt == 3 {
				if err != nil {
					t.Fatal(err)
				}
				err = FinishDraftRetirement(spool.db, grant.Scope, lease)
			}
			if !errors.Is(err, errDraftGCCommit) {
				t.Fatal("expected failure boundary missing", err)
			}
			_, pathErr := os.Stat(name)
			if failAt == 1 && pathErr != nil || failAt != 1 && !os.IsNotExist(pathErr) {
				t.Fatal("wrong unlink boundary", pathErr)
			}
			spool.db = original
			if err := spool.RetireDraft(context.Background(), grant, lease); err != nil {
				t.Fatal("original intent could not resume", err)
			}
			if err := FinishDraftRetirement(spool.db, grant.Scope, lease); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenDraftStore(spool, grant.Scope, true); !errors.Is(err, ErrUsed) {
				t.Fatal("settlement recreated original data", err)
			}
		})
	}
}

func TestDraftLifetimeRetirementRejectsCurrentFutureOrReplacedData(t *testing.T) {
	for _, cause := range []string{"current", "generation", "missing", "replacement"} {
		t.Run(cause, func(t *testing.T) {
			store, spool, grant, lease := draftRetirementFixture(t)
			name := filepath.Join(grant.Scope.Root.Path, ".sfc-imagebuild", string(store.key))
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			switch cause {
			case "current":
				grant.Deleted = false
			case "generation":
				grant.Generation = grant.Scope.Data().Generation - 1
			case "missing":
				if err := os.RemoveAll(name); err != nil {
					t.Fatal(err)
				}
			case "replacement":
				if err := os.Rename(name, name+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(name, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := spool.RetireDraft(context.Background(), grant, lease); err == nil {
				t.Fatal("unsafe data retirement accepted", cause)
			}
			if _, started, err := DraftRetirementState(spool.db, store.scope); err != nil || started {
				t.Fatal("refusal changed original retirement intent", started, err)
			}
		})
	}
}
