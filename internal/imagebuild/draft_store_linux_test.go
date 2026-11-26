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

	"github.com/jay94ks/mydcd/internal/reconcile"
	bolt "go.etcd.io/bbolt"
)

func draftStoreFixture(t *testing.T) (*DraftStore, *Spool) {
	return draftStoreFixtureLimit(t, 1<<20)
}

func draftStoreFixtureLimit(t *testing.T, expandedLimit int64) (*DraftStore, *Spool) {
	t.Helper()
	spool, upload, _, _ := openTestSpool(t, []byte{1})
	scope := draftScopeFixture()
	scope.Root = upload.Root
	scope.ExpandedLimit = expandedLimit
	store, err := OpenDraftStore(spool, scope, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, spool
}

func TestDraftStorePersistsEditsOriginalReceiptsAndFrozenZIP(t *testing.T) {
	store, spool := draftStoreFixture(t)
	ctx := context.Background()
	first := draftFileEdit("first", "Dockerfile", "FROM scratch\n", 1)
	result, err := store.Edit(ctx, first, bytes.NewBufferString("FROM scratch\n"))
	if err != nil || result.Revision != 2 {
		t.Fatal("native put", result, err)
	}
	second := draftFileEdit("second", "dir/payload", "native content", 2)
	if _, err := store.Edit(ctx, second, bytes.NewBufferString("native content")); err != nil {
		t.Fatal(err)
	}
	if err := spool.Close(); !errors.Is(err, ErrUsed) {
		t.Fatal("root could close before draft descriptor", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenDraftStore(spool, store.scope, false)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if got, err := store.Edit(ctx, first, nil); err != nil || got != result {
		t.Fatal("original result changed after later edits/reopen", got, err)
	}
	changed := first
	changed.Path, changed.File = second.Path, second.File
	if _, err := store.Edit(ctx, changed, nil); !errors.Is(err, ErrConflict) {
		t.Fatal("same original edit ID reused", err)
	}
	var raw bytes.Buffer
	draft, tree, err := store.Freeze(ctx, 3, &raw)
	if err != nil || draft.Revision != 3 || tree.Digest() == ([32]byte{}) {
		t.Fatal("native freeze", err)
	}
	actual, err := InspectZIP(ctx, bytes.NewReader(raw.Bytes()), int64(raw.Len()), "Dockerfile", draft.Scope.ExpandedLimit)
	if err != nil || actual.Digest() != tree.Digest() {
		t.Fatal("native bytes/tree mismatch", err)
	}
	if _, _, err := store.Freeze(ctx, 2, io.Discard); !errors.Is(err, ErrConflict) {
		t.Fatal("stale freeze revision accepted", err)
	}
}

func TestDraftStoreInterruptedPutRetainsOriginalAndNeverOverwrites(t *testing.T) {
	store, spool := draftStoreFixture(t)
	ctx := context.Background()
	edit := draftFileEdit("interrupted", "Dockerfile", "FROM scratch\n", 1)
	if _, err := store.Edit(ctx, edit, bytes.NewBufferString("FROM")); !errors.Is(err, ErrDigest) {
		t.Fatal("short upload accepted", err)
	}
	changed := draftFileEdit(edit.ID, "other", "replacement", 1)
	if _, err := store.Edit(ctx, changed, bytes.NewBufferString("replacement")); !errors.Is(err, ErrConflict) {
		t.Fatal("pending original ID replaced", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := OpenDraftStore(spool, store.scope, false)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.Edit(ctx, edit, bytes.NewBufferString("FROM scratch\n")); !errors.Is(err, reconcile.ErrPending) {
		t.Fatal("interrupted file rewritten", err)
	}
	draft, err := store.Read()
	if err != nil || draft.Revision != 1 || len(draft.Entries) != 0 {
		t.Fatal("incomplete file entered editable state", err)
	}
}

func TestDraftStoreMissingJournalAndReplacedBlobFailClosed(t *testing.T) {
	store, spool := draftStoreFixture(t)
	ctx := context.Background()
	edit := draftFileEdit("first", "Dockerfile", "FROM scratch\n", 1)
	if _, err := store.Edit(ctx, edit, bytes.NewBufferString("FROM scratch\n")); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(store.scope.Root.Path, ".mydc-imagebuild", string(store.key), string(draftBlobKey(edit.File.Digest)))
	if err := os.Rename(file, file+"-original"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("FROM scratch\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Freeze(ctx, 2, io.Discard); !errors.Is(err, ErrStorage) {
		t.Fatal("same bytes at a substituted inode accepted", err)
	}
	key := bytes.Clone(store.key)
	scope := store.scope
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := spool.db.Update(func(tx *bolt.Tx) error {
		return store.parent(tx).DeleteBucket(key)
	}); err != nil {
		t.Fatal(err)
	}
	if recovered, err := OpenDraftStore(spool, scope, true); err == nil {
		_ = recovered.Close()
		t.Fatal("missing original journal adopted a native directory")
	}
}

func TestDraftStoreAdoptsOnlyCompletedOriginalFileAndChecksScope(t *testing.T) {
	store, spool := draftStoreFixture(t)
	ctx := context.Background()
	edit := draftFileEdit("first", "Dockerfile", "FROM scratch\n", 1)
	// Simulate completion of the native file before the metadata edit commits.
	// The real Edit path consumes this same putFile implementation.
	spool.mu.Lock()
	err := store.putFile(ctx, *edit.File, bytes.NewBufferString("FROM scratch\n"))
	if err == nil {
		var blob draftBlob
		blob, err = store.blob(*edit.File)
		if err == nil {
			blob.Done = false
			err = store.saveBlob(blob)
		}
	}
	spool.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if result, err := store.Edit(ctx, edit, nil); err != nil || result.Revision != 2 {
		t.Fatal("complete original was not verified/adopted", result, err)
	}
	other := store.scope
	other.Tenant = "another"
	if foreign, err := OpenDraftStore(spool, other, false); err == nil {
		_ = foreign.Close()
		t.Fatal("another tenant read the original draft")
	}
	other = store.scope
	other.Root.Generation++
	if foreign, err := OpenDraftStore(spool, other, true); err == nil {
		_ = foreign.Close()
		t.Fatal("different root generation reused a spool")
	}
}

func TestDraftStoreMissingNativeDirectoryIsNotUninitializedWhenJournalExists(t *testing.T) {
	store, spool := draftStoreFixture(t)
	scope := store.scope
	name := filepath.Join(scope.Root.Path, ".mydc-imagebuild", string(store.key))
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(name, name+"-original"); err != nil {
		t.Fatal(err)
	}
	if reopened, err := OpenDraftStore(spool, scope, false); err == nil || errors.Is(err, ErrDraftMissing) {
		if reopened != nil {
			_ = reopened.Close()
		}
		t.Fatal("lost original directory reported as never initialized", err)
	}
}
