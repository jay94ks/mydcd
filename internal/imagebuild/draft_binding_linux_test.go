// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func TestDraftFreshConfigurationPreservesBodyRevisionAndOriginalResults(t *testing.T) {
	store, spool := draftStoreFixture(t)
	ctx := context.Background()
	edit := draftFileEdit("original", "Dockerfile", "FROM scratch\n", 1)
	result, err := store.Edit(ctx, edit, bytes.NewBufferString("FROM scratch\n"))
	if err != nil {
		t.Fatal(err)
	}
	original, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Clone(store.key)
	anchor := store.scope
	fresh := anchor
	fresh.Generation = anchor.Data().Generation
	fresh.ContextRevision++
	fresh.PolicyRevision++
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenDraftStore(spool, fresh, false)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	view, err := store.Read()
	if err != nil || view.Revision != original.Revision || !reflect.DeepEqual(view.Entries, original.Entries) || view.Scope != fresh || !bytes.Equal(store.key, key) {
		t.Fatal("fresh policy/config lost editor", view, err)
	}
	stored, found, err := DraftStoredScope(spool.db, fresh)
	if err != nil || !found || stored != anchor {
		t.Fatal("original RootManager consumer changed", stored, err)
	}
	if got, err := store.Edit(ctx, edit, nil); err != nil || got != result {
		t.Fatal("historical edit receipt rewritten", got, err)
	}
	if _, err := store.Edit(ctx, DraftEdit{ID: "next", Kind: "mkdir", Path: "assets", Expected: view.Revision}, nil); err != nil {
		t.Fatal("current metadata CAS did not use original state", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenDraftStore(spool, fresh, false)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if got, err := store.Read(); err != nil || got.Revision != 3 || len(got.Entries) != 2 {
		t.Fatal("projected state did not survive reopen", got, err)
	}
}

func TestDraftLoweredBudgetKeepsReadAndIncrementalCleanup(t *testing.T) {
	store, spool := draftStoreFixture(t)
	ctx := context.Background()
	if _, err := store.Edit(ctx, draftFileEdit("df", "Dockerfile", "FROM scratch\n", 1), bytes.NewBufferString("FROM scratch\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Edit(ctx, draftFileEdit("body", "payload", "12345678", 2), bytes.NewBufferString("12345678")); err != nil {
		t.Fatal(err)
	}
	fresh := store.scope
	fresh.Generation = fresh.Data().Generation
	fresh.PolicyRevision++
	fresh.ExpandedLimit = 8
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := OpenDraftStore(spool, fresh, false)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	view, err := store.Read()
	if err != nil || len(view.Entries) != 2 || view.Validate() == nil {
		t.Fatal("over-budget metadata could not be inspected", view, err)
	}
	plan := DraftFreezePlan{Schema: 1, Scope: fresh, ID: "too-large", Creator: "manager", Revision: view.Revision, Draft: view.Digest(), CreatedAt: 100, ExpiresAt: 1000}
	if _, err := store.PrepareFreeze(ctx, plan); !errors.Is(err, ErrInvalid) {
		t.Fatal("oversized freeze accepted", err)
	}
	if _, err := store.Edit(ctx, draftFileEdit("grow", "new", "x", view.Revision), bytes.NewBufferString("x")); err == nil {
		t.Fatal("over-budget editor grew")
	}
	if _, err := store.Edit(ctx, DraftEdit{ID: "remove-payload", Kind: "delete", Path: "payload", Expected: view.Revision}, nil); err != nil {
		t.Fatal("first reducing edit refused", err)
	}
	if _, err := store.Edit(ctx, DraftEdit{ID: "remove-df", Kind: "delete", Path: "Dockerfile", Expected: view.Revision + 1}, nil); err != nil {
		t.Fatal("incremental cleanup refused", err)
	}
	if view, err := store.Read(); err != nil || len(view.Entries) != 0 || view.Validate() != nil {
		t.Fatal("cleanup never returned to valid budget", view, err)
	}
}

func TestDraftDeleteRecreateUsesANewDataLifetime(t *testing.T) {
	store, spool := draftStoreFixture(t)
	ctx := context.Background()
	if _, err := store.Edit(ctx, draftFileEdit("file", "payload", "old", 1), bytes.NewBufferString("old")); err != nil {
		t.Fatal(err)
	}
	fresh := store.scope
	fresh.Generation = 3
	fresh.ContextRevision = 3
	if next, err := OpenDraftStore(spool, fresh, false); err == nil || !errors.Is(err, ErrDraftMissing) {
		if next != nil {
			_ = next.Close()
		}
		t.Fatal("recreated context inherited old bytes", err)
	}
	next, err := OpenDraftStore(spool, fresh, true)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if view, err := next.Read(); err != nil || view.Revision != 1 || len(view.Entries) != 0 {
		t.Fatal("new context was not empty", view, err)
	}
	if view, err := store.Read(); err != nil || view.Revision != 2 || len(view.Entries) != 1 {
		t.Fatal("new context altered original evidence", view, err)
	}
}

func TestDraftBindingDoesNotResetWhenItsOriginalJournalDisappears(t *testing.T) {
	store, spool := draftStoreFixture(t)
	fresh := store.scope
	fresh.Generation = fresh.Data().Generation
	fresh.PolicyRevision++
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := spool.db.Update(func(tx *bolt.Tx) error { return store.parent(tx).DeleteBucket(store.key) }); err != nil {
		t.Fatal(err)
	}
	if next, err := OpenDraftStore(spool, fresh, true); err == nil {
		if next != nil {
			_ = next.Close()
		}
		t.Fatal("lost original initialized as a new editor")
	}
	// The old bytes/index are deliberately retained, not repaired by a new
	// state record. A read cannot initialize missing evidence either.
	if _, _, err := DraftStoredScope(spool.db, fresh); err == nil {
		t.Fatal("lost namespace journal treated as no data")
	}
}

func TestDraftBindingIndexContainsOnlyOriginalIdentity(t *testing.T) {
	store, spool := draftStoreFixture(t)
	if _, err := store.Edit(context.Background(), draftFileEdit("file", "payload", "private source bytes", 1), bytes.NewBufferString("private source bytes")); err != nil {
		t.Fatal(err)
	}
	if err := spool.db.View(func(tx *bolt.Tx) error {
		raw := store.parent(tx).Get(draftIndexKey(store.scope.Data()))
		var binding draftBinding
		if json.Unmarshal(raw, &binding) != nil || !validDraftBinding(binding, store.scope) || bytes.Contains(raw, []byte("private source bytes")) {
			return ErrStorage
		}
		return nil
	}); err != nil {
		t.Fatal("index duplicated body/state instead of identity", err)
	}
}
