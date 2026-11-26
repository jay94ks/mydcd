// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/reconcile"
)

func TestStoredDraftResultPreservesOriginalAfterFilesRetireWithoutWrites(t *testing.T) {
	store, spool := draftStoreFixture(t)
	edit := draftFileEdit("original", "Dockerfile", "FROM scratch\n", 1)
	result, err := store.Edit(context.Background(), edit, bytes.NewBufferString("FROM scratch\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	g := DraftRetirementGrant{Scope: store.scope, ContextRevision: store.scope.ContextRevision + 1, Generation: store.scope.Data().Generation, Deleted: true, Index: 20, Epoch: 1}
	if err := spool.RetireDraft(context.Background(), g, reconcile.Lease{Generation: store.scope.Root.Generation, Token: 7}); err != nil {
		t.Fatal(err)
	}
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}
	// Every Update fails. No native file/root/draft is open or initialized.
	db := &draftGCFailureDB{Transactions: spool.db, failAt: 1}
	out, err := StoredDraftEditResult(db, store.scope, edit)
	if err != nil || out.Code != "OK" || out.Edit == nil || *out.Edit != result || out.Scope != store.scope {
		t.Fatal("original result changed after source retirement", out, err)
	}
	changed := edit
	changed.Path = "different"
	file := *edit.File
	file.Path = changed.Path
	changed.File = &file
	if _, err := StoredDraftEditResult(db, store.scope, changed); !errors.Is(err, ErrConflict) {
		t.Fatal("same ID/different input read as original result", err)
	}
	missing := edit
	missing.ID = "not-recorded"
	if out, err := StoredDraftEditResult(db, store.scope, missing); err != nil || out.Code != "NOT_INITIALIZED" || out.Edit != nil {
		t.Fatal("missing evidence became a completed/unexecuted claim", out, err)
	}
}

func TestStoredDraftResultDistinguishesPendingAndDiscardedMultipartEdit(t *testing.T) {
	store, spool := draftStoreFixture(t)
	body := strings.Repeat("x", PartBytes+10)
	edit := draftFileEdit("partial", "payload", body, 1)
	if _, err := store.StageFilePart(context.Background(), edit, 0, []byte(body[:PartBytes])); err != nil {
		t.Fatal(err)
	}
	if out, err := StoredDraftEditResult(spool.db, store.scope, edit); err != nil || out.Code != "PENDING" || out.Edit != nil {
		t.Fatal("partial stage reported success", out, err)
	}
	if _, err := store.Edit(context.Background(), DraftEdit{ID: "advance", Kind: "mkdir", Path: "new", Expected: 1}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CollectUnused(context.Background(), 16); err != nil {
		t.Fatal(err)
	}
	if out, err := StoredDraftEditResult(spool.db, store.scope, edit); err != nil || out.Code != "DISCARDED" || out.Edit != nil {
		t.Fatal("abandoned original became retryable/completed", out, err)
	}
}
