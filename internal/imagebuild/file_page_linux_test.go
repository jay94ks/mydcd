// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/jay94ks/mydcd/internal/reconcile"
)

func TestRetainedZIPFilePagesUseOriginalSealAndStreamingDigest(t *testing.T) {
	data := bytes.Repeat([]byte("{\"require\":\"library\"}\n"), 3000)
	raw := makeZIP(t, zipInput{name: "Dockerfile", body: "FROM scratch\n"}, zipInput{name: "composer.json", body: string(data)})
	spool, scope, _, _ := openTestSpool(t, raw)
	_, key := testScope(int64(len(raw)), sha256.Sum256(raw))
	ctx := context.Background()
	if err := spool.Begin(ctx, scope); err != nil {
		t.Fatal(err)
	}
	for index := uint32(0); index < scope.Parts(); index++ {
		start := int(index) * PartBytes
		if _, err := spool.Put(ctx, scope, index, raw[start:start+scope.PartLength(index)], key); err != nil {
			t.Fatal(err)
		}
	}
	seal, tree, err := spool.Seal(ctx, scope, key)
	if err != nil {
		t.Fatal(err)
	}
	content, err := NewContent(tree, scope, seal)
	if err != nil {
		t.Fatal(err)
	}
	query := ContentQuery{Version: VersionID(seal), Part: "file", Path: "composer.json"}
	entry, err := content.FileEntry(query)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := spool.OpenFile(scope, seal, entry)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var actual []byte
	for offset := uint64(0); ; {
		page, err := reader.Read(ctx, offset)
		if err != nil || !page.Valid(query.Path, offset) {
			t.Fatal(page, err)
		}
		actual = append(actual, page.Data...)
		// Retry the same page cannot advance the shared decompressor again.
		again, err := reader.Read(ctx, offset)
		if err != nil || !bytes.Equal(again.Data, page.Data) {
			t.Fatal("page retry", err)
		}
		if page.Next == 0 {
			break
		}
		offset = page.Next
	}
	if !bytes.Equal(actual, data) || sha256.Sum256(actual) != entry.Digest {
		t.Fatal("EOF/tree digest mismatch")
	}
	past, err := reader.Read(ctx, 7)
	if err != nil || !bytes.Equal(past.Data, data[7:7+PartBytes]) {
		t.Fatal("past offset reopen", err)
	}
	ctxCancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := reader.Read(ctxCancelled, past.Next); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled scan", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Read(ctx, 0); err == nil {
		t.Fatal("closed reader accepted")
	}
	// A different tree digest is checked at EOF, not silently attested by a
	// valid CRC or selected ZIP filename.
	badEntry := entry
	badEntry.Digest[0] ^= 1
	bad, err := spool.OpenFile(scope, seal, badEntry)
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	if _, err := bad.Read(ctx, uint64(len(data))); !errors.Is(err, ErrDigest) {
		t.Fatal("wrong complete digest", err)
	}
	wrong := query
	wrong.Path = "../secret"
	if _, err := content.FileEntry(wrong); err == nil {
		t.Fatal("escaped context path")
	}
	wrong = query
	wrong.Path = "absent"
	if _, err := content.FileEntry(wrong); err == nil {
		t.Fatal("absent file invented")
	}
}

func TestDraftFileReadUsesExactNativeRevisionAndNeverPartialBytes(t *testing.T) {
	store, _ := draftStoreFixture(t)
	ctx := context.Background()
	data := bytes.Repeat([]byte("composer-content\n"), 2000)
	edit := draftFileEdit("original", "composer.json", string(data), 1)
	if _, err := store.Edit(ctx, edit, bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	draft, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	digest := draft.Digest()
	var actual []byte
	for offset := uint32(0); ; {
		page, err := store.ReadFile(ctx, draft.Revision, digest, edit.Path, offset)
		if err != nil || !page.Valid(edit.Path, uint64(offset)) {
			t.Fatal(page, err)
		}
		actual = append(actual, page.Data...)
		if page.Next == 0 {
			break
		}
		offset = uint32(page.Next)
	}
	if !bytes.Equal(actual, data) || sha256.Sum256(actual) != edit.File.Digest {
		t.Fatal("draft file/tree digest mismatch")
	}
	pendingData := bytes.Repeat([]byte("pending-content\n"), 2000)
	pending := draftFileEdit("multipart", "pending.json", string(pendingData), draft.Revision)
	if _, err := store.StageFilePart(ctx, pending, 0, pendingData[:PartBytes]); err != nil {
		t.Fatal(err)
	}
	if page, err := store.ReadFile(ctx, draft.Revision, digest, pending.Path, 0); !errors.Is(err, reconcile.ErrPending) || len(page.Data) != 0 {
		t.Fatal("partial multipart exposed", page, err)
	}
	changed := draftFileEdit("updated", edit.Path, "changed", draft.Revision)
	if _, err := store.Edit(ctx, changed, bytes.NewBufferString("changed")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadFile(ctx, draft.Revision, digest, edit.Path, 0); !errors.Is(err, ErrConflict) {
		t.Fatal("old tree revision accepted", err)
	}
	fresh, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	if page, err := store.ReadFile(ctx, fresh.Revision, fresh.Digest(), edit.Path, 0); err != nil || string(page.Data) != "changed" {
		t.Fatal("new tree not readable", page, err)
	}
	for _, path := range []string{"../secret", "/etc/passwd", "missing"} {
		if _, err := store.ReadFile(ctx, fresh.Revision, fresh.Digest(), path, 0); err == nil {
			t.Fatal("invalid/missing path", path)
		}
	}
	mkdir := DraftEdit{ID: "directory", Kind: "mkdir", Path: "dir", Expected: fresh.Revision}
	if _, err := store.Edit(ctx, mkdir, nil); err != nil {
		t.Fatal(err)
	}
	fresh, err = store.Read()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReadFile(ctx, fresh.Revision, fresh.Digest(), "dir", 0); !errors.Is(err, ErrInvalid) {
		t.Fatal("directory returned as file", err)
	}
}
