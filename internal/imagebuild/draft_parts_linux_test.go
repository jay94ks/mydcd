// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func TestDraftMultipartUnorderedDuplicatePartsAndOriginalCommitRecovery(t *testing.T) {
	store, spool := draftStoreFixture(t)
	ctx := context.Background()
	data := bytes.Repeat([]byte{61}, 3*PartBytes+7)
	edit := draftFileEdit("file", "assets/payload", string(data), 1)
	part := func(index uint32) []byte {
		start := int(index) * PartBytes
		return data[start : start+DraftFilePartLength(edit, index)]
	}
	progress, err := store.StageFilePart(ctx, edit, 3, part(3))
	if err != nil || progress.Received != 1 || progress.Complete {
		t.Fatal("first out-of-order part", progress, err)
	}
	if draft, err := store.Read(); err != nil || draft.Revision != 1 || len(draft.Entries) != 0 {
		t.Fatal("partial file published", err)
	}
	missing, err := store.FileStatus(ctx, edit, 0)
	if err != nil || !slices.Equal(missing.Missing, []uint32{0, 1, 2}) {
		t.Fatal("missing parts", missing, err)
	}
	if _, err := store.CommitFile(ctx, edit); err == nil {
		t.Fatal("incomplete file committed")
	}
	again, err := store.StageFilePart(ctx, edit, 3, part(3))
	if err != nil || again.Received != 1 {
		t.Fatal("duplicate changed count", again, err)
	}
	changed := bytes.Clone(part(3))
	changed[0] ^= 1
	if _, err := store.StageFilePart(ctx, edit, 3, changed); !errors.Is(err, ErrConflict) {
		t.Fatal("original part overwritten", err)
	}
	for _, index := range []uint32{1, 0, 2} {
		progress, err = store.StageFilePart(ctx, edit, index, part(index))
		if err != nil {
			t.Fatal(index, err)
		}
	}
	if !progress.Complete || progress.Received != 4 {
		t.Fatal("complete original file", progress)
	}
	// Crash after all durable slots but before the complete-header save. Seal
	// must read back the original file instead of requiring another upload.
	spool.mu.Lock()
	blob, err := store.blob(*edit.File)
	if err == nil {
		blob.Done = false
		err = store.saveBlob(blob)
	}
	spool.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenDraftStore(spool, store.scope, false)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	result, err := store.CommitFile(ctx, edit)
	if err != nil || result.Revision != 2 {
		t.Fatal("completed original not recovered", result, err)
	}
	if _, err := store.Edit(ctx, DraftEdit{ID: "mkdir", Kind: "mkdir", Path: "other", Expected: 2}, nil); err != nil {
		t.Fatal(err)
	}
	if got, err := store.CommitFile(ctx, edit); err != nil || got != result {
		t.Fatal("original result lost after later edit", got, err)
	}
}

func TestDraftMultipartPendingSlotRepairKeepsOriginalInodeAndDigest(t *testing.T) {
	store, spool := draftStoreFixture(t)
	ctx := context.Background()
	data := bytes.Repeat([]byte{11}, PartBytes+5)
	edit := draftFileEdit("pending", "data", string(data), 1)
	if _, err := store.StageFilePart(ctx, edit, 0, data[:PartBytes]); err != nil {
		t.Fatal(err)
	}
	spool.mu.Lock()
	blob, err := store.blob(*edit.File)
	if err != nil {
		spool.mu.Unlock()
		t.Fatal(err)
	}
	originalInode := blob.Inode
	err = spool.db.Update(func(tx *bolt.Tx) error {
		b := store.bucket(tx)
		key := draftFilePartKey(blob.Digest, 0)
		var part localPart
		if json.Unmarshal(b.Get(key), &part) != nil {
			return ErrStorage
		}
		part.Stored = false
		raw, _ := json.Marshal(part)
		if err := b.Put(key, raw); err != nil {
			return err
		}
		blob.Received = 0
		raw, _ = json.Marshal(blob)
		return b.Put(draftBlobKey(blob.Digest), raw)
	})
	if err == nil {
		var fileErr error
		file, fileErr := store.openMultipartBlob(blob)
		if fileErr == nil {
			_, fileErr = file.WriteAt([]byte{0}, 0)
			_ = file.Close()
		}
		err = fileErr
	}
	spool.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.StageFilePart(ctx, edit, 0, data[:PartBytes]); err != nil {
		t.Fatal("same original pending bytes could not recover", err)
	}
	spool.mu.Lock()
	after, err := store.blob(*edit.File)
	spool.mu.Unlock()
	if err != nil || after.Inode != originalInode || after.Received != 1 {
		t.Fatal("pending repair changed native original", after, err)
	}
	wrong := edit
	wrong.File = &Entry{Path: edit.Path, Bytes: edit.File.Bytes, Digest: [32]byte{9}}
	if _, err := store.StageFilePart(ctx, wrong, 1, data[PartBytes:]); !errors.Is(err, ErrConflict) {
		t.Fatal("same pending ID rebound", err)
	}
}

func TestDraftMultipartFullDigestFailureNeverAdvancesRevision(t *testing.T) {
	store, _ := draftStoreFixture(t)
	ctx := context.Background()
	data := bytes.Repeat([]byte{17}, PartBytes+3)
	edit := draftFileEdit("wrong-digest", "data", string(data), 1)
	edit.File.Digest[0] ^= 1
	if _, err := store.StageFilePart(ctx, edit, 0, data[:PartBytes]); err != nil {
		t.Fatal(err)
	}
	if _, err := store.StageFilePart(ctx, edit, 1, data[PartBytes:]); !errors.Is(err, ErrDigest) {
		t.Fatal("wrong whole-file digest accepted", err)
	}
	status, err := store.FileStatus(ctx, edit, 0)
	if err != nil || status.Complete || status.Received != status.Parts || len(status.Missing) != 0 {
		t.Fatal("durable slots and whole-file validity conflated", status, err)
	}
	if _, err := store.CommitFile(ctx, edit); !errors.Is(err, ErrDigest) {
		t.Fatal("seal accepted corrupt complete slots", err)
	}
	if draft, err := store.Read(); err != nil || draft.Revision != 1 || len(draft.Entries) != 0 {
		t.Fatal("invalid bytes entered draft", err)
	}
}

func TestDraftMultipartMissingPageIsBoundedAndScopeSpecific(t *testing.T) {
	// More than two missing pages need a context admitted for this file size.
	store, _ := draftStoreFixtureLimit(t, 16<<20)
	ctx := context.Background()
	edit := DraftEdit{ID: "paged", Kind: "put", Path: "data", Expected: 1, File: &Entry{Path: "data", Bytes: 600*PartBytes + 1, Digest: [32]byte{1}}}
	if _, err := store.StageFilePart(ctx, edit, 600, []byte{1}); err != nil {
		t.Fatal(err)
	}
	var missing int
	for offset := uint32(0); ; {
		status, err := store.FileStatus(ctx, edit, offset)
		if err != nil || len(status.Missing) > 256 || status.Offset != offset || status.Received != 1 {
			t.Fatal("bounded page", status, err)
		}
		missing += len(status.Missing)
		if status.Next == 0 {
			break
		}
		if status.Next <= offset {
			t.Fatal("cursor did not advance")
		}
		offset = status.Next
	}
	if missing != 600 {
		t.Fatal("missing page coverage", missing)
	}
	changed := edit
	changed.Expected++
	if _, err := store.FileStatus(ctx, changed, 0); !errors.Is(err, ErrConflict) {
		t.Fatal("foreign original progress accepted", err)
	}
}

func TestDraftMultipartAcceptedInputKeepsFinalEditCAS(t *testing.T) {
	store, _ := draftStoreFixture(t)
	ctx := context.Background()
	data := bytes.Repeat([]byte{23}, PartBytes+3)
	edit := draftFileEdit("staged", "payload", string(data), 1)
	if _, err := store.StageFilePart(ctx, edit, 0, data[:PartBytes]); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Edit(ctx, DraftEdit{ID: "another", Kind: "mkdir", Path: "other", Expected: 1}, nil); err != nil {
		t.Fatal(err)
	}
	// Existing accepted bytes may finish staging before collection, but
	// cannot overwrite an intervening edit or choose a new commit revision.
	if _, err := store.StageFilePart(ctx, edit, 1, data[PartBytes:]); err != nil {
		t.Fatal("original staging was rebound", err)
	}
	if _, err := store.CommitFile(ctx, edit); !errors.Is(err, ErrConflict) {
		t.Fatal("file seal ignored original CAS", err)
	}
	draft, err := store.Read()
	if err != nil || draft.Revision != 2 || len(draft.Entries) != 1 || draft.Entries[0].Path != "other" {
		t.Fatal("intervening edit changed", draft, err)
	}
}
