// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
)

func draftScopeFixture() DraftScope {
	u, _ := testScope(1, [32]byte{1})
	return DraftScope{Schema: 1, Tenant: u.Tenant, Context: u.Context, Root: u.Root, ContextRevision: 1, PolicyRevision: 1, Dockerfile: "Dockerfile", ExpandedLimit: 1 << 20}
}
func draftFileEdit(id, name, body string, expected uint64) DraftEdit {
	return DraftEdit{ID: id, Kind: "put", Path: name, Expected: expected, File: &Entry{Path: name, Bytes: int64(len(body)), Digest: sha256.Sum256([]byte(body))}}
}
func TestDraftMovesImplicitDirectoriesAtomicallyWithoutDestinationMerge(t *testing.T) {
	draft, err := NewDraft(draftScopeFixture())
	if err != nil {
		t.Fatal(err)
	}
	for i, name := range []string{"Dockerfile", "src/a", "src/deep/b", "other/keep"} {
		draft, err = draft.Edit(draftFileEdit([]string{"first", "second", "third", "fourth"}[i], name, "data", draft.Revision))
		if err != nil {
			t.Fatal(err)
		}
	}
	before := draft.Digest()
	for _, edit := range []DraftEdit{
		{ID: "stale", Kind: "delete", Path: "src", Expected: draft.Revision - 1},
		{ID: "merge", Kind: "move", Path: "src", To: "other", Expected: draft.Revision},
		{ID: "cycle", Kind: "move", Path: "src", To: "src/nested", Expected: draft.Revision},
		{ID: "parent-file", Kind: "move", Path: "src", To: "Dockerfile/sub", Expected: draft.Revision},
		draftFileEdit("replace-directory", "src", "data", draft.Revision),
		draftFileEdit("path-escape", "../outside", "data", draft.Revision),
	} {
		if _, err := draft.Edit(edit); err == nil {
			t.Fatalf("accepted invalid edit: %+v", edit)
		}
		if draft.Digest() != before {
			t.Fatal("rejected edit mutated original entries")
		}
	}
	moved, err := draft.Edit(DraftEdit{ID: "move", Kind: "move", Path: "src", To: "assets", Expected: draft.Revision})
	if err != nil || moved.Validate() != nil || len(moved.Entries) != 4 || moved.Entries[1].Path != "assets/a" || moved.Entries[2].Path != "assets/deep/b" {
		t.Fatal("implicit directory move", moved, err)
	}
	deleted, err := moved.Edit(DraftEdit{ID: "delete", Kind: "delete", Path: "assets", Expected: moved.Revision})
	if err != nil || len(deleted.Entries) != 2 || len(draft.Entries) != 4 {
		t.Fatal("subtree delete or input ownership", err)
	}
	for _, entry := range deleted.Entries {
		if entry.Path != "Dockerfile" && entry.Path != "other/keep" {
			t.Fatal("delete affected another directory", entry)
		}
	}
}

func TestDraftZIPFreezeUsesTheSameZIPTreeAndRejectsChangedFiles(t *testing.T) {
	draft, _ := NewDraft(draftScopeFixture())
	files := map[string]string{"Dockerfile": "FROM scratch\nCOPY files /files\n", "files/payload": "immutable", "empty": ""}
	for i, name := range []string{"Dockerfile", "files/payload", "empty"} {
		var err error
		draft, err = draft.Edit(draftFileEdit([]string{"dockerfile", "payload", "empty"}[i], name, files[name], draft.Revision))
		if err != nil {
			t.Fatal(err)
		}
	}
	closed := 0
	open := func(e Entry) (io.ReadCloser, error) {
		return &draftTestReader{Reader: bytes.NewReader([]byte(files[e.Path])), close: func() { closed++ }}, nil
	}
	var raw bytes.Buffer
	tree, err := draft.WriteZIP(context.Background(), &raw, open)
	if err != nil || closed != len(files) {
		t.Fatal("freeze/file reader lifetime", err, closed)
	}
	actual, err := InspectZIP(context.Background(), bytes.NewReader(raw.Bytes()), int64(raw.Len()), draft.Scope.Dockerfile, draft.Scope.ExpandedLimit)
	if err != nil || actual.Digest() != tree.Digest() || !reflect.DeepEqual(actual.Entries, draft.Entries) {
		t.Fatal("draft and uploaded archive diverge", err)
	}
	var repeated bytes.Buffer
	if _, err := draft.WriteZIP(context.Background(), &repeated, open); err != nil || !bytes.Equal(raw.Bytes(), repeated.Bytes()) {
		t.Fatal("same frozen revision is not deterministic", err)
	}
	files["files/payload"] = "tampered!"
	if _, err := draft.WriteZIP(context.Background(), io.Discard, open); !errors.Is(err, ErrDigest) {
		t.Fatal("content hash not checked", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := draft.WriteZIP(ctx, io.Discard, open); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled freeze continued", err)
	}
}

type draftTestReader struct {
	*bytes.Reader
	close func()
}

func (r *draftTestReader) Close() error { r.close(); return nil }

func TestDraftEditableBudgetAndMissingDockerfileDoNotPublishVersion(t *testing.T) {
	scope := draftScopeFixture()
	scope.ExpandedLimit = 8
	draft, _ := NewDraft(scope)
	if _, err := draft.Edit(draftFileEdit("large", "data", "123456789", draft.Revision)); err == nil {
		t.Fatal("expanded content budget ignored")
	}
	draft, err := draft.Edit(DraftEdit{ID: "mkdir", Kind: "mkdir", Path: "files", Expected: draft.Revision})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := draft.WriteZIP(context.Background(), io.Discard, func(Entry) (io.ReadCloser, error) { t.Fatal("opened absent Dockerfile"); return nil, nil }); err == nil {
		t.Fatal("published a draft without Dockerfile")
	}
}

func TestDraftFolderMoveCannotCommitMetadataThatReopenWouldReject(t *testing.T) {
	draft, _ := NewDraft(draftScopeFixture())
	for i := 0; i < 10_000; i++ {
		draft.Entries = append(draft.Entries, Entry{Path: fmt.Sprintf("src/f%05d", i), Digest: sha256.Sum256(nil)})
	}
	if err := draft.Validate(); err != nil {
		t.Fatal("initial short paths", err)
	}
	original := draft.Digest()
	// Each resulting path is valid on its own, but renaming one implicit
	// directory would multiply the stored path prefix across all its files.
	if _, err := draft.Edit(DraftEdit{ID: "long-prefix", Kind: "move", Path: "src", To: strings.Repeat("parent/", 140) + "dest", Expected: 1}); err == nil {
		t.Fatal("accepted a revision larger than the native reopen budget")
	}
	if draft.Digest() != original || draft.Validate() != nil {
		t.Fatal("rejected rename damaged the original revision")
	}
}
