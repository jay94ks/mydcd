// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
)

func TestFilePageSelectorsBoundsAndLargeOffsets(t *testing.T) {
	query := ContentQuery{Version: [32]byte{1}, Part: "file", Path: "config/composer.json"}
	if !query.Valid() {
		t.Fatal("regular file query rejected")
	}
	for _, path := range []string{"", ".", "../secret", "/etc/passwd", "dir/../secret", "dir//file", "dir\\file"} {
		q := query
		q.Path = path
		if q.Valid() {
			t.Fatal("unsafe file path", path)
		}
	}
	for _, part := range []string{"tree", "dockerfile"} {
		q := query
		q.Part = part
		if q.Valid() {
			t.Fatal("file selector on non-file part")
		}
	}
	entry := Entry{Path: query.Path, Bytes: (1 << 32) + 3, Digest: [32]byte{2}, Executable: true}
	page := FilePage{Entry: entry, Offset: 1 << 32, Total: uint64(entry.Bytes), Data: []byte("end")}
	if !page.Valid(query.Path, 1<<32) {
		t.Fatal("64-bit terminal page rejected")
	}
	for _, mutate := range []func(*FilePage){func(p *FilePage) { p.Next = p.Total }, func(p *FilePage) { p.Total++ }, func(p *FilePage) { p.Data = p.Data[:2] }, func(p *FilePage) { p.Entry.Directory = true }, func(p *FilePage) { p.Entry.Path = "other" }, func(p *FilePage) { p.Entry.Digest = [32]byte{} }} {
		bad := page
		mutate(&bad)
		if bad.Valid(query.Path, 1<<32) {
			t.Fatal("corrupt file page accepted", bad)
		}
	}
	outer := ContentPage{Schema: 1, Version: query.Version, Tree: [32]byte{3}, Part: "file", File: &page}
	if !outer.Valid(query) || outer.PageOffset() != 1<<32 || outer.PageNext() != 0 {
		t.Fatal("file projection lost wide offset")
	}
	outer.Data = []byte("mixed")
	if outer.Valid(query) {
		t.Fatal("mixed legacy/file payload accepted")
	}
}

func TestNativeFilePageReadBoundsShortReadAndCancellation(t *testing.T) {
	data := bytes.Repeat([]byte("x"), PartBytes+1)
	entry := Entry{Path: "composer.json", Bytes: int64(len(data)), Digest: sha256.Sum256(data)}
	first, err := readAtFilePage(context.Background(), entry, 0, bytes.NewReader(data))
	if err != nil || !first.Valid(entry.Path, 0) || len(first.Data) != PartBytes || first.Next != PartBytes {
		t.Fatal(first, err)
	}
	last, err := readAtFilePage(context.Background(), entry, first.Next, bytes.NewReader(data))
	if err != nil || !last.Valid(entry.Path, PartBytes) || !bytes.Equal(last.Data, []byte("x")) || last.Next != 0 {
		t.Fatal(last, err)
	}
	if _, err := readAtFilePage(context.Background(), entry, 0, bytes.NewReader(data[:2])); !errors.Is(err, ErrStorage) {
		t.Fatal("short original accepted", err)
	}
	if _, err := readAtFilePage(context.Background(), entry, uint64(len(data)+1), bytes.NewReader(data)); !errors.Is(err, ErrInvalid) {
		t.Fatal("outside file accepted", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := readAtFilePage(ctx, entry, 0, bytes.NewReader(data)); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored", err)
	}
	empty := Entry{Path: "empty", Digest: sha256.Sum256(nil)}
	if page, err := readAtFilePage(context.Background(), empty, 0, bytes.NewReader(nil)); err != nil || !page.Valid("empty", 0) || page.Next != 0 {
		t.Fatal("empty file", page, err)
	}
}

func TestDraftFileRequestPinsExactTreeAndRejectsMixedResponses(t *testing.T) {
	scope := draftScopeFixture()
	digest := [32]byte{2}
	query := DraftRequest{Context: scope.Context, Kind: "file", Scope: &scope, Revision: 2, Digest: &digest, Path: "composer.json"}
	file := FilePage{Entry: Entry{Path: query.Path, Bytes: 4, Digest: sha256.Sum256([]byte("text"))}, Total: 4, Data: []byte("text")}
	response := DraftResponse{Schema: 1, Scope: scope, Code: "OK", Revision: 2, Digest: &digest, Content: &file}
	if !query.Valid() || !response.Valid(query) || query.RequiresProof() || query.Mutation() {
		t.Fatal("valid file read rejected")
	}
	for _, mutate := range []func(*DraftRequest){func(q *DraftRequest) { q.Revision = 0 }, func(q *DraftRequest) { q.Digest = nil }, func(q *DraftRequest) { q.Path = "../private" }, func(q *DraftRequest) { q.Proof = &DraftProof{} }, func(q *DraftRequest) { q.Data = []byte("not-input") }, func(q *DraftRequest) { q.Kind = "tree" }} {
		bad := query
		mutate(&bad)
		if bad.Valid() {
			t.Fatal("mixed/missing file snapshot accepted")
		}
	}
	for _, mutate := range []func(*DraftResponse){func(r *DraftResponse) { r.Revision++ }, func(r *DraftResponse) { r.Digest = &[32]byte{9} }, func(r *DraftResponse) { r.File = &DraftFileProgress{} }, func(r *DraftResponse) { r.Next = 1 }, func(r *DraftResponse) { r.Code = "PENDING" }, func(r *DraftResponse) { r.Content = nil }} {
		bad := response
		mutate(&bad)
		if bad.Valid(query) {
			t.Fatal("wrong draft file reply accepted")
		}
	}
	pending := DraftResponse{Schema: 1, Scope: scope, Code: "PENDING"}
	if !pending.Valid(query) {
		t.Fatal("pending without content rejected")
	}
}
