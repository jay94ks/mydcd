// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

func TestContentUsesInspectedImmutableTreeAndBoundedPages(t *testing.T) {
	dockerfile := "FROM scratch\n#" + strings.Repeat("a", PartBytes+11)
	inputs := []zipInput{{name: "Dockerfile", body: dockerfile}}
	for i := 0; i < 10; i++ {
		inputs = append(inputs, zipInput{name: fmt.Sprintf("data/%02d", i), body: "file"})
	}
	raw := makeZIP(t, inputs...)
	tree, err := InspectZIP(context.Background(), bytes.NewReader(raw), int64(len(raw)), "Dockerfile", 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	scope, key := testScope(int64(len(raw)), sha256.Sum256(raw))
	seal := SealReceipt{Schema: 1, Scope: scope.Hash(), ZIP: scope.Digest, Tree: tree.Digest(), Entries: uint32(len(tree.Entries)), ExpandedBytes: tree.Bytes}
	seal.Signature = ed25519.Sign(key, SealReceiptBytes(seal))
	content, err := NewContent(tree, scope, seal)
	if err != nil {
		t.Fatal(err)
	}
	// Callers own neither the cached tree nor the slices returned by a page.
	tree.Entries[0].Path = "overwritten"
	tree.Dockerfile[0] = '!'
	q := ContentQuery{Version: VersionID(seal), Part: "tree"}
	first, err := content.Read(q, 0)
	if err != nil || !first.Valid(q) || len(first.Entries) != 8 || first.Next != 8 {
		t.Fatal(first, err)
	}
	first.Entries[0].Path = "another overwrite"
	again, _ := content.Read(q, 0)
	if again.Entries[0].Path != "Dockerfile" {
		t.Fatal("mutable page changed product content")
	}
	last, err := content.Read(q, 8)
	if err != nil || !last.Valid(q) || last.Next != 0 || len(last.Entries) != 3 {
		t.Fatal(last, err)
	}
	if _, err := content.Read(q, 12); err == nil {
		t.Fatal("out-of-range offset accepted")
	}
	q.Part = "dockerfile"
	var got []byte
	for offset := uint32(0); ; {
		page, err := content.Read(q, offset)
		if err != nil || !page.Valid(q) {
			t.Fatal(err, page)
		}
		got = append(got, page.Data...)
		if page.Next == 0 {
			break
		}
		offset = page.Next
	}
	if string(got) != dockerfile {
		t.Fatal("original Dockerfile bytes changed")
	}
	q.Version[0] ^= 1
	if _, err := content.Read(q, 0); err == nil {
		t.Fatal("another version accepted")
	}
	if _, err := NewContent(tree, scope, seal); err == nil {
		t.Fatal("altered tree accepted")
	}
}

func TestContentPageRejectsMixedOversizedAndTruncatedProjection(t *testing.T) {
	q := ContentQuery{Version: [32]byte{1}, Part: "dockerfile"}
	page := ContentPage{Schema: 1, Version: q.Version, Tree: [32]byte{2}, Part: q.Part, Total: 4, Data: []byte("text")}
	if !page.Valid(q) {
		t.Fatal("valid page rejected")
	}
	for _, edit := range []func(*ContentPage){
		func(p *ContentPage) { p.Next = 4 }, func(p *ContentPage) { p.Offset = 1 },
		func(p *ContentPage) { p.Total = MaxDockerfileBytes + 1 }, func(p *ContentPage) { p.Tree = [32]byte{} },
		func(p *ContentPage) { p.Data = p.Data[:3] }, func(p *ContentPage) { p.Entries = []Entry{{Path: "extra"}} },
	} {
		bad := page
		edit(&bad)
		if bad.Valid(q) {
			t.Fatal("invalid page accepted", bad)
		}
	}
}
