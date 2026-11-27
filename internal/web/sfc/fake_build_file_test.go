// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/imagebuild"
)

// a frozen version's file in pages; plus sfcd's fixed build
// server per context.
func TestBuildContextFile(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	alice := passwordLogin(t, f, "alice", "alice")
	bob, _ := keyLogin(t, f, "bob", FixtureKey("bob"))
	big := strings.Repeat("0123456789abcdef", 4000) // 64000 bytes: 3 pages
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range map[string]string{"Dockerfile": "FROM docker.io/library/busybox:1.36\nCOPY data/ /data/\n", "data/big.txt": big} {
		fw, _ := zw.Create(name)
		fw.Write([]byte(body))
	}
	zw.Close()
	v3 := uploadZip(t, f, alice, "zip-file", buf.Bytes())
	var digest [32]byte
	after := ""
	for {
		tree, err := bob.BuildContextContent(ctx, "shop", imagebuild.ContentQuery{Version: v3, Part: "tree"}, after)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range tree.Page.Entries {
			if e.Path == "data/big.txt" {
				digest = e.Digest
			}
		}
		if after = tree.Next; after == "" {
			break
		}
	}
	// Part file: 64-bit offsets, cursor or a start Offset.
	fq := imagebuild.ContentQuery{Version: v3, Part: "file", Path: "data/big.txt"}
	var got []byte
	pages := 0
	after = ""
	for {
		p, err := bob.BuildContextContent(ctx, "shop", fq, after)
		if err != nil || p.Page.File == nil || p.Page.File.Total != uint64(len(big)) || p.Page.File.Entry.Digest != digest || p.Page.File.Offset != uint64(len(got)) {
			t.Fatalf("page %d: %+v %v", pages, p.Page, err)
		}
		got, pages = append(got, p.Page.File.Data...), pages+1
		if after = p.Next; after == "" {
			break
		}
	}
	if string(got) != big || pages != 3 {
		t.Fatalf("read %d bytes in %d pages", len(got), pages)
	}
	mid := fq
	mid.Offset = 50000
	if p, err := bob.BuildContextContent(ctx, "shop", mid, ""); err != nil || string(p.Page.File.Data) != big[50000:] || p.Next != "" {
		t.Fatalf("from offset %+v %v", p.Page, err)
	}
	for _, path := range []string{"data", "../x", "/etc/passwd", "nope.txt"} {
		q := fq
		q.Path = path
		if _, err := bob.BuildContextContent(ctx, "shop", q, ""); err == nil {
			t.Fatalf("%s read", path)
		}
	}
	if _, err := bob.BuildContextContent(ctx, "shop", fq, "bad"); err == nil {
		t.Fatal("bad cursor")
	}
	if _, err := bob.BuildContextContent(ctx, "payments", fq, ""); err == nil {
		t.Fatal("version read from another tenant")
	}

	// A saved context's build server is fixed.
	cur, _ := bob.ImageBuilds(ctx, "shop", control.ImageBuildQuery{Part: "contexts", ID: "worker"}, "")
	w := cur.Contexts[0]
	moved := control.ImageBuildContextPut{Spec: w.Spec}
	moved.Spec.Root.Path = "/elsewhere"
	if _, res := submit(t, alice, ActionPutBuildContext, w.Revision, moved, rootFor(t, alice, ActionPutBuildContext)); res.Code != ResultConditionFailed {
		t.Fatalf("root change %v", res.Code)
	}
}
