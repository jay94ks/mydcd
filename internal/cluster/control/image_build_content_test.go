// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/imagebuild"
)

func TestBuildContentReadPinsTenantVersionEpochAndRefusesDeletedVersion(t *testing.T) {
	f, _ := imageBuildFixture(t)
	data := []byte("injected native artifact")
	f.apply("manager", "begin-build-zip-upload", 0, ImageBuildUploadBegin{Tenant: "tenant", Context: "source", Upload: "retained", Length: int64(len(data)), Digest: sha256.Sum256(data), ExpiresAt: 1000}, state.Applied)
	f.apply("manager", "put-build-zip-part", 1, buildTestPart(t, f, "retained", 0, data), state.Applied)
	seal := buildTestSeal(t, f, "retained")
	seal.Entries = 9
	seal.Signature = ed25519.Sign(f.node, imagebuild.SealReceiptBytes(seal))
	f.apply("manager", "upload-build-zip", 2, ImageBuildZIPConsume{Tenant: "tenant", ID: "source", Upload: "retained", Fact: seal}, state.Applied)
	q := imagebuild.ContentQuery{Version: imagebuild.VersionID(seal), Part: "tree"}
	read, err := f.p.ImageBuildContentRead(f.s, f.sessions["manager"], 2, "tenant", q, "")
	if err != nil {
		t.Fatal(err)
	}
	// Owner facts are injected here. Native ZIP verification has its own
	// actual filesystem tests, not a second implementation of the algorithm.
	page := imagebuild.ContentPage{Schema: 1, Version: q.Version, Tree: seal.Tree, Part: "tree", Total: 9, Next: 8}
	for i := 0; i < 8; i++ {
		page.Entries = append(page.Entries, imagebuild.Entry{Path: fmt.Sprintf("file-%02d", i), Digest: sha256.Sum256([]byte("data")), Bytes: 4})
	}
	first, err := read.Page(page)
	if err != nil || !first.Valid(read) || first.Next == "" {
		t.Fatal("bounded projection", err)
	}
	next, err := f.p.ImageBuildContentRead(f.s, f.sessions["manager"], 2, "tenant", q, first.Next)
	if offset, cause := next.Offset(); err != nil || cause != nil || offset != 8 {
		t.Fatal("next offset", err, cause)
	}
	other := q
	other.Part = "dockerfile"
	if _, err := f.p.ImageBuildContentRead(f.s, f.sessions["manager"], 2, "tenant", other, first.Next); err == nil {
		t.Fatal("tree cursor used for Dockerfile")
	}
	if _, err := f.p.ImageBuildContentRead(f.s, f.sessions["manager"], 2, "other", q, ""); err == nil {
		t.Fatal("cross-tenant version exposed")
	}
	if _, err := f.p.ImageBuildContentRead(f.s, f.sessions["manager"], 1002, "tenant", q, ""); err == nil {
		t.Fatal("expired session reads retained bytes")
	}
	fresh := f.sessions["manager"]
	fresh.ID = "fresh-manager"
	fresh.IssuedAt, fresh.ExpiresAt = 1100, 2000
	fresh.Signature = ed25519.Sign(f.node, access.SessionBytes(fresh))
	if _, err := f.p.ImageBuildContentRead(f.s, fresh, 1100, "tenant", q, ""); err != nil {
		t.Fatal("consumed version incorrectly expired with its upload deadline", err)
	}
	for _, edit := range []func(*ImageBuildContentRead){
		func(r *ImageBuildContentRead) { r.Epoch++ }, func(r *ImageBuildContentRead) { r.Scope.Upload = "substituted" },
		func(r *ImageBuildContentRead) { r.Seal.Tree[0] ^= 1 }, func(r *ImageBuildContentRead) { r.After = buildPageNext(r.Snapshot(), "0000000008x") },
	} {
		bad := read
		edit(&bad)
		if _, err := f.p.CurrentImageBuildContentRead(f.s, bad, 2); err == nil {
			t.Fatal("altered owner read accepted")
		}
	}
	f.apply("manager", "delete-build-version", 1, ImageBuildVersionSelection{Tenant: "tenant", ID: q.Version}, state.Applied)
	if _, err := f.p.CurrentImageBuildContentRead(f.s, read, 2); err == nil {
		t.Fatal("accepted read survived committed version deletion")
	}
	if _, err := f.p.ImageBuildContentRead(f.s, f.sessions["manager"], 2, "tenant", q, first.Next); err == nil {
		t.Fatal("deleted version cursor remained usable")
	}
}
