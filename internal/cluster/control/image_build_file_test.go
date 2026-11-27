// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/imagebuild"
)

// Real authorization/cursors and FSM state; native seal facts are injected.
func TestFileContentCursorPinsPathVersionTenantAndCurrentPermission(t *testing.T) {
	f, spec := imageBuildFixture(t)
	data := []byte("injected native ZIP")
	f.apply("manager", "begin-build-zip-upload", 0, ImageBuildUploadBegin{Tenant: "tenant", Context: spec.ID, Upload: "file-read", Length: int64(len(data)), Digest: sha256.Sum256(data), ExpiresAt: 1000}, state.Applied)
	f.apply("manager", "put-build-zip-part", 1, buildTestPart(t, f, "file-read", 0, data), state.Applied)
	seal := buildTestSeal(t, f, "file-read")
	seal.ExpandedBytes = imagebuild.PartBytes + 1
	seal.Signature = ed25519.Sign(f.node, imagebuild.SealReceiptBytes(seal))
	f.apply("manager", "upload-build-zip", 2, ImageBuildZIPConsume{Tenant: "tenant", ID: spec.ID, Upload: "file-read", Fact: seal}, state.Applied)
	q := imagebuild.ContentQuery{Version: imagebuild.VersionID(seal), Part: "file", Path: "composer.json"}
	read, err := f.p.ImageBuildContentRead(f.s, f.sessions["manager"], 2, "tenant", q, "")
	if err != nil {
		t.Fatal(err)
	}
	file := imagebuild.FilePage{Entry: imagebuild.Entry{Path: q.Path, Bytes: imagebuild.PartBytes + 1, Digest: [32]byte{7}}, Total: imagebuild.PartBytes + 1, Next: imagebuild.PartBytes, Data: make([]byte, imagebuild.PartBytes)}
	page, err := read.Page(imagebuild.ContentPage{Schema: 1, Version: q.Version, Tree: seal.Tree, Part: "file", File: &file})
	if err != nil || page.Next == "" {
		t.Fatal("file cursor", err)
	}
	next, err := f.p.ImageBuildContentRead(f.s, f.sessions["manager"], 2, "tenant", q, page.Next)
	if offset, cause := next.Offset(); err != nil || cause != nil || offset != imagebuild.PartBytes {
		t.Fatal("same file cursor", offset, err, cause)
	}
	for _, mutate := range []func(*imagebuild.ContentQuery){func(q *imagebuild.ContentQuery) { q.Path = "other.json" }, func(q *imagebuild.ContentQuery) { q.Path = "../secret" }, func(q *imagebuild.ContentQuery) { q.Offset = 1 }, func(q *imagebuild.ContentQuery) { q.Version[0] ^= 1 }} {
		bad := q
		mutate(&bad)
		if _, err := f.p.ImageBuildContentRead(f.s, f.sessions["manager"], 2, "tenant", bad, page.Next); err == nil {
			t.Fatal("foreign file cursor accepted")
		}
	}
	if _, err := f.p.ImageBuildContentRead(f.s, f.sessions["manager"], 2, "other", q, ""); err == nil {
		t.Fatal("cross tenant file exposed")
	}
	readonly := f.sessions["manager"]
	readonly.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read}}}
	readonly.Signature = ed25519.Sign(f.node, access.SessionBytes(readonly))
	if _, err := f.p.ImageBuildContentRead(f.s, readonly, 2, "tenant", q, ""); err != nil {
		t.Fatal("read scope cannot inspect immutable file", err)
	}
	draftSpec := spec.Own()
	draftSpec.ID, draftSpec.Kind = "file-draft", "draft"
	f.apply("manager", "put-build-context", 0, ImageBuildContextPut{Spec: draftSpec}, state.Applied)
	call := ImageBuildDraftCall{Session: f.sessions["manager"], Tenant: "tenant", At: 2, Request: imagebuild.DraftRequest{Context: draftSpec.ID, Kind: "plan"}}
	work, err := f.p.ImageBuildDraftWork(f.s, call)
	if err != nil {
		t.Fatal(err)
	}
	call.Request = imagebuild.DraftRequest{Context: draftSpec.ID, Kind: "file", Scope: &work.Scope, Revision: 2, Digest: &[32]byte{8}, Path: "composer.json"}
	if _, err := f.p.ImageBuildDraftWork(f.s, call); err != nil {
		t.Fatal("draft manager read", err)
	}
	call.Session = readonly
	if _, err := f.p.ImageBuildDraftWork(f.s, call); err == nil {
		t.Fatal("read-only session read mutable draft")
	}
	f.apply("manager", "delete-build-version", 1, ImageBuildVersionSelection{Tenant: "tenant", ID: q.Version}, state.Applied)
	if _, err := f.p.CurrentImageBuildContentRead(f.s, read, 2); err == nil {
		t.Fatal("file read survived committed version deletion")
	}
}
