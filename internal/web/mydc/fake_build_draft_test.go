// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/imagebuild"
)

func TestBuildDraftRealContract(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	alice := passwordLogin(t, f, "alice", "alice")
	bob, _ := keyLogin(t, f, "bob", FixtureKey("bob"))
	planQ := imagebuild.DraftRequest{Context: "cron", Kind: "plan"}
	plan, err := alice.BuildDraft(ctx, "shop", planQ)
	if err != nil || !plan.Valid(planQ) {
		t.Fatalf("plan %+v %v", plan, err)
	}
	scope := plan.Scope
	if _, err := bob.BuildDraft(ctx, "shop", planQ); err == nil {
		t.Fatal("a viewer opened the mutable draft")
	}
	tree := func() imagebuild.DraftResponse {
		t.Helper()
		var all []imagebuild.Entry
		q := imagebuild.DraftRequest{Context: "cron", Kind: "tree", Scope: &scope}
		first, err := alice.BuildDraft(ctx, "shop", q)
		if err != nil || !first.Valid(q) {
			t.Fatalf("tree %+v %v", first, err)
		}
		r := first
		for {
			all = append(all, r.Entries...)
			if r.Next == 0 {
				break
			}
			q = imagebuild.DraftRequest{Context: "cron", Kind: "tree", Scope: &scope, Revision: first.Revision, Digest: first.Digest, Offset: r.Next}
			if r, err = alice.BuildDraft(ctx, "shop", q); err != nil || !r.Valid(q) {
				t.Fatalf("tree page %+v %v", r, err)
			}
		}
		first.Entries = all
		return first
	}
	t0 := tree()
	if t0.Revision != 1 || len(t0.Entries) != 2 {
		t.Fatalf("tree %+v", t0)
	}

	// Inline put: once per ID; the same ID with other content is refused.
	body := []byte("#!/bin/sh\necho hi\n")
	put := imagebuild.DraftEdit{ID: "e-put", Kind: "put", Path: "bin/run", Expected: 1, File: &imagebuild.Entry{Path: "bin/run", Executable: true, Bytes: int64(len(body)), Digest: sha256.Sum256(body)}}
	r, err := alice.EditBuildDraft(ctx, scope, put, body)
	if err != nil || r.Code != "OK" || r.Revision != 2 || r.Edit.Edit != put.Digest() {
		t.Fatalf("put %+v %v", r, err)
	}
	if again, err := alice.EditBuildDraft(ctx, scope, put, body); err != nil || again.Revision != 2 {
		t.Fatalf("same edit again %+v %v", again, err)
	}
	other := put
	other.Path, other.File = "bin/other", &imagebuild.Entry{Path: "bin/other", Bytes: int64(len(body)), Digest: sha256.Sum256(body)}
	if _, err := alice.EditBuildDraft(ctx, scope, other, body); err == nil {
		t.Fatal("edit ID reused")
	}
	stale := imagebuild.DraftEdit{ID: "e-stale", Kind: "mkdir", Path: "x", Expected: 1}
	if _, err := alice.EditBuildDraft(ctx, scope, stale, nil); err == nil {
		t.Fatal("stale Expected")
	}
	if res, err := alice.DraftEditResult(ctx, scope, put); err != nil || res.Code != "OK" || res.Revision != 2 {
		t.Fatalf("result %+v %v", res, err)
	}
	for i, e := range []imagebuild.DraftEdit{
		{ID: "e-mkdir", Kind: "mkdir", Path: "assets", Expected: 2},
		{ID: "e-move", Kind: "move", Path: "bin", To: "tools", Expected: 3},
		{ID: "e-del", Kind: "delete", Path: "assets", Expected: 4},
	} {
		if r, err := alice.EditBuildDraft(ctx, scope, e, nil); err != nil || r.Revision != uint64(i)+3 {
			t.Fatalf("%s %+v %v", e.ID, r, err)
		}
	}
	t1 := tree()
	var paths []string
	for _, e := range t1.Entries {
		paths = append(paths, e.Path)
		if e.Path == "tools/run" && !e.Executable {
			t.Fatal("executable bit lost on move")
		}
	}
	if strings.Join(paths, ",") != "Dockerfile,crontab,tools,tools/run" {
		t.Fatalf("draft paths %v", paths)
	}

	// build-draft Kind file → Content FilePage.
	dq := imagebuild.DraftRequest{Context: scope.Context, Kind: "file", Scope: &scope, Revision: t1.Revision, Digest: t1.Digest, Path: "tools/run"}
	if r, err := alice.BuildDraft(ctx, "shop", dq); err != nil || !r.Valid(dq) || string(r.Content.Data) != string(body) || !r.Content.Entry.Executable || r.Content.Next != 0 {
		t.Fatalf("draft file (real) %+v %v", r, err)
	}
	staleQ := dq
	staleQ.Revision, staleQ.Digest = t0.Revision, t0.Digest
	if _, err := alice.BuildDraft(ctx, "shop", staleQ); err == nil {
		t.Fatal("stale draft file read (real)")
	}
	dirQ := dq
	dirQ.Path = "tools"
	if _, err := alice.BuildDraft(ctx, "shop", dirQ); err == nil {
		t.Fatal("draft directory read as a file")
	}

	// A large file in parts: status lists the missing, seal registers it.
	big := []byte(strings.Repeat("x", 60000))
	bigEdit := imagebuild.DraftEdit{ID: "e-big", Kind: "put", Path: "data.txt", Expected: t1.Revision, File: &imagebuild.Entry{Path: "data.txt", Bytes: int64(len(big)), Digest: sha256.Sum256(big)}}
	if r, err := alice.PutDraftFilePart(ctx, scope, bigEdit, 0, big[:imagebuild.PartBytes]); err != nil || r.Code != "STAGED" || r.File.Received != 1 {
		t.Fatalf("part 0 %+v %v", r, err)
	}
	if st, err := alice.DraftFileStatus(ctx, scope, bigEdit, 0); err != nil || st.Code != "STAGED" || len(st.File.Missing) != 2 {
		t.Fatalf("status %+v %v", st, err)
	}
	if r, err := alice.CommitDraftFile(ctx, scope, bigEdit); err != nil || r.Code != "PENDING" {
		t.Fatalf("early seal %+v %v", r, err)
	}
	for i := uint32(1); i < 3; i++ {
		end := min(int(i+1)*imagebuild.PartBytes, len(big))
		if _, err := alice.PutDraftFilePart(ctx, scope, bigEdit, i, big[int(i)*imagebuild.PartBytes:end]); err != nil {
			t.Fatal(err)
		}
	}
	sealed, err := alice.CommitDraftFile(ctx, scope, bigEdit)
	if err != nil || sealed.Code != "OK" || sealed.Revision != t1.Revision+1 {
		t.Fatalf("seal %+v %v", sealed, err)
	}

	// Freeze → publish-build-draft → a new version with those files.
	t2 := tree()
	now := uint64(f.now().Unix())
	fp := imagebuild.DraftFreezePlan{Schema: 1, Scope: scope, ID: "fz-1", Creator: "u-alice", Revision: t2.Revision, Draft: *t2.Digest, CreatedAt: now, ExpiresAt: now + 3600}
	fr, err := alice.FreezeBuildDraft(ctx, fp)
	if err != nil || fr.Code != "FROZEN" || !fr.Frozen.Valid() {
		t.Fatalf("freeze %+v %v", fr, err)
	}
	if again, err := alice.DraftFreezeResult(ctx, fp); err != nil || again.Code != "FROZEN" {
		t.Fatalf("freeze result %+v %v", again, err)
	}
	pub := control.ImageBuildDraftPublish{Tenant: "shop", Context: "cron", Frozen: *fr.Frozen}
	if _, res := submit(t, alice, ActionPublishBuildDraft, fp.Revision, pub, rootFor(t, alice, ActionPublishBuildDraft)); res.Code != ResultApplied {
		t.Fatalf("publish %v", res.Code)
	}
	vs, _ := bob.ImageBuilds(ctx, "shop", control.ImageBuildQuery{Part: "versions", ID: "cron"}, "")
	var v2 [32]byte
	for _, v := range vs.Versions {
		if v.Number == 2 {
			v2 = v.ID
		}
	}
	if v2 != imagebuild.VersionID(fr.Frozen.Fact) {
		t.Fatalf("published version %+v", vs.Versions)
	}
	if p, err := bob.BuildContextContent(ctx, "shop", imagebuild.ContentQuery{Version: v2, Part: "file", Path: "data.txt"}, ""); err != nil || p.Page.File == nil || p.Page.File.Total != 60000 {
		t.Fatalf("published file %+v %v", p.Page, err)
	}

	// A forged proof is refused; a new draft context starts uninitialized.
	forged := imagebuild.DraftRequest{Context: "cron", Kind: "edit", Scope: &scope, Edit: &imagebuild.DraftEdit{ID: "e-forged", Kind: "mkdir", Path: "y", Expected: t2.Revision},
		Proof: &imagebuild.DraftProof{Schema: 1, Scope: scope.Digest(), At: int64(now), ExpiresAt: int64(now) + 60, Nonce: [32]byte{1}, Signature: make([]byte, 64)}}
	if _, err := alice.BuildDraft(ctx, "shop", forged); err == nil {
		t.Fatal("forged proof")
	}
	pol, _ := bob.ImageBuilds(ctx, "shop", control.ImageBuildQuery{Part: "policy"}, "")
	spec := imagebuild.ContextSpec{Tenant: "shop", ID: "fresh", Kind: "draft", Root: pol.Policies[0].Spec.Nodes[0].Root, Dockerfile: "Dockerfile", Repository: "shop/fresh",
		Tags: []string{"{version}"}, Platforms: []string{"linux/amd64"}}
	if _, res := submit(t, alice, ActionPutBuildContext, 0, control.ImageBuildContextPut{Spec: spec}, rootFor(t, alice, ActionPutBuildContext)); res.Code != ResultApplied {
		t.Fatalf("put fresh %v", res.Code)
	}
	fresh, _ := alice.BuildDraft(ctx, "shop", imagebuild.DraftRequest{Context: "fresh", Kind: "plan"})
	q := imagebuild.DraftRequest{Context: "fresh", Kind: "tree", Scope: &fresh.Scope}
	if r, err := alice.BuildDraft(ctx, "shop", q); err != nil || r.Code != "NOT_INITIALIZED" || !r.Valid(q) {
		t.Fatalf("fresh tree %+v %v", r, err)
	}
}
