// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
)

func TestDraftResultProofCannotBeReplayedAsMutationOrMixedWithBytes(t *testing.T) {
	scope := draftScopeFixture()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{63}, 32))
	session := access.Session{Cluster: scope.Root.Cluster, User: "manager", Key: [32]byte(key.Public().(ed25519.PublicKey)), ExpiresAt: 300}
	edit := draftFileEdit("original", "Dockerfile", "FROM scratch\n", 1)
	proof := DraftProof{Schema: 1, Scope: scope.Digest(), Edit: edit.Digest(), At: 100, ExpiresAt: 200, Nonce: [32]byte{1}, Transfer: &DraftTransferProof{Kind: "result"}}
	proof.Signature = ed25519.Sign(key, DraftProofBytes(proof))
	q := DraftRequest{Context: scope.Context, Kind: "result", Scope: &scope, Edit: &edit, Proof: &proof}
	if !q.Valid() || q.Mutation() || !q.RequiresProof() || q.Authorize(scope, session, 101) != nil {
		t.Fatal("original result query rejected")
	}
	for _, change := range []func(*DraftRequest){
		func(q *DraftRequest) { q.Data = []byte("FROM scratch\n") },
		func(q *DraftRequest) { q.Kind = "edit"; q.Data = []byte("FROM scratch\n") },
		func(q *DraftRequest) {
			p := *q.Proof
			p.Transfer = nil
			q.Proof = &p
			q.Kind = "edit"
			q.Data = []byte("FROM scratch\n")
		},
		func(q *DraftRequest) { e := *q.Edit; e.Expected++; q.Edit = &e },
	} {
		bad := q
		change(&bad)
		if bad.Valid() && bad.Authorize(scope, session, 101) == nil {
			t.Fatal("result proof changed purpose/input or carried source bytes")
		}
	}
	for _, code := range []string{"PENDING", "NOT_INITIALIZED", "DISCARDED"} {
		if !(DraftResponse{Schema: 1, Scope: scope, Code: code}).Valid(q) {
			t.Fatal("result state rejected", code)
		}
	}
}

func TestFreezeResultPurposePreservesExpiredPlanWithoutExtendingFreezeAuthority(t *testing.T) {
	scope := draftScopeFixture()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{63}, 32))
	session := access.Session{Cluster: scope.Root.Cluster, User: "manager", Key: [32]byte(key.Public().(ed25519.PublicKey)), ExpiresAt: 300}
	plan := DraftFreezePlan{Schema: 1, Scope: scope, ID: "original", Creator: session.User, Revision: 2, Draft: [32]byte{9}, CreatedAt: 1, ExpiresAt: 100}
	proof := DraftProof{Schema: 1, Scope: scope.Digest(), Edit: plan.Digest(), At: 101, ExpiresAt: 200, Nonce: [32]byte{1}, Transfer: &DraftTransferProof{Kind: "freeze-result"}}
	proof.Signature = ed25519.Sign(key, DraftProofBytes(proof))
	q := DraftRequest{Context: scope.Context, Kind: "freeze-result", Scope: &scope, Freeze: &plan, Proof: &proof}
	if !q.Valid() || q.Mutation() || !q.RequiresProof() || q.Authorize(scope, session, 102) != nil {
		t.Fatal("original expired freeze result denied")
	}
	bad := q
	bad.Kind = "freeze"
	if bad.Authorize(scope, session, 102) == nil {
		t.Fatal("result proof reexecuted expired freeze")
	}
	for _, code := range []string{"PENDING", "DISCARDED", "NOT_INITIALIZED"} {
		if !(DraftResponse{Schema: 1, Scope: scope, Code: code}).Valid(q) {
			t.Fatal("historical freeze state rejected", code)
		}
	}
}

func TestDraftEditProofSurvivesRelayWithoutGrantingDifferentBytesOrScope(t *testing.T) {
	scope := draftScopeFixture()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{63}, 32))
	session := access.Session{Cluster: scope.Root.Cluster, User: "manager", Key: [32]byte(key.Public().(ed25519.PublicKey)), ExpiresAt: 300}
	edit := draftFileEdit("original", "Dockerfile", "FROM scratch\n", 1)
	proof := DraftProof{Schema: 1, Scope: scope.Digest(), Edit: edit.Digest(), At: 100, ExpiresAt: 200, Nonce: [32]byte{1}}
	proof.Signature = ed25519.Sign(key, DraftProofBytes(proof))
	q := DraftRequest{Context: scope.Context, Kind: "edit", Scope: &scope, Edit: &edit, Proof: &proof, Data: []byte("FROM scratch\n")}
	if !q.Valid() || q.Authorize(scope, session, 101) != nil {
		t.Fatal("valid original user edit refused")
	}
	for name, mutate := range map[string]func(*DraftRequest){
		"different-file": func(q *DraftRequest) {
			e := *q.Edit
			e.Path, e.File = "other", &Entry{Path: "other", Bytes: q.Edit.File.Bytes, Digest: q.Edit.File.Digest}
			q.Edit = &e
		},
		"different-cas":     func(q *DraftRequest) { e := *q.Edit; e.Expected++; q.Edit = &e },
		"different-data":    func(q *DraftRequest) { q.Data = []byte("different data") },
		"different-root":    func(q *DraftRequest) { s := *q.Scope; s.Root.Generation++; q.Scope = &s },
		"different-context": func(q *DraftRequest) { q.Context = "other" },
		"paged-mutation":    func(q *DraftRequest) { q.Offset = 1 },
		"different-proof": func(q *DraftRequest) {
			p := *q.Proof
			p.Signature = bytes.Clone(p.Signature)
			p.Signature[0] ^= 1
			q.Proof = &p
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := q
			mutate(&bad)
			if bad.Valid() && bad.Authorize(scope, session, 101) == nil {
				t.Fatal("relay changed signed edit")
			}
		})
	}
	if q.Authorize(scope, session, 200) == nil || q.Authorize(scope, session, 99) == nil {
		t.Fatal("expired or future proof accepted")
	}
	foreign := session
	foreign.Key[0] ^= 1
	if q.Authorize(scope, foreign, 101) == nil {
		t.Fatal("another user key accepted")
	}
}

func TestDraftResponseChecksRevisionDigestPagingAndOriginalResult(t *testing.T) {
	scope := draftScopeFixture()
	draft, _ := NewDraft(scope)
	digest := draft.Digest()
	q := DraftRequest{Context: scope.Context, Kind: "tree", Scope: &scope}
	page := DraftResponse{Schema: 1, Scope: scope, Code: "OK", Revision: 1, Digest: &digest}
	if !page.Valid(q) {
		t.Fatal("empty but initialized native draft page rejected")
	}
	for _, mutate := range []func(*DraftResponse){
		func(p *DraftResponse) { p.Revision = 0 },
		func(p *DraftResponse) { p.Digest = nil },
		func(p *DraftResponse) { p.Next = 1 },
		func(p *DraftResponse) { p.Total = 2 },
		func(p *DraftResponse) { p.Scope.PolicyRevision++ },
	} {
		bad := page
		mutate(&bad)
		if bad.Valid(q) {
			t.Fatal("corrupt page accepted")
		}
	}
	q.Revision, q.Digest = 2, &digest
	if page.Valid(q) {
		t.Fatal("different native revision accepted for a later page")
	}
	plan := DraftRequest{Context: scope.Context, Kind: "plan"}
	if !(DraftResponse{Schema: 1, Scope: scope, Code: "PLAN"}).Valid(plan) {
		t.Fatal("scope-only plan rejected")
	}
	edit := DraftEdit{ID: "mkdir", Kind: "mkdir", Path: "assets", Expected: 1}
	mutation := DraftRequest{Context: scope.Context, Kind: "edit", Scope: &scope, Edit: &edit, Proof: &DraftProof{}}
	result := DraftEditResult{Edit: edit.Digest(), Draft: digest, Revision: 2}
	response := DraftResponse{Schema: 1, Scope: scope, Code: "OK", Revision: 2, Digest: &digest, Edit: &result}
	if !response.Valid(mutation) {
		t.Fatal("original native edit result rejected")
	}
	wrong := result
	wrong.Edit[0] ^= 1
	response.Edit = &wrong
	if response.Valid(mutation) {
		t.Fatal("another edit's result accepted")
	}
}

func TestDraftMultipartProofBindsPartBytesIndexAndSealPurpose(t *testing.T) {
	scope := draftScopeFixture()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{64}, 32))
	session := access.Session{Cluster: scope.Root.Cluster, Key: [32]byte(key.Public().(ed25519.PublicKey)), ExpiresAt: 300}
	data := bytes.Repeat([]byte{7}, PartBytes+3)
	edit := draftFileEdit("multipart", "data", string(data), 1)
	part := DraftFilePart{Index: 0, Length: PartBytes, Digest: sha256.Sum256(data[:PartBytes])}
	proof := DraftProof{Schema: 1, Scope: scope.Digest(), Edit: edit.Digest(), At: 100, ExpiresAt: 200, Nonce: [32]byte{1}, Transfer: &DraftTransferProof{Kind: "file-part", Part: &part}}
	proof.Signature = ed25519.Sign(key, DraftProofBytes(proof))
	q := DraftRequest{Context: scope.Context, Kind: "file-part", Scope: &scope, Edit: &edit, Proof: &proof, Data: data[:PartBytes]}
	if !q.Valid() || q.Authorize(scope, session, 101) != nil {
		t.Fatal("original file part refused")
	}
	second := DraftFilePart{Index: 1, Length: 3, Digest: sha256.Sum256(data[PartBytes:])}
	changed := q
	other := proof
	other.Transfer = &DraftTransferProof{Kind: "file-part", Part: &second}
	changed.Proof = &other
	changed.Data = data[PartBytes:]
	if !changed.Valid() || changed.Authorize(scope, session, 101) == nil {
		t.Fatal("part proof reused for different index/bytes")
	}
	seal := q
	other = proof
	other.Transfer = &DraftTransferProof{Kind: "file-seal"}
	seal.Proof = &other
	seal.Data = nil
	seal.Kind = "file-seal"
	if !seal.Valid() || seal.Authorize(scope, session, 101) == nil {
		t.Fatal("part proof reused to commit metadata")
	}
	progress := DraftFileProgress{Edit: edit.Digest(), Parts: 2, Received: 1, Part: &part}
	response := DraftResponse{Schema: 1, Scope: scope, Code: "STAGED", File: &progress}
	if !response.Valid(q) {
		t.Fatal("valid stage acknowledgement refused")
	}
	wrong := part
	wrong.Index = 1
	progress.Part = &wrong
	if response.Valid(q) {
		t.Fatal("acknowledgement for another part accepted")
	}
	status := DraftRequest{Context: scope.Context, Kind: "file-status", Scope: &scope, Edit: &edit}
	missing := DraftFileProgress{Edit: edit.Digest(), Parts: 2, Received: 1, Missing: []uint32{1}}
	response.File = &missing
	if !response.Valid(status) {
		t.Fatal("valid missing page refused")
	}
	missing.Received = 2
	if response.Valid(status) {
		t.Fatal("inconsistent received/missing count accepted")
	}
}

func TestDraftFreezeProofPinsSnapshotCreatorAndDoesNotReuseEditProof(t *testing.T) {
	scope := draftScopeFixture()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{65}, 32))
	session := access.Session{Cluster: scope.Root.Cluster, User: "manager", Key: [32]byte(key.Public().(ed25519.PublicKey)), ExpiresAt: 300}
	plan := DraftFreezePlan{Schema: 1, Scope: scope, ID: "save-one", Creator: session.User, Revision: 2, Draft: [32]byte{7}, CreatedAt: 100, ExpiresAt: 1000}
	proof := DraftProof{Schema: 1, Scope: scope.Digest(), Edit: plan.Digest(), At: 100, ExpiresAt: 200, Nonce: [32]byte{1}, Transfer: &DraftTransferProof{Kind: "freeze"}}
	proof.Signature = ed25519.Sign(key, DraftProofBytes(proof))
	q := DraftRequest{Context: scope.Context, Kind: "freeze", Scope: &scope, Freeze: &plan, Proof: &proof}
	if !q.Valid() || q.Authorize(scope, session, 101) != nil {
		t.Fatal("original freeze proof rejected")
	}
	for _, mutate := range []func(*DraftFreezePlan){
		func(p *DraftFreezePlan) { p.Revision++ }, func(p *DraftFreezePlan) { p.Draft[0] ^= 1 },
		func(p *DraftFreezePlan) { p.Creator = "other" }, func(p *DraftFreezePlan) { p.ExpiresAt++ },
	} {
		changed := plan
		mutate(&changed)
		bad := q
		bad.Freeze = &changed
		if bad.Valid() && bad.Authorize(scope, session, 101) == nil {
			t.Fatal("relay retargeted frozen snapshot")
		}
	}
	bad := q
	p := proof
	p.Transfer = &DraftTransferProof{Kind: "file-seal"}
	bad.Proof = &p
	if bad.Valid() {
		t.Fatal("file-seal proof reused for freeze")
	}
}
