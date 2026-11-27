// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/imagebuild"
)

func TestDraftResultUsesCurrentPermissionAndOriginalReadProofAcrossConfigurationDeletion(t *testing.T) {
	f, publication := draftPublicationFixture(t)
	scope := publication.Frozen.Plan.Scope
	edit := imagebuild.DraftEdit{ID: "original", Kind: "mkdir", Path: "source", Expected: 1}
	proof := imagebuild.DraftProof{Schema: 1, Scope: scope.Digest(), Edit: edit.Digest(), At: 2, ExpiresAt: 100, Nonce: [32]byte{1}, Transfer: &imagebuild.DraftTransferProof{Kind: "result"}}
	proof.Signature = ed25519.Sign(f.manager, imagebuild.DraftProofBytes(proof))
	call := ImageBuildDraftCall{Session: f.sessions["manager"], Tenant: scope.Tenant, At: 2, Request: imagebuild.DraftRequest{Context: scope.Context, Kind: "result", Scope: &scope, Edit: &edit, Proof: &proof}}
	book, _ := f.p.ImageBuilds(f.s)
	context, _ := book.Context(scope.Tenant, scope.Context)
	context.Spec.Tags = []string{"changed"}
	f.apply("manager", "put-build-context", context.Revision, ImageBuildContextPut{Spec: context.Spec}, state.Applied)
	for _, deleted := range []bool{false, true} {
		if deleted {
			f.apply("manager", "delete-build-context", context.Revision+1, ImageBuildSelection{Tenant: scope.Tenant, ID: scope.Context}, state.Applied)
		}
		work, err := f.p.ImageBuildDraftWork(f.s, call)
		if err != nil || work.Scope != scope || work.Root.Generation != 0 {
			t.Fatal("metadata result was retargeted or required a new root", work, err)
		}
		bad := call
		bad.Request = call.Request
		p := proof
		p.Transfer = nil // An edit-purpose signature cannot authorize result reads.
		bad.Request.Proof = &p
		if _, err := f.p.ImageBuildDraftWork(f.s, bad); err == nil {
			t.Fatal("mixed proof purpose accepted")
		}
		bad = call
		bad.Session.Scopes = []access.Scope{{Tenant: scope.Tenant, Actions: []access.Action{access.Read}}}
		bad.Session.Signature = ed25519.Sign(f.node, access.SessionBytes(bad.Session))
		if _, err := f.p.ImageBuildDraftWork(f.s, bad); err == nil {
			t.Fatal("read-only/replaced actor gained source result access")
		}
		bad = call
		bad.At = 100
		if _, err := f.p.ImageBuildDraftWork(f.s, bad); err == nil {
			t.Fatal("expired result proof accepted")
		}
		bad = call
		future := scope
		future.ContextRevision = 100
		p = proof
		p.Scope = future.Digest()
		p.Signature = ed25519.Sign(f.manager, imagebuild.DraftProofBytes(p))
		bad.Request.Scope, bad.Request.Proof = &future, &p
		if _, err := f.p.ImageBuildDraftWork(f.s, bad); err == nil {
			t.Fatal("signed local-ahead scope treated as a historical result")
		}
	}
}
