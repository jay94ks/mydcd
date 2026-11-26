// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/imagebuild"
)

// Real shared context/policy/permission changes. The original native archive
// facts are injected by the publication fixture, not actual filesystem proof.
func TestGeneratedResultAllowsExpiredOriginalPlanButNotSavingAcrossConfigurationDeletion(t *testing.T) {
	for _, kind := range []string{"draft", "git"} {
		t.Run(kind, func(t *testing.T) {
			f, a, _ := generatedControlFixture(t, kind)
			book, _ := f.p.ImageBuilds(f.s)
			context, _ := book.Context(a.Scope.Tenant, a.Scope.Context)
			context.Spec.Tags = []string{"changed"}
			f.apply("manager", "put-build-context", context.Revision, ImageBuildContextPut{Spec: context.Spec}, state.Applied)
			session := f.sessions["manager"]
			for _, deleted := range []bool{false, true} {
				if deleted {
					f.apply("manager", "delete-build-context", context.Revision+1, ImageBuildSelection{Tenant: a.Scope.Tenant, ID: a.Scope.Context}, state.Applied)
				}
				if a.Draft != nil {
					proof := imagebuild.DraftProof{Schema: 1, Scope: a.Draft.Scope.Digest(), Edit: a.Draft.Digest(), At: 1000, ExpiresAt: 1001, Nonce: [32]byte{1}, Transfer: &imagebuild.DraftTransferProof{Kind: "freeze-result"}}
					proof.Signature = ed25519.Sign(f.manager, imagebuild.DraftProofBytes(proof))
					call := ImageBuildDraftCall{Session: session, Tenant: a.Scope.Tenant, At: 1000, Request: imagebuild.DraftRequest{Context: a.Scope.Context, Kind: "freeze-result", Scope: &a.Draft.Scope, Freeze: a.Draft, Proof: &proof}}
					work, err := f.p.ImageBuildDraftWork(f.s, call)
					if err != nil || work.Scope != a.Draft.Scope || work.Root.Generation != 0 {
						t.Fatal("historical freeze result retargeted/denied", work, err)
					}
					bad := call
					bad.Request.Kind = "freeze"
					if _, err := f.p.ImageBuildDraftWork(f.s, bad); err == nil {
						t.Fatal("result permission/proof reexecuted freeze")
					}
					bad = call
					bad.Session.Scopes = []access.Scope{{Tenant: a.Scope.Tenant, Actions: []access.Action{access.Read}}}
					bad.Session.Signature = ed25519.Sign(f.node, access.SessionBytes(bad.Session))
					if _, err := f.p.ImageBuildDraftWork(f.s, bad); err == nil {
						t.Fatal("read-only session gained historical source evidence")
					}
				} else {
					proof := imagebuild.GitSaveProof{Schema: 1, Plan: a.Git.Digest(), At: 1000, ExpiresAt: 1001, Nonce: [32]byte{1}, Result: true}
					proof.Signature = ed25519.Sign(f.manager, imagebuild.GitSaveProofBytes(proof))
					call := ImageBuildGitCall{Session: session, Tenant: a.Scope.Tenant, At: 1000, Request: imagebuild.GitSaveRequest{Plan: *a.Git, Proof: proof, Result: true}}
					work, err := f.p.ImageBuildGitWork(f.s, call)
					if err != nil || work.Read.Spec.Root != a.Scope.Root || work.Root.Generation != 0 {
						t.Fatal("historical Git result denied/required placement", work, err)
					}
					bad := call
					bad.Request.Result = false
					if _, err := f.p.ImageBuildGitWork(f.s, bad); err == nil {
						t.Fatal("result proof reexecuted Git save")
					}
					bad = call
					bad.Session.Scopes = []access.Scope{{Tenant: a.Scope.Tenant, Actions: []access.Action{access.Read}}}
					bad.Session.Signature = ed25519.Sign(f.node, access.SessionBytes(bad.Session))
					if _, err := f.p.ImageBuildGitWork(f.s, bad); err == nil {
						t.Fatal("read-only session gained historical Git evidence")
					}
				}
			}
		})
	}
}
