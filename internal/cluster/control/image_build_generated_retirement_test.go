// SPDX-License-Identifier: Apache-2.0

package control

import (
	"errors"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/reconcile"
)

func generatedControlFixture(t *testing.T, kind string) (*nodeStorageFixture, imagebuild.GeneratedArtifact, func(state.Code)) {
	t.Helper()
	if kind == "draft" {
		f, q := draftPublicationFixture(t)
		a := imagebuild.GeneratedArtifact{Scope: q.Frozen.Scope, Draft: &q.Frozen.Plan}
		return f, a, func(code state.Code) { f.apply("manager", "publish-build-draft", q.Frozen.Plan.Revision, q, code) }
	}
	f, q := gitPublicationFixture(t)
	a := imagebuild.GeneratedArtifact{Scope: q.Saved.Scope, Git: &q.Saved.Plan}
	return f, a, func(code state.Code) { f.apply("manager", "publish-build-git", q.Saved.Plan.ContextRevision, q, code) }
}

// Real FSM/operation/restore fences; native receipts are fixture inputs, not
// evidence that the filesystem or RootManager has finished deletion.
func TestUnpublishedGeneratedArchiveGrantRequiresFenceAndExcludesCommittedUpload(t *testing.T) {
	for _, kind := range []string{"draft", "git"} {
		for _, published := range []bool{false, true} {
			t.Run(kind+"/"+map[bool]string{false: "unpublished", true: "published"}[published], func(t *testing.T) {
				f, a, publish := generatedControlFixture(t, kind)
				owner := a.Scope.Root.Key
				if _, err := f.p.ImageBuildGeneratedArchiveGrant(f.s, owner, a); !errors.Is(err, reconcile.ErrPending) {
					t.Fatal("current publishable archive eligible", err)
				}
				if _, err := f.p.ImageBuildGeneratedArchiveGrant(f.s, [32]byte{99}, a); !errors.Is(err, access.ErrDenied) {
					t.Fatal("foreign cleanup owner", err)
				}
				if published {
					publish(state.Applied)
				}
				book, _ := f.p.ImageBuilds(f.s)
				policy, _ := book.Policy(a.Scope.Tenant)
				policy.Spec.Cleanup.UnusedDays++
				f.apply("manager", "set-image-build-policy", policy.Revision, ImageBuildPolicyPut{Spec: policy.Spec}, state.Applied)
				g, err := f.p.ImageBuildGeneratedArchiveGrant(f.s, owner, a)
				if published {
					if !errors.Is(err, imagebuild.ErrUsed) {
						t.Fatal("published archive bypassed existing reference/owner closure", err)
					}
					collision := a
					collision.Scope.Length++
					if _, err := f.p.ImageBuildGeneratedArchiveGrant(f.s, owner, collision); !errors.Is(err, access.ErrConflict) {
						t.Fatal("same ID/different scope ignored", err)
					}
					return
				}
				if err != nil || !g.Valid() || g.Artifact.Digest() != a.Digest() || g.Index != f.s.Index() || g.Epoch != f.s.ModuleEpoch() {
					t.Fatal("monotonic fence not derived", g, err)
				}
				publish(state.ConditionFailed)
				raw, err := state.Encode(f.s)
				if err != nil {
					t.Fatal(err)
				}
				restored, err := state.Decode(raw)
				if err != nil {
					t.Fatal(err)
				}
				again, err := f.p.ImageBuildGeneratedArchiveGrant(restored, owner, a)
				if err != nil || !again.Valid() || again.Artifact.Digest() != a.Digest() || again.ContextRevision != g.ContextRevision || again.PolicyRevision != g.PolicyRevision {
					t.Fatal("restore lost original publication fence", again, err)
				}
			})
		}
	}
}
