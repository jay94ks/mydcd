// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/imagebuild"
)

// Operational node evidence is injected. This fixture proves the shared
// reducer/signatures/restore contract, not native Git/ZIP/Docker execution.
func gitPublicationFixture(t *testing.T) (*nodeStorageFixture, ImageBuildGitPublish) {
	t.Helper()
	f, spec := imageBuildFixture(t)
	spec.ID, spec.Kind = "git-source", "git"
	spec.Git = &imagebuild.GitContext{Repository: "https://git.example.test/team/app.git", Ref: "refs/heads/main", Path: "."}
	spec.Tags = []string{"git-{commit}"}
	f.apply("manager", "put-build-context", 0, ImageBuildContextPut{Spec: spec}, state.Applied)
	b, err := f.p.ImageBuilds(f.s)
	if err != nil {
		t.Fatal(err)
	}
	context, _ := b.Context("tenant", spec.ID)
	policy, _ := b.Policy("tenant")
	plan := imagebuild.GitSavePlan{Schema: 1, Tenant: "tenant", Context: spec.ID, ID: "git-save-one", Creator: "manager", Root: spec.Root, ContextRevision: context.Revision, PolicyRevision: policy.Revision, Dockerfile: spec.Dockerfile, ExpandedLimit: policy.Spec.WorkspaceBytes, Commit: strings.Repeat("a", 40), Tree: [32]byte{7}, CreatedAt: 1, ExpiresAt: 1000}
	return f, ImageBuildGitPublish{Tenant: "tenant", Context: spec.ID, Saved: gitSavedFactFixture(f, plan)}
}
func gitSavedFactFixture(f *nodeStorageFixture, plan imagebuild.GitSavePlan) imagebuild.SavedGit {
	scope := plan.ArchiveScope(100, [32]byte{8})
	fact := imagebuild.SealReceipt{Schema: 1, Scope: scope.Hash(), ZIP: scope.Digest, Tree: plan.Tree, Entries: 1, ExpandedBytes: 13}
	fact.Signature = ed25519.Sign(f.node, imagebuild.SealReceiptBytes(fact))
	saved := imagebuild.SavedGit{Schema: 1, Plan: plan, Scope: scope, Fact: fact}
	saved.Signature = ed25519.Sign(f.node, imagebuild.SavedGitBytes(saved))
	return saved
}

func TestGitPublicationKeepsCommitVersionArtifactAndJobInputAtomic(t *testing.T) {
	f, q := gitPublicationFixture(t)
	f.apply("manager", "publish-build-git", q.Saved.Plan.ContextRevision, q, state.Applied)
	b, err := f.p.ImageBuilds(f.s)
	if err != nil {
		t.Fatal(err)
	}
	u, ok := b.Upload(q.Tenant, q.Saved.Scope.Upload)
	if !ok || !u.Closed || u.Received != 0 || u.Version != imagebuild.VersionID(q.Saved.Fact) || !b.ArtifactReferenced(u) || len(f.s.Objects(buildPartPrefix(q.Tenant, u.Scope.Upload))) != 0 {
		t.Fatal("generated Git archive did not use original closed artifact contract")
	}
	v, ok := b.Version(q.Tenant, u.Version)
	context, _ := b.Context(q.Tenant, q.Context)
	if !ok || v.Commit != q.Saved.Plan.Commit || v.Number != 1 || context.NextVersion != 1 || !validBuildVersionOrigin(v, u, f.p.Cluster) {
		t.Fatal("Git commit/version/next number not atomic")
	}
	bad := v
	bad.Commit = strings.Repeat("b", 40)
	if validBuildVersionOrigin(bad, u, f.p.Cluster) {
		t.Fatal("version commit detached from original publication")
	}
	registryReportFixture(t, f, RegistryReport{Tenant: "tenant", ID: "private", Action: "reserve", SpecRevision: 1, Generation: 1}, state.Applied)
	plan, err := f.p.ImageBuildJobPlan(f.s, f.sessions["manager"], 2, "tenant", ImageBuildJobQuery{ID: "build-git", Context: q.Context, Version: v.ID})
	if err != nil || plan.Spec.Commit != v.Commit {
		t.Fatal("preserved commit not supplied to job", err)
	}
	tags, err := plan.Spec.OutputTags()
	if err != nil || len(tags) != 1 || !strings.HasSuffix(tags[0], ":git-"+v.Commit) {
		t.Fatal("job tag not fixed to preserved commit", tags, err)
	}
	raw, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := state.Decode(raw)
	if err != nil || f.p.Validate(state.State{}, restored, state.Command{}) != nil {
		t.Fatal("Git publication restore", err)
	}
	f.apply("manager", "publish-build-git", q.Saved.Plan.ContextRevision, q, state.ConditionFailed)
	f.apply("manager", "delete-build-version", v.Number, ImageBuildVersionSelection{Tenant: q.Tenant, ID: v.ID}, state.Applied)
	b, err = f.p.ImageBuilds(f.s)
	if err != nil || b.ArtifactReferenced(u) {
		t.Fatal("Git version did not reuse deletion/GC references", err)
	}
}

func TestGitPublicationRejectsWrongCreatorExpiredOrChangedPolicy(t *testing.T) {
	for _, kind := range []string{"creator", "expired", "policy", "revision", "tree"} {
		t.Run(kind, func(t *testing.T) {
			f, q := gitPublicationFixture(t)
			actor := "manager"
			expected := q.Saved.Plan.ContextRevision
			want := state.Invalid
			switch kind {
			case "creator":
				actor = "admin"
			case "expired":
				p := q.Saved.Plan
				p.ExpiresAt = 2
				q.Saved = gitSavedFactFixture(f, p)
			case "policy":
				b, _ := f.p.ImageBuilds(f.s)
				policy, _ := b.Policy(q.Tenant)
				policy.Spec.CPUMillis *= 2
				f.apply("manager", "set-image-build-policy", policy.Revision, ImageBuildPolicyPut{Spec: policy.Spec}, state.Applied)
				want = state.ConditionFailed
			case "revision":
				expected++
			case "tree":
				q.Saved.Plan.Tree[0] ^= 1
				want = state.Forbidden
			}
			f.apply(actor, "publish-build-git", expected, q, want)
			b, err := f.p.ImageBuilds(f.s)
			if err != nil || len(b.Versions) != 0 || len(b.Uploads) != 0 {
				t.Fatal("rejected Git save published partial state", err)
			}
		})
	}
}
