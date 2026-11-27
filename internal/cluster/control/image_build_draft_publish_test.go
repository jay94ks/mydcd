// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/imagebuild"
)

// Native evidence is injected here. Actual archive/inode behavior is covered
// by the DraftStore tests and the final RQ6 full user-path validation.
func draftPublicationFixture(t *testing.T) (*nodeStorageFixture, ImageBuildDraftPublish) {
	t.Helper()
	f, spec := imageBuildFixture(t)
	spec.ID, spec.Kind = "editable", "draft"
	f.apply("manager", "put-build-context", 0, ImageBuildContextPut{Spec: spec}, state.Applied)
	b, err := f.p.ImageBuilds(f.s)
	if err != nil {
		t.Fatal(err)
	}
	context, _ := b.Context("tenant", spec.ID)
	policy, _ := b.Policy("tenant")
	plan := imagebuild.DraftFreezePlan{Schema: 1, Scope: imagebuild.DraftScope{Schema: 1, Tenant: "tenant", Context: spec.ID, Root: spec.Root, ContextRevision: context.Revision, PolicyRevision: policy.Revision, Dockerfile: spec.Dockerfile, ExpandedLimit: policy.Spec.WorkspaceBytes}, ID: "save-one", Creator: "manager", Revision: 2, Draft: [32]byte{7}, CreatedAt: 1, ExpiresAt: 1000}
	scope := plan.ArchiveScope(100, [32]byte{8})
	fact := imagebuild.SealReceipt{Schema: 1, Scope: scope.Hash(), ZIP: scope.Digest, Tree: [32]byte{9}, Entries: 1, ExpandedBytes: 13}
	fact.Signature = ed25519.Sign(f.node, imagebuild.SealReceiptBytes(fact))
	frozen := imagebuild.FrozenDraft{Schema: 1, Plan: plan, Scope: scope, Fact: fact}
	frozen.Signature = ed25519.Sign(f.node, imagebuild.FrozenDraftBytes(frozen))
	return f, ImageBuildDraftPublish{Tenant: "tenant", Context: spec.ID, Frozen: frozen}
}

func TestPublishDraftAtomicallyKeepsClosedArchiveVersionAndRestore(t *testing.T) {
	f, q := draftPublicationFixture(t)
	f.apply("manager", "publish-build-draft", q.Frozen.Plan.Revision, q, state.Applied)
	b, err := f.p.ImageBuilds(f.s)
	if err != nil {
		t.Fatal(err)
	}
	u, ok := b.Upload("tenant", q.Frozen.Scope.Upload)
	if !ok || !u.Closed || u.Received != 0 || u.Version != imagebuild.VersionID(q.Frozen.Fact) || !b.ArtifactReferenced(u) {
		t.Fatal("closed artifact reference", u)
	}
	if len(f.s.Objects(buildPartPrefix("tenant", u.Scope.Upload))) != 0 {
		t.Fatal("generated archive created fake part slots")
	}
	v, ok := b.Version("tenant", u.Version)
	context, _ := b.Context("tenant", q.Context)
	if !ok || v.Number != 1 || context.NextVersion != 1 || !validBuildVersionOrigin(v, u, f.p.Cluster) {
		t.Fatal("version publication", v)
	}
	f.apply("manager", "publish-build-draft", q.Frozen.Plan.Revision, q, state.ConditionFailed)
	raw, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := state.Decode(raw)
	if err != nil || f.p.Validate(state.State{}, restored, state.Command{}) != nil {
		t.Fatal("generated version restore", err)
	}
	f.apply("manager", "delete-build-version", 1, ImageBuildVersionSelection{Tenant: "tenant", ID: v.ID}, state.Applied)
	b, err = f.p.ImageBuilds(f.s)
	if err != nil || b.ArtifactReferenced(u) {
		t.Fatal("deleted version still referenced without a job", err)
	}
	work, err := f.p.ImageBuildArtifactWork(f.s, q.Frozen.Scope.Root.Key, ImageBuildArtifactSelection{Tenant: "tenant", Upload: q.Frozen.Scope.Upload})
	if err != nil || !work.Reclaim {
		t.Fatal("same artifact cleanup policy not reused", err)
	}
}

func TestPublishDraftRejectsChangedContextOrWrongRevision(t *testing.T) {
	f, q := draftPublicationFixture(t)
	f.apply("manager", "publish-build-draft", q.Frozen.Plan.Revision+1, q, state.Invalid)
	b, _ := f.p.ImageBuilds(f.s)
	context, _ := b.Context("tenant", q.Context)
	changed := context.Spec.Own()
	changed.Arguments = map[string]string{"MODE": "new"}
	f.apply("manager", "put-build-context", context.Revision, ImageBuildContextPut{Spec: changed}, state.Applied)
	f.apply("manager", "publish-build-draft", q.Frozen.Plan.Revision, q, state.ConditionFailed)
	b, err := f.p.ImageBuilds(f.s)
	if err != nil || len(b.Versions) != 0 || len(b.Uploads) != 0 {
		t.Fatal("failed publication left shared reservations", err)
	}
}
