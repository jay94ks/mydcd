// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/imagecache"
)

// Real UserOperation/reducer/checkpoint and source/queue fences. No native
// deletion or owner completion is fabricated by these admission tests.
func TestCachePruneAdmissionKeepsOriginalSourceAndOrdersBeforeOnlyLaterBuilds(t *testing.T) {
	f, plan := buildJobFixture(t)
	f.apply("manager", "begin-image-build", 0, plan.Change, state.Applied)
	change := ImageBuildCachePruneChange{Tenant: "tenant", ID: "clear-one", Node: "node-a", Cache: imagebuild.CacheIdentity(plan.Spec), Filter: imagebuild.CachePruneFilter{Mode: "all"}}
	bad := change
	bad.Cache = [32]byte{99}
	f.apply("manager", ImageBuildCachePruneAction, 0, bad, state.ConditionFailed)
	original := f.sessions["manager"]
	read := original
	read.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read}}}
	read.Signature = ed25519.Sign(f.node, access.SessionBytes(read))
	f.sessions["manager"] = read
	f.apply("manager", ImageBuildCachePruneAction, 0, change, state.Forbidden)
	f.sessions["manager"] = original
	f.apply("manager", ImageBuildCachePruneAction, 0, change, state.Applied)
	b, err := f.p.ImageBuilds(f.s)
	if err != nil || len(b.CachePrunes) != 1 || b.CachePrunes[0].Source != plan.Spec.ID || b.CachePrunes[0].SourceDigest != plan.Spec.Digest() || b.CachePrunes[0].State != "queued" {
		t.Fatal(b.CachePrunes, err)
	}
	f.apply("manager", ImageBuildCachePruneAction, 0, change, state.ConditionFailed)
	bad = change
	bad.ID = "competing"
	f.apply("manager", ImageBuildCachePruneAction, 0, bad, state.ConditionFailed)
	before, err := f.p.ImageBuildJobWork(f.s, plan.Spec.Scope.Root.Key, ImageBuildJobWorkQuery{Tenant: "tenant", ID: plan.Spec.ID, At: 3})
	if err != nil || !before.Allowed {
		t.Fatal("earlier queued build deadlocked", before.Blocked, err)
	}
	work, err := f.p.ImageBuildCachePruneWork(f.s, plan.Spec.Scope.Root.Key, ImageBuildCachePruneWorkQuery{Tenant: "tenant", ID: change.ID, At: 3})
	if err != nil || work.Allowed || work.Blocked != "WAITING_FOR_CACHE" {
		t.Fatal(work.Blocked, err)
	}
	grant, err := work.NativeGrant()
	if err != nil || grant.Spec.Intent != work.Record.Digest() || grant.Spec.Source.Digest() != plan.Spec.Digest() || grant.Allowed {
		t.Fatal("maintenance became a fake/replacement build", grant, err)
	}
	changed := work
	changed.Source = work.Source.Own()
	changed.Source.ID = "replacement"
	if _, err := changed.NativeGrant(); err == nil {
		t.Fatal("changed source became native grant")
	}
	buildJobReportFixture(t, f, ImageBuildJobReport{Job: plan.Spec.ID, Action: "begin"}, state.Applied)
	later, err := f.p.ImageBuildJobPlan(f.s, original, 2, "tenant", ImageBuildJobQuery{ID: "later", Context: "source", Version: plan.Spec.Version})
	if err != nil {
		t.Fatal(err)
	}
	f.apply("manager", "begin-image-build", 0, later.Change, state.Applied)
	blocked, err := f.p.ImageBuildJobWork(f.s, plan.Spec.Scope.Root.Key, ImageBuildJobWorkQuery{Tenant: "tenant", ID: "later", At: 3})
	if err != nil || blocked.Allowed || blocked.Blocked != "WAITING_FOR_CACHE" {
		t.Fatal("later build bypassed original cleanup", blocked.Blocked, err)
	}
	f.apply("manager", "cancel-image-build", 2, ImageBuildJobSelection{Tenant: "tenant", ID: plan.Spec.ID}, state.Applied)
	closure := buildJobClosure(f, plan.Spec, "CANCELLED")
	buildJobReportFixture(t, f, ImageBuildJobReport{Job: plan.Spec.ID, Action: "complete", Closure: &closure}, state.Applied)
	work, err = f.p.ImageBuildCachePruneWork(f.s, plan.Spec.Scope.Root.Key, ImageBuildCachePruneWorkQuery{Tenant: "tenant", ID: change.ID, At: 4})
	if err != nil || !work.Allowed || work.Source.Digest() != plan.Spec.Digest() {
		t.Fatal("later queue blocked cleanup", work.Blocked, err)
	}
	page, err := f.p.ImageBuildPage(f.s, original, 4, "tenant", ImageBuildQuery{Part: "cache-prunes", Node: "node-a"}, "")
	if err != nil || len(page.CachePrunes) != 1 || page.CachePrunes[0].State != "queued" {
		t.Fatal(page, err)
	}
	b, err = f.p.ImageBuilds(f.s)
	if err != nil {
		t.Fatal(err)
	}
	without := b
	without.CachePrunes = nil
	if b.RootReferences(plan.Spec.Scope.Root) != without.RootReferences(plan.Spec.Scope.Root)+1 || f.p.storageQuiescent(f.s) {
		t.Fatal("pending cleanup lost original root/window fence")
	}
	raw, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := state.Decode(raw)
	if err != nil || f.p.Validate(state.State{}, restored, state.Command{}) != nil {
		t.Fatal("cleanup checkpoint/source restore rejected", err)
	}
	row := b.CachePrunes[0]
	row.SourceDigest = [32]byte{99}
	if validateImageBuildCachePrune(b, row, f.p.Cluster, true) == nil {
		t.Fatal("changed original source accepted")
	}
	if _, err := f.p.ImageBuildCachePruneWork(f.s, [32]byte{99}, ImageBuildCachePruneWorkQuery{Tenant: "tenant", ID: change.ID, At: 4}); err == nil {
		t.Fatal("foreign owner received source/work")
	}
}

func TestCachePruneInputAndLegacyEmptyRootRemainCanonical(t *testing.T) {
	q := ImageBuildCachePruneChange{Tenant: "tenant", ID: "clear", Node: "node-a", Cache: [32]byte{1}, Filter: imagebuild.CachePruneFilter{Mode: "unused", UnusedDays: 7}}
	payload, _ := json.Marshal(q)
	raw, _ := json.Marshal(ChangeDocument{Schema: 1, Action: ImageBuildCachePruneAction, Payload: payload})
	change, err := InputChange(raw, "manager")
	if err != nil || change.Action != ImageBuildCachePruneAction || CommandKey(change.Action) != ImageBuildKey {
		t.Fatal(change, err)
	}
	root, err := (ImageBuildCatalog{}).root([32]byte{1})
	if err != nil || strings.Contains(string(root), "CachePrunes") {
		t.Fatal("legacy optional-zero root bytes changed", string(root), err)
	}
}

func TestCachePruneAndNodeImageDeletionFenceEachOtherWithDeletedSourceHistory(t *testing.T) {
	for _, pruneFirst := range []bool{true, false} {
		t.Run(map[bool]string{true: "prune-first", false: "image-delete-first"}[pruneFirst], func(t *testing.T) {
			f, plan := buildJobFixture(t)
			f.apply("manager", "begin-image-build", 0, plan.Change, state.Applied)
			f.apply("manager", "cancel-image-build", 1, ImageBuildJobSelection{Tenant: "tenant", ID: plan.Spec.ID}, state.Applied)
			closure := buildJobClosure(f, plan.Spec, "CANCELLED")
			buildJobReportFixture(t, f, ImageBuildJobReport{Job: plan.Spec.ID, Action: "complete", Closure: &closure}, state.Applied)
			f.apply("manager", "delete-image-build-job", 3, ImageBuildJobSelection{Tenant: "tenant", ID: plan.Spec.ID}, state.Applied)
			change := ImageBuildCachePruneChange{Tenant: "tenant", ID: "clear", Node: "node-a", Cache: imagebuild.CacheIdentity(plan.Spec), Filter: imagebuild.CachePruneFilter{Mode: "all"}}
			id := "sha256:" + strings.Repeat("b", 64)
			deletion := imagecache.Plan{Schema: 1, Cluster: f.p.Cluster, Owner: plan.Spec.Scope.Root.Key, Boot: [32]byte{1}, Node: "node-a", At: 2500, Index: f.s.Index(), Selection: []string{id}, Images: []imagecache.Image{{ID: id, Bytes: 128, Aliases: []string{plan.Spec.Policy.BuilderImage}}}}
			deletion.Signature = ed25519.Sign(f.node, imagecache.PlanBytes(deletion))
			if !deletion.DeleteReady() {
				t.Fatal("invalid native image-delete fixture")
			}
			if pruneFirst {
				f.apply("manager", ImageBuildCachePruneAction, 0, change, state.Applied)
				refs, err := f.p.ImageReferences(f.s, "tenant", "node-a")
				if err != nil || len(refs) != 1 || !refs[0].Valid() || refs[0].Kind != "image-build-cache-prune" || refs[0].Operation != "clear" || refs[0].Image != plan.Spec.Policy.BuilderImage {
					t.Fatal("deleted source lost pending maintenance image", refs, err)
				}
				f.apply("admin", "prune-node-images", 0, imagecache.Change{Operation: "delete-builder", Plan: deletion}, state.ConditionFailed)
			} else {
				f.apply("admin", "prune-node-images", 0, imagecache.Change{Operation: "delete-builder", Plan: deletion}, state.Applied)
				f.apply("manager", ImageBuildCachePruneAction, 0, change, state.ConditionFailed)
			}
		})
	}
}

func TestCachePruneQueryKeepsOperationNodeAndCursorScopesSeparate(t *testing.T) {
	q := ImageBuildQuery{Part: "cache-prunes", ID: "clear", Node: "node-a"}
	if !q.Valid() {
		t.Fatal("valid prune query rejected")
	}
	for _, bad := range []ImageBuildQuery{{Part: "cache-prunes", Job: "job"}, {Part: "cache-prunes", Upload: "upload"}, {Part: "cache-prunes", ID: "../clear"}, {Part: "cache-prunes", Node: "../node"}} {
		if bad.Valid() {
			t.Fatal("mixed cache-prune selector accepted", bad)
		}
	}
	f, _ := buildJobFixture(t)
	snapshot := imageBuildCursor(f.p.Cluster, f.s, "tenant", q)
	for _, other := range []ImageBuildQuery{{Part: "cache-prunes", ID: "other", Node: "node-a"}, {Part: "cache-prunes", ID: "clear", Node: "node-b"}, {Part: "caches", ID: "clear", Node: "node-a"}} {
		if imageBuildCursor(f.p.Cluster, f.s, "tenant", other) == snapshot {
			t.Fatal("cursor did not bind query", other)
		}
	}
	if _, err := f.p.ImageBuildPage(f.s, f.sessions["manager"], 2, "tenant", ImageBuildQuery{Part: "cache-prunes", Node: "node-b"}, ""); err == nil {
		t.Fatal("explicit unauthorized node read hidden as empty success")
	}
}
