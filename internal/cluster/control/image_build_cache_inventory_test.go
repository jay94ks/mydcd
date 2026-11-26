// SPDX-License-Identifier: Apache-2.0

package control

import (
	"fmt"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/imagebuild"
)

func TestCacheInventoryGroupsRealAcceptedJobsAndKeepsDeletedHistoryCacheVisible(t *testing.T) {
	f, plan := buildJobFixture(t)
	f.apply("manager", "begin-image-build", 0, plan.Change, state.Applied)
	q := ImageBuildQuery{Part: "caches", ID: "source", Node: "node-a"}
	page, err := f.p.ImageBuildPage(f.s, f.sessions["manager"], 2, "tenant", q, "")
	if err != nil || len(page.Caches) != 1 || !ValidImageBuildCacheInventoryPage(page, q, "", false) {
		t.Fatal(page, err)
	}
	root := *page.InventoryRoot
	buildJobReportFixture(t, f, ImageBuildJobReport{Job: plan.Spec.ID, Action: "begin"}, state.Applied)
	progress, err := f.p.ImageBuildPage(f.s, f.sessions["manager"], 3, "tenant", q, "")
	if err != nil || *progress.InventoryRoot != root || progress.RootRevision == page.RootRevision {
		t.Fatal("progress invalidated scope inventory", progress, err)
	}
	f.apply("manager", "cancel-image-build", 2, ImageBuildJobSelection{Tenant: "tenant", ID: plan.Spec.ID}, state.Applied)
	closure := buildJobClosure(f, plan.Spec, "CANCELLED")
	buildJobReportFixture(t, f, ImageBuildJobReport{Job: plan.Spec.ID, Action: "complete", Closure: &closure}, state.Applied)
	f.apply("manager", "delete-image-build-job", 4, ImageBuildJobSelection{Tenant: "tenant", ID: plan.Spec.ID}, state.Applied)
	page, err = f.p.ImageBuildPage(f.s, f.sessions["manager"], 4, "tenant", q, "")
	if err != nil || len(page.Caches) != 1 || !page.Caches[0].JobDeleted {
		t.Fatal("history deletion hid retained cache", page, err)
	}
	read := ImageBuildCacheInventoryRead{Session: f.sessions["manager"], Tenant: "tenant", Query: q, Root: *page.InventoryRoot, Cache: page.Caches[0].Cache, Epoch: page.Epoch}
	if spec, err := f.p.CurrentImageBuildCacheInventory(f.s, read, 4); err != nil || spec.Digest() != plan.Spec.Digest() {
		t.Fatal("retained scope lost native selection", spec.ID, err)
	}
	for _, edit := range []func(*ImageBuildCacheInventoryRead){func(r *ImageBuildCacheInventoryRead) { r.Tenant = "other" }, func(r *ImageBuildCacheInventoryRead) { r.Cache = [32]byte{99} }, func(r *ImageBuildCacheInventoryRead) { r.Epoch++ }, func(r *ImageBuildCacheInventoryRead) { r.Root = [32]byte{99} }} {
		bad := read
		edit(&bad)
		if _, err := f.p.CurrentImageBuildCacheInventory(f.s, bad, 4); err == nil {
			t.Fatal("foreign/changed inventory selection accepted")
		}
	}
	if _, err := f.p.CurrentImageBuildCacheInventory(f.s, read, 1002); err == nil {
		t.Fatal("expired user read inventory")
	}
	second, err := f.p.ImageBuildJobPlan(f.s, f.sessions["manager"], 2, "tenant", ImageBuildJobQuery{ID: "build-two", Context: "source", Version: plan.Spec.Version})
	if err != nil {
		t.Fatal(err)
	}
	f.apply("manager", "begin-image-build", 0, second.Change, state.Applied)
	page, err = f.p.ImageBuildPage(f.s, f.sessions["manager"], 4, "tenant", q, "")
	if err != nil || len(page.Caches) != 1 || page.Caches[0].RepresentativeJob != "build-two" || page.Caches[0].Cache != imagebuild.CacheIdentity(plan.Spec) {
		t.Fatal("same scope double counted", page, err)
	}
}

// Inject a catalogue at the projection boundary to isolate grouping/paging.
// Full signed reducer/current-session behavior is exercised above.
func TestCacheInventoryProjectionPagesDistinctScopesAndReportsUnavailablePerRow(t *testing.T) {
	f, plan := buildJobFixture(t)
	c, err := f.p.Catalog(f.s)
	if err != nil {
		t.Fatal(err)
	}
	current, err := f.p.Current(f.s)
	if err != nil {
		t.Fatal(err)
	}
	var b ImageBuildCatalog
	for i := 0; i < 7; i++ {
		spec := plan.Spec.Own()
		spec.ID = fmt.Sprintf("job-%d", i)
		spec.Policy.BuilderImage = fmt.Sprintf("docker.io/moby/buildkit@sha256:%064x", i+1)
		b.Jobs = append(b.Jobs, ImageBuildJobRecord{Run: imagebuild.JobRun{Spec: spec}})
	}
	q := ImageBuildQuery{Part: "caches"}
	page, err := current.imageBuildCacheInventoryPage(f.s, c, b, f.sessions["manager"], 2, "tenant", q, "")
	if err != nil || len(page.Caches) != ImageBuildCacheInventoryRows || page.Next == "" {
		t.Fatal(page, err)
	}
	last, err := current.imageBuildCacheInventoryPage(f.s, c, b, f.sessions["manager"], 2, "tenant", q, page.Next)
	if err != nil || len(last.Caches) != 3 || last.Next != "" || page.Caches[len(page.Caches)-1].Key() >= last.Caches[0].Key() {
		t.Fatal(last, err)
	}
	for i := range page.Caches {
		page.Caches[i].Code = "UNAVAILABLE"
	}
	if !ValidImageBuildCacheInventoryPage(page, q, "", true) {
		t.Fatal("node failure could not be reported without fake usage0")
	}
	page.Caches[0].Usage = &imagebuild.CacheSummary{Schema: 1, Cache: page.Caches[0].Cache}
	if ValidImageBuildCacheInventoryPage(page, q, "", true) {
		t.Fatal("unavailable owner returned invented usage")
	}
	b.Jobs = b.Jobs[:6]
	if _, err := current.imageBuildCacheInventoryPage(f.s, c, b, f.sessions["manager"], 2, "tenant", q, page.Next); err == nil {
		t.Fatal("changed catalogue accepted old cursor")
	}
}
