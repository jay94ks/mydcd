// SPDX-License-Identifier: Apache-2.0

package control

import (
	"fmt"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/imagebuild"

	bkclient "github.com/moby/buildkit/client"
)

func TestCacheScopeReadSurvivesDeletedJobAndRepresentativeChangeWithoutRelaxingJobCursor(t *testing.T) {
	f, plan := buildJobFixture(t)
	f.apply("manager", "begin-image-build", 0, plan.Change, state.Applied)
	f.apply("manager", "cancel-image-build", 1, ImageBuildJobSelection{Tenant: "tenant", ID: plan.Spec.ID}, state.Applied)
	closure := buildJobClosure(f, plan.Spec, "CANCELLED")
	buildJobReportFixture(t, f, ImageBuildJobReport{Job: plan.Spec.ID, Action: "complete", Closure: &closure}, state.Applied)
	f.apply("manager", "delete-image-build-job", 3, ImageBuildJobSelection{Tenant: "tenant", ID: plan.Spec.ID}, state.Applied)
	cache := imagebuild.CacheIdentity(plan.Spec)
	q := imagebuild.CacheQuery{Cache: &cache, Node: plan.Spec.Scope.Root.Node}
	read, err := f.p.ImageBuildCacheRead(f.s, f.sessions["manager"], 4, "tenant", q, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.p.ImageBuildCacheRead(f.s, f.sessions["manager"], 4, "tenant", imagebuild.CacheQuery{Job: plan.Spec.ID}, ""); err == nil {
		t.Fatal("scope read silently reopened deleted job history")
	}
	var rows []*bkclient.UsageInfo
	for i := 0; i < imagebuild.CachePageItems+1; i++ {
		rows = append(rows, &bkclient.UsageInfo{ID: fmt.Sprintf("record-%03d", i), Size: 1})
	}
	u, err := imagebuild.NewCacheUsage(plan.Spec, 5, rows)
	if err != nil {
		t.Fatal(err)
	}
	first, err := u.Page(0, [32]byte{}, false)
	if err != nil {
		t.Fatal(err)
	}
	out, err := read.Page(first)
	if err != nil || out.CacheScope == nil || *out.CacheScope != cache || out.Next == "" {
		t.Fatal(out, err)
	}
	_, binding, _, _, err := ImageBuildCacheOffset(out.Next)
	if err != nil || binding != cache {
		t.Fatal("scope cursor bound to representative job", binding, err)
	}
	read.After = out.Next
	newPlan, err := f.p.ImageBuildJobPlan(f.s, f.sessions["manager"], 2, "tenant", ImageBuildJobQuery{ID: "build-two", Context: "source", Version: plan.Spec.Version})
	if err != nil {
		t.Fatal(err)
	}
	f.apply("manager", "begin-image-build", 0, newPlan.Change, state.Applied)
	current, err := f.p.CurrentImageBuildCacheRead(f.s, read, 5)
	if err != nil || current.Spec.ID != "build-two" || current.Binding() != cache {
		t.Fatal("same scope lost on representative change", current.Spec.ID, err)
	}
	last, err := u.Page(first.Next, first.Snapshot, false)
	if err != nil {
		t.Fatal(err)
	}
	continued, err := current.Page(last)
	if err != nil || !continued.Valid(read) || continued.Job != "build-two" || continued.Page.ObservedBy != plan.Spec.Digest() {
		t.Fatal(continued, err)
	}
	if _, err := f.p.ImageBuildCacheRead(f.s, f.sessions["manager"], 5, "tenant", imagebuild.CacheQuery{Job: "build-two"}, out.Next); err == nil {
		t.Fatal("job read accepted scope cursor")
	}
	for _, bad := range []imagebuild.CacheQuery{{Job: "build-two", Cache: &cache, Node: q.Node}, {Cache: &cache}, {Cache: &cache, Node: "other"}, {Cache: &[32]byte{99}, Node: q.Node}} {
		if _, err := f.p.ImageBuildCacheRead(f.s, f.sessions["manager"], 5, "tenant", bad, ""); err == nil {
			t.Fatal("invalid/foreign scope accepted", bad.Node)
		}
	}
	if _, err := f.p.ImageBuildCacheRead(f.s, f.sessions["manager"], 5, "other", q, ""); err == nil {
		t.Fatal("cross-tenant cache scope read")
	}
	if _, err := f.p.CurrentImageBuildCacheRead(f.s, read, 1002); err == nil {
		t.Fatal("expired scope authorization")
	}
	copy := cache
	cache[0] ^= 1
	if read.Query.Cache == nil || *read.Query.Cache != copy {
		t.Fatal("returned scope aliases caller query")
	}
}
