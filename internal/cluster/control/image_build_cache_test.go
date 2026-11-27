// SPDX-License-Identifier: Apache-2.0

package control

import (
	"fmt"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/imagebuild"

	bkclient "github.com/moby/buildkit/client"
)

func TestBuildCacheReadChecksCurrentAuthorityAndOriginalJobEpochAndObservationCursor(t *testing.T) {
	f, plan := buildJobFixture(t)
	f.apply("manager", "begin-image-build", 0, plan.Change, state.Applied)
	q := imagebuild.CacheQuery{Job: plan.Spec.ID}
	read, err := f.p.ImageBuildCacheRead(f.s, f.sessions["manager"], 2, "tenant", q, "")
	if err != nil {
		t.Fatal(err)
	}
	var rows []*bkclient.UsageInfo
	for i := 0; i < imagebuild.CachePageItems+1; i++ {
		rows = append(rows, &bkclient.UsageInfo{ID: fmt.Sprintf("entry-%03d", i), Size: 2})
	}
	usage, err := imagebuild.NewCacheUsage(plan.Spec, 3, rows)
	if err != nil {
		t.Fatal(err)
	}
	page, err := usage.Page(0, [32]byte{}, false)
	if err != nil {
		t.Fatal(err)
	}
	out, err := read.Page(page)
	if err != nil || out.Next == "" || !out.Valid(read) {
		t.Fatal(out, err)
	}
	firstRead := read
	read.After = out.Next
	buildJobReportFixture(t, f, ImageBuildJobReport{Job: q.Job, Action: "begin"}, state.Applied)
	if _, err := f.p.CurrentImageBuildCacheRead(f.s, read, 3); err != nil {
		t.Fatal("job progress invalidated observation cursor", err)
	}
	for _, edit := range []func(*ImageBuildCacheRead){func(r *ImageBuildCacheRead) { r.Epoch++ }, func(r *ImageBuildCacheRead) { r.Spec.ID = "other" }, func(r *ImageBuildCacheRead) { r.Tenant = "other" }, func(r *ImageBuildCacheRead) { r.After = out.Next + "x" }} {
		bad := read
		edit(&bad)
		if _, err := f.p.CurrentImageBuildCacheRead(f.s, bad, 3); err == nil {
			t.Fatal("changed original/tenant/epoch accepted")
		}
	}
	if _, err := f.p.ImageBuildCacheRead(f.s, f.sessions["manager"], 1002, "tenant", q, ""); err == nil {
		t.Fatal("expired user read native cache")
	}
	for _, edit := range []func(*ImageBuildCachePage){func(p *ImageBuildCachePage) { p.Job = "other" }, func(p *ImageBuildCachePage) { p.Context = "other" }, func(p *ImageBuildCachePage) { p.Page.Cache = [32]byte{99} }, func(p *ImageBuildCachePage) { p.Next = "invalid" }, func(p *ImageBuildCachePage) { p.Page.Count = 1 }} {
		bad := out
		edit(&bad)
		if bad.Valid(firstRead) {
			t.Fatal("corrupt/foreign cache page accepted")
		}
	}
	_, job, epoch, offset, err := ImageBuildCacheOffset(out.Next)
	if err != nil || job != plan.Spec.Digest() || epoch != read.Epoch || offset != imagebuild.CachePageItems {
		t.Fatal(job, epoch, offset, err)
	}
	if _, _, _, _, err := ImageBuildCacheOffset(buildPageNext(page.Snapshot, fmt.Sprintf("%x/01/0000000032", plan.Spec.Digest()))); err == nil {
		t.Fatal("noncanonical epoch accepted")
	}
}
