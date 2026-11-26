// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/imagebuild"
)

func TestBuildLogTailPreservesAppendCursorAndCurrentTenantAuthorization(t *testing.T) {
	f, plan := buildJobFixture(t)
	f.apply("manager", "begin-image-build", 0, plan.Change, state.Applied)
	q := imagebuild.LogQuery{Job: plan.Spec.ID, MaxBytes: imagebuild.MaxLogPageBytes, Tail: true}
	read, err := f.p.ImageBuildLogRead(f.s, f.sessions["manager"], 2, "tenant", q, "")
	if err != nil {
		t.Fatal(err)
	}
	total := uint32(400 << 10)
	page, err := read.Page(imagebuild.LogPage{Schema: 1, Job: plan.Spec.Digest(), Available: true, Offset: total - q.MaxBytes, Total: total, Next: total, Data: bytes.Repeat([]byte{'x'}, int(q.MaxBytes))})
	if err != nil || !page.Valid(read) {
		t.Fatal("tail page", err)
	}
	bad := page
	bad.Page.Offset--
	if bad.Valid(read) {
		t.Fatal("server's wrong tail offset accepted")
	}
	if _, err := f.p.ImageBuildLogRead(f.s, f.sessions["manager"], 2, "tenant", q, page.Next); err == nil {
		t.Fatal("tail mixed with prior cursor")
	}
	for _, tenant := range []string{"other", "tenant"} {
		at := int64(2)
		if tenant == "tenant" {
			at = 1002
		}
		if _, err := f.p.ImageBuildLogRead(f.s, f.sessions["manager"], at, tenant, q, ""); err == nil {
			t.Fatal("foreign tenant or expired session read tail", tenant)
		}
	}
	buildJobReportFixture(t, f, ImageBuildJobReport{Job: q.Job, Action: "begin"}, state.Applied)
	q.Tail = false
	follow, err := f.p.ImageBuildLogRead(f.s, f.sessions["manager"], 3, "tenant", q, page.Next)
	if err != nil || follow.Snapshot() != read.Snapshot() {
		t.Fatal("progress changed the tail cursor", err)
	}
	next, err := follow.Page(imagebuild.LogPage{Schema: 1, Job: plan.Spec.Digest(), Available: true, Offset: total, Next: total + 3, Total: total + 3, Data: []byte("new")})
	if err != nil || string(next.Page.Data) != "new" {
		t.Fatal("append page", err)
	}
	if _, err := f.p.ImageBuildLogRead(f.s, f.sessions["manager"], 3, "other", q, page.Next); err == nil {
		t.Fatal("tail cursor moved across tenants")
	}
}

func TestBuildLogReadKeepsCursorAcrossJobProgressButChecksCurrentUserAndJob(t *testing.T) {
	f, plan := buildJobFixture(t)
	f.apply("manager", "begin-image-build", 0, plan.Change, state.Applied)
	q := imagebuild.LogQuery{Job: "build-one", MaxBytes: 4}
	read, err := f.p.ImageBuildLogRead(f.s, f.sessions["manager"], 2, "tenant", q, "")
	if err != nil {
		t.Fatal(err)
	}
	// Owner log bytes are injected; native storage/SDK have distinct tests.
	page, err := read.Page(imagebuild.LogPage{Schema: 1, Job: plan.Spec.Digest(), Available: true, Data: []byte("text"), Total: 4, Next: 4})
	if err != nil || !page.Valid(read) {
		t.Fatal(page, err)
	}
	buildJobReportFixture(t, f, ImageBuildJobReport{Job: q.Job, Action: "begin"}, state.Applied)
	firstRead := read
	read.After = page.Next
	current, err := f.p.CurrentImageBuildLogRead(f.s, read, 3)
	if err != nil || current.Phase != "running" {
		t.Fatal("job progress invalidated byte cursor", current, err)
	}
	if offset, err := current.Offset(); err != nil || offset != 4 {
		t.Fatal(offset, err)
	}
	if _, err := f.p.ImageBuildLogRead(f.s, f.sessions["manager"], 1002, "tenant", q, ""); err == nil {
		t.Fatal("expired current login read logs")
	}
	if _, err := f.p.ImageBuildLogRead(f.s, f.sessions["manager"], 3, "other", q, ""); err == nil {
		t.Fatal("cross-tenant log read")
	}
	for _, edit := range []func(*ImageBuildLogRead){
		func(r *ImageBuildLogRead) { r.Epoch++ }, func(r *ImageBuildLogRead) { r.Spec.ID = "other" },
		func(r *ImageBuildLogRead) { r.After = buildPageNext(r.Snapshot(), "0000000004x") },
	} {
		bad := current
		edit(&bad)
		if _, err := f.p.CurrentImageBuildLogRead(f.s, bad, 3); err == nil {
			t.Fatal("changed cursor/owner scope accepted")
		}
	}
	for _, edit := range []func(*ImageBuildLogPage){
		func(p *ImageBuildLogPage) { p.Job = "other" }, func(p *ImageBuildLogPage) { p.Tenant = "other" },
		func(p *ImageBuildLogPage) { p.Page.Next++ }, func(p *ImageBuildLogPage) { p.Page.Data = nil },
		func(p *ImageBuildLogPage) { p.Next = "invalid" }, func(p *ImageBuildLogPage) { p.Phase = "ready" },
	} {
		bad := page
		edit(&bad)
		if bad.Valid(firstRead) {
			t.Fatal("corrupt owner page accepted")
		}
	}
}

func TestBuildLogReclaimRequiresCommittedDeletionAndOriginalOwner(t *testing.T) {
	f, plan := buildJobFixture(t)
	f.apply("manager", "begin-image-build", 0, plan.Change, state.Applied)
	if _, err := f.p.ImageBuildLogReclaim(f.s, plan.Spec.Scope.Root.Key, plan.Spec); err == nil {
		t.Fatal("active job reclaimed logs")
	}
	f.apply("manager", "cancel-image-build", 1, ImageBuildJobSelection{Tenant: "tenant", ID: plan.Spec.ID}, state.Applied)
	closure := buildJobClosure(f, plan.Spec, "CANCELLED")
	buildJobReportFixture(t, f, ImageBuildJobReport{Job: plan.Spec.ID, Action: "complete", Closure: &closure}, state.Applied)
	if _, err := f.p.ImageBuildLogReclaim(f.s, plan.Spec.Scope.Root.Key, plan.Spec); err == nil {
		t.Fatal("visible job history logs reclaimed")
	}
	f.apply("manager", "delete-image-build-job", 3, ImageBuildJobSelection{Tenant: "tenant", ID: plan.Spec.ID}, state.Applied)
	if _, err := f.p.ImageBuildLogRead(f.s, f.sessions["manager"], 4, "tenant", imagebuild.LogQuery{Job: plan.Spec.ID, MaxBytes: 4096}, ""); err == nil {
		t.Fatal("deleted job logs exposed")
	}
	got, err := f.p.ImageBuildLogReclaim(f.s, plan.Spec.Scope.Root.Key, plan.Spec)
	if err != nil || !got.Valid(plan.Spec) || got.Native != closure.Native {
		t.Fatal(got, err)
	}
	if _, err := f.p.ImageBuildLogReclaim(f.s, [32]byte{9}, plan.Spec); err == nil {
		t.Fatal("other owner reclaimed job logs")
	}
	got.Signature[0] ^= 1
	if _, err := f.p.ImageBuilds(f.s); err != nil {
		t.Fatal("reclaim result aliased shared closure", err)
	}
}
