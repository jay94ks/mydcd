// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/imagebuild"
)

func cachePruneReportFixture(t *testing.T, f *nodeStorageFixture, r ImageBuildCachePruneReport, want state.Code) ImageBuildCachePruneReport {
	t.Helper()
	b, err := f.p.ImageBuilds(f.s)
	if err != nil || len(b.CachePrunes) != 1 {
		t.Fatal("missing original cleanup", err)
	}
	row := b.CachePrunes[0]
	q, _ := row.Change()
	source, _ := b.Job(q.Tenant, row.Source)
	r.Schema, r.Kind, r.Cluster, r.Owner, r.Intent = 1, "cache-prune", f.p.Cluster, source.Run.Spec.Scope.Root.Key, row.Digest()
	r.Tenant, r.ID, r.Expected, r.RootRevision, r.Epoch = q.Tenant, q.ID, row.Revision, f.s.Object(ImageBuildKey).Revision, f.s.ModuleEpoch()
	r.Signature = ed25519.Sign(f.node, ImageBuildCachePruneReportBytes(r))
	cmd, err := r.Command()
	if err != nil {
		t.Fatal(err)
	}
	validate := func(before, after state.State, command state.Command) error {
		err := f.p.Validate(before, after, command)
		if err != nil {
			t.Log("cache prune checkpoint rejected:", err)
		}
		return err
	}
	next, result, err := state.ApplyTransactional(f.s, f.s.Index()+1, cmd, validate, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
	if err != nil || result.Code != want {
		t.Fatal(r.Action, result.Code, want, err)
	}
	f.s = next
	return r
}

func retainedCachePruneFixture(t *testing.T) (*nodeStorageFixture, ImageBuildJobPlan) {
	t.Helper()
	f, plan := buildJobFixture(t)
	f.apply("manager", "begin-image-build", 0, plan.Change, state.Applied)
	f.apply("manager", "cancel-image-build", 1, ImageBuildJobSelection{Tenant: "tenant", ID: plan.Spec.ID}, state.Applied)
	closure := buildJobClosure(f, plan.Spec, "CANCELLED")
	buildJobReportFixture(t, f, ImageBuildJobReport{Job: plan.Spec.ID, Action: "complete", Closure: &closure}, state.Applied)
	f.apply("manager", "delete-image-build-job", 3, ImageBuildJobSelection{Tenant: "tenant", ID: plan.Spec.ID}, state.Applied)
	f.apply("manager", ImageBuildCachePruneAction, 0, ImageBuildCachePruneChange{Tenant: "tenant", ID: "clear", Node: "node-a", Cache: imagebuild.CacheIdentity(plan.Spec), Filter: imagebuild.CachePruneFilter{Mode: "all"}}, state.Applied)
	return f, plan
}

// Reports are injected original owner facts. These tests exercise the real
// signed FSM/reservation/restore, not actual SDK prune or container closure.
func TestCachePruneReportsRetainUnknownBudgetUntilOriginalClosureAfterRevocation(t *testing.T) {
	f, plan := retainedCachePruneFixture(t)
	native := [32]byte{88}
	cachePruneReportFixture(t, f, ImageBuildCachePruneReport{Action: "complete", At: 5, ClosedAt: 5, Native: &native, Code: "OK"}, state.Forbidden)
	begin := cachePruneReportFixture(t, f, ImageBuildCachePruneReport{Action: "begin", At: 5}, state.Applied)
	rows, err := f.p.imageBuildReservations(f.s)
	if err != nil || len(rows) != 1 || rows[0].Need.Memory != uint64(plan.Spec.Policy.MemoryBytes) || rows[0].Key != "workload/imagebuild-cache-prune/tenant/clear/builder" {
		t.Fatal(rows, err)
	}
	// Work after admission must not ask for its already reserved budget again.
	work, err := f.p.ImageBuildCachePruneWork(f.s, plan.Spec.Scope.Root.Key, ImageBuildCachePruneWorkQuery{Tenant: "tenant", ID: "clear", At: 6})
	if err != nil || !work.Allowed {
		t.Fatal("running cleanup double-counted its budget", work.Blocked, err)
	}

	proof := begin
	proof.Action = "uncertain"
	proof.At = 6
	proof.Expected = 2
	proof.RootRevision = f.s.Object(ImageBuildKey).Revision
	proof.Signature = ed25519.Sign(f.node, ImageBuildCachePruneReportBytes(proof))
	proofRaw, _ := json.Marshal(proof)
	if _, err := f.p.ResolveImageBuildCachePruneReport(f.s, [32]byte{99}, proofRaw); err == nil {
		t.Fatal("foreign node submitted original owner progress")
	}
	proof.Intent[0] ^= 1
	proof.Signature = ed25519.Sign(f.node, ImageBuildCachePruneReportBytes(proof))
	proofRaw, _ = json.Marshal(proof)
	if _, err := f.p.ResolveImageBuildCachePruneReport(f.s, plan.Spec.Scope.Root.Key, proofRaw); err == nil {
		t.Fatal("wrong maintenance intent accepted")
	}
	cachePruneReportFixture(t, f, ImageBuildCachePruneReport{Action: "uncertain", At: 6}, state.Applied)
	cachePruneReportFixture(t, f, ImageBuildCachePruneReport{Action: "begin", At: 7}, state.Forbidden)
	rows, err = f.p.imageBuildReservations(f.s)
	if err != nil || len(rows) != 1 {
		t.Fatal("unknown released budget", rows, err)
	}
	c, err := f.p.Catalog(f.s)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := c.User("manager")
	revision := u.Revision
	u.Revision = 0
	u.Credentials[0].Operations = []string{"put-build-context"}
	f.apply("admin", "put-user", revision, u, state.Applied)
	work, err = f.p.ImageBuildCachePruneWork(f.s, plan.Spec.Scope.Root.Key, ImageBuildCachePruneWorkQuery{Tenant: "tenant", ID: "clear", At: 7})
	if err != nil || work.Allowed || work.Blocked != "PERMISSION_REVOKED" {
		t.Fatal("revoked original still executes", work.Blocked, err)
	}
	completed := cachePruneReportFixture(t, f, ImageBuildCachePruneReport{Action: "complete", At: 20, ClosedAt: 7, Native: &native, Code: "OK", RemovedCount: 2, ReportedBytes: 123}, state.Applied)
	b, err := f.p.ImageBuilds(f.s)
	if err != nil || b.CachePrunes[0].Pending() || b.CachePrunes[0].State != "succeeded" || b.CachePrunes[0].Revision != 4 || len(b.CachePrunes[0].Reports) != 3 {
		t.Fatal(b.CachePrunes, err)
	}
	rows, err = f.p.imageBuildReservations(f.s)
	if err != nil || len(rows) != 0 {
		t.Fatal("closed cleanup retained budget", rows, err)
	}
	page, err := f.p.ImageBuildPage(f.s, f.sessions["admin"], 20, "tenant", ImageBuildQuery{Part: "cache-prunes"}, "")
	if err != nil || len(page.CachePrunes) != 1 || !page.CachePrunes[0].Valid() || page.CachePrunes[0].ClosedAt != 7 || page.CachePrunes[0].ReportedBytes != 123 {
		t.Fatal(page, err)
	}
	raw, err := json.Marshal(page)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	_ = json.Unmarshal(raw, &fields)
	view := fields["CachePrunes"].([]any)[0].(map[string]any)
	for _, key := range []string{"Origin", "Reports", "Source", "Session", "Native"} {
		if view[key] != nil {
			t.Fatal("private report leaked", key)
		}
	}
	encoded, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := state.Decode(encoded)
	if err != nil || f.p.Validate(state.State{}, restored, state.Command{}) != nil {
		t.Fatal("reports did not restore", err)
	}
	// Original report bytes name the accepted action independently of progress.
	if begin.Intent != completed.Intent {
		t.Fatal("intent changed with progress")
	}
	broken := b.CachePrunes[0]
	broken.Reports = append([]ImageBuildCachePruneReport(nil), broken.Reports...)
	broken.Reports[2].ClosedAt = 4
	broken.Reports[2].Signature = ed25519.Sign(f.node, ImageBuildCachePruneReportBytes(broken.Reports[2]))
	if validateImageBuildCachePrune(b, broken, f.p.Cluster, true) == nil {
		t.Fatal("closure before original start accepted")
	}
}

func TestCachePruneQueuedFailureNeedsNativeProofAndNeverReportsDeletedBytes(t *testing.T) {
	f, _ := retainedCachePruneFixture(t)
	native := [32]byte{88}
	cachePruneReportFixture(t, f, ImageBuildCachePruneReport{Action: "complete", At: 5, ClosedAt: 5, Code: "FAILED"}, state.Forbidden)
	cachePruneReportFixture(t, f, ImageBuildCachePruneReport{Action: "complete", At: 5, ClosedAt: 5, Native: &native, Code: "FAILED", RemovedCount: 1}, state.Forbidden)
	cachePruneReportFixture(t, f, ImageBuildCachePruneReport{Action: "uncertain", At: 5}, state.Forbidden)
	cachePruneReportFixture(t, f, ImageBuildCachePruneReport{Action: "complete", At: 5, ClosedAt: 5, Native: &native, Code: "PERMISSION_REVOKED"}, state.Applied)
	b, err := f.p.ImageBuilds(f.s)
	if err != nil || b.CachePrunes[0].State != "failed" || b.CachePrunes[0].Revision != 2 {
		t.Fatal(b, err)
	}
	if rows, err := f.p.imageBuildReservations(f.s); err != nil || len(rows) != 0 {
		t.Fatal(rows, err)
	}
}

func TestCachePruneWorkUsesOriginalMaintenanceDeadlineRatherThanSourceBuildTime(t *testing.T) {
	f, plan := retainedCachePruneFixture(t)
	b, err := f.p.ImageBuilds(f.s)
	if err != nil {
		t.Fatal(err)
	}
	q := ImageBuildCachePruneWorkQuery{Tenant: "tenant", ID: "clear", At: b.CachePrunes[0].Origin.At - 1}
	work, err := f.p.ImageBuildCachePruneWork(f.s, plan.Spec.Scope.Root.Key, q)
	if err != nil || work.Allowed || work.Blocked != "NOT_READY" {
		t.Fatal(work.Blocked, err)
	}
	q.At = b.CachePrunes[0].Origin.At + int64(plan.Spec.Policy.Seconds)
	work, err = f.p.ImageBuildCachePruneWork(f.s, plan.Spec.Scope.Root.Key, q)
	if err != nil || work.Allowed || work.Blocked != "TIMEOUT" {
		t.Fatal(work.Blocked, err)
	}
	if grant, err := work.NativeGrant(); err != nil || grant.Spec.At != uint64(b.CachePrunes[0].Origin.At) || grant.Allowed {
		t.Fatal("deadline lost original maintenance identity", grant, err)
	}
}
