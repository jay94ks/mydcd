// SPDX-License-Identifier: Apache-2.0

package control

import (
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/workload"
)

func TestBuildBudgetUsesCommittedJobAndSurvivesCancelUnknownUntilOwnerClosure(t *testing.T) {
	f, plan := buildJobFixture(t)
	f.apply("manager", "begin-image-build", 0, plan.Change, state.Applied)
	base, err := f.p.ProjectResources(f.s)
	if err != nil {
		t.Fatal(err)
	}
	before, err := base.Resources.Quotas.Usage("tenant", "node-a")
	if err != nil {
		t.Fatal(err)
	}
	buildJobReportFixture(t, f, ImageBuildJobReport{Job: "build-one", Action: "begin"}, state.Applied)
	need := workload.Resources{CPU: uint64(plan.Spec.Policy.CPUMillis) * 1_000_000, Memory: uint64(plan.Spec.Policy.MemoryBytes)}
	key := "workload/imagebuild/tenant/build-one/builder"
	check := func(draining bool) {
		t.Helper()
		projection, err := f.p.ProjectResources(f.s)
		if err != nil {
			t.Fatal(err)
		}
		held, ok := projection.Resources.Quotas.Reservation(key)
		if !ok || held.Generation != 1 || held.Owner != plan.Spec.Scope.Root.Key || held.Need != need || held.Draining != draining {
			t.Fatal("lost/changed original build budget", held)
		}
		used, err := projection.Resources.Quotas.Usage("tenant", "node-a")
		if err != nil || used != (workload.Resources{CPU: before.CPU + need.CPU, Memory: before.Memory + need.Memory}) {
			t.Fatal("not combined with registry/Task usage", used, err)
		}
		base, err := f.p.Resources(f.s)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := base.Quotas.Reservation(key); ok {
			t.Fatal("duplicated into manual budget checkpoint")
		}
	}
	check(false)
	buildJobReportFixture(t, f, ImageBuildJobReport{Job: "build-one", Action: "uncertain"}, state.Applied)
	check(false)
	f.apply("manager", "cancel-image-build", 3, ImageBuildJobSelection{Tenant: "tenant", ID: "build-one"}, state.Applied)
	check(true)
	closure := buildJobClosure(f, plan.Spec, "CANCELLED")
	buildJobReportFixture(t, f, ImageBuildJobReport{Job: "build-one", Action: "complete", Closure: &closure}, state.Applied)
	after, err := f.p.ProjectResources(f.s)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := after.Resources.Quotas.Reservation(key); ok {
		t.Fatal("terminal owner closure did not return build budget")
	}
	if used, err := after.Resources.Quotas.Usage("tenant", "node-a"); err != nil || used != before {
		t.Fatal("changed another consumer's budget", used, err)
	}
	raw, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := state.Decode(raw)
	if err != nil || f.p.Validate(state.State{}, restored, state.Command{}) != nil {
		t.Fatal("restore lost source budget validation", err)
	}
}

func TestBuildBeginCannotBypassCurrentTenantCPUQuota(t *testing.T) {
	f, plan := buildJobFixture(t)
	f.apply("manager", "begin-image-build", 0, plan.Change, state.Applied)
	projection, err := f.p.ProjectResources(f.s)
	if err != nil {
		t.Fatal(err)
	}
	used, err := projection.Resources.Quotas.Usage("tenant", "node-a")
	if err != nil {
		t.Fatal(err)
	}
	resources, err := f.p.Resources(f.s)
	if err != nil {
		t.Fatal(err)
	}
	limit, ok := resources.Quotas.Limit("tenant", "node-a")
	if !ok {
		t.Fatal("missing quota")
	}
	expected := limit.Revision
	limit.Revision = 0
	limit.Capacity.CPU = used.CPU + uint64(plan.Spec.Policy.CPUMillis)*1_000_000 - 1
	f.apply("admin", "set-node-quota", expected, limit, state.Applied)
	work, err := f.p.ImageBuildJobWork(f.s, plan.Spec.Scope.Root.Key, ImageBuildJobWorkQuery{Tenant: "tenant", ID: "build-one", At: 3})
	if err != nil || work.Allowed || work.Blocked != "WAITING_FOR_BUDGET" {
		t.Fatal("queue ignored current tenant budget", work.Allowed, err)
	}
	buildJobReportFixture(t, f, ImageBuildJobReport{Job: "build-one", Action: "begin"}, state.Forbidden)
	book, err := f.p.ImageBuilds(f.s)
	if err != nil {
		t.Fatal(err)
	}
	row, ok := book.Job("tenant", "build-one")
	if !ok || row.Run.Phase != "queued" || row.Run.Revision != 1 {
		t.Fatal("rejected begin advanced original", row.Run.Phase)
	}
}
