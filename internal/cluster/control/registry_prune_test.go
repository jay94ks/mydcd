// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/registryclient"
)

func signedPruneFixture(t *testing.T, f *nodeStorageFixture, id string, external bool, conditions registryclient.PruneConditions, count uint32) RegistryMaintenancePlan {
	t.Helper()
	read, err := f.p.RegistryPruneRead(f.s, f.sessions["manager"], 3, "tenant", RegistryPruneQuery{ID: id, External: external, Conditions: &conditions, Part: "items"}, "", false)
	if err != nil {
		t.Fatal(err)
	}
	plan := read.Base
	fact := RegistryPruneFact{Schema: 1, Cluster: f.p.Cluster, Owner: plan.Change.OwnerKey(), Target: plan.Change.PruneBase().DigestValue(), Conditions: PruneConditionsDigest(conditions), Preview: [32]byte{7}, Public: [32]byte{8}, Tenant: "tenant", Registry: id, External: external, Items: count, At: 2}
	fact.Signature = ed25519.Sign(f.node, RegistryPruneFactBytes(fact))
	plan.Change.Prune = &RegistryPruneTarget{Conditions: conditions, Fact: fact}
	return plan
}

func TestPruneSignedSelectionBindsOwnerConditionsAndTargetWithoutLargeRaftBody(t *testing.T) {
	f, spec := readyMaintenanceRegistry(t)
	plan := signedPruneFixture(t, f, spec.ID, false, registryclient.PruneConditions{Repositories: []string{"team/app"}}, 9000)
	change := plan.Change
	change.Operation = "original-prune"
	if !change.Valid(f.p.Cluster, RegistryPruneAction) {
		t.Fatal("signed original invalid")
	}
	raw, _ := json.Marshal(change)
	if len(raw) > 16<<10 {
		t.Fatal("large item count expanded Raft input", len(raw))
	}
	for _, edit := range []func(*RegistryMaintenanceChange){
		func(q *RegistryMaintenanceChange) { q.Prune.Fact.Preview[0]++ },
		func(q *RegistryMaintenanceChange) { q.Prune.Fact.Public[0]++ },
		func(q *RegistryMaintenanceChange) { q.Prune.Conditions.Before = 1 },
		func(q *RegistryMaintenanceChange) { q.Run.Generation++ },
		func(q *RegistryMaintenanceChange) { q.Prune.Fact.Items-- },
	} {
		var bad RegistryMaintenanceChange
		_ = json.Unmarshal(raw, &bad)
		edit(&bad)
		if bad.Valid(f.p.Cluster, RegistryPruneAction) {
			t.Fatal("modified signed target accepted")
		}
	}
	f.apply("manager", RegistryPruneAction, plan.Expected, change, state.Applied)
	if f.p.imageCacheAvailable(f.s, "node-b", spec.Authority+"/team/app:future") == nil {
		t.Fatal("new consumer crossed pending prune fence")
	}
	if err := f.p.imageCacheAvailable(f.s, "node-b", spec.Authority+"/other/app:future"); err != nil {
		t.Fatal("unselected repository fenced", err)
	}
	if f.p.RegistryPushAvailable(f.s, spec) == nil {
		t.Fatal("new writer crossed pending prune")
	}
	maintenanceReportFixture(t, f, change.Operation, "begin", nil, state.Applied)
	bad := RegistryMaintenanceResult{Code: "OK", At: 9, Native: [32]byte{1}, Prune: &RegistryPruneSummary{Processed: 8999, Deleted: 8999}}
	maintenanceReportFixture(t, f, change.Operation, "complete", &bad, state.Forbidden)
	done := RegistryMaintenanceResult{Code: "PARTIAL", At: 9, Native: [32]byte{1}, Prune: &RegistryPruneSummary{Processed: 9000, Deleted: 8998, Skipped: 1, Failed: 1}}
	maintenanceReportFixture(t, f, change.Operation, "complete", &done, state.Applied)
	jobs, err := f.p.RegistryMaintenanceJobs(f.s)
	row, ok := jobs.Record(change.Operation)
	if err != nil || !ok || row.Pending() || row.State != "failed" || row.Result.Prune.Failed != 1 {
		t.Fatal(row, err)
	}
	raw, err = state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := state.Decode(raw)
	if err != nil || f.p.Validate(decoded, decoded, state.Command{}) != nil {
		t.Fatal("original summary did not survive snapshot", err)
	}
}

func TestPruneExternalReadSetScopeAndUncertainParentKeepOriginal(t *testing.T) {
	f, _ := maintenanceSourceFixture(t)
	plan := signedPruneFixture(t, f, "private", true, registryclient.PruneConditions{Repositories: []string{"team/app"}}, 2)
	change := plan.Change
	change.Operation = "external-prune-original"
	f.apply("manager", RegistryPruneAction, plan.Expected, change, state.Applied)
	maintenanceReportFixture(t, f, change.Operation, "begin", nil, state.Applied)
	for _, tc := range []struct {
		image   string
		allowed bool
	}{
		{"external.example/team/app@sha256:" + strings.Repeat("a", 64), true},
		{"external.example/team/other@sha256:" + strings.Repeat("a", 64), false},
		{"elsewhere.example/team/app@sha256:" + strings.Repeat("a", 64), false},
	} {
		work, err := f.p.RegistryMaintenanceWork(f.s, change.OwnerKey(), RegistryMaintenanceWorkRequest{Operation: change.Operation, At: 3, Images: []string{tc.image}})
		if err != nil || work.Allowed != tc.allowed {
			t.Fatal(tc, work, err)
		}
	}
	maintenanceReportFixture(t, f, change.Operation, "uncertain", nil, state.Applied)
	work, err := f.p.RegistryMaintenanceWork(f.s, change.OwnerKey(), RegistryMaintenanceWorkRequest{Operation: change.Operation, At: 3})
	if err != nil || work.Allowed || work.State != "unknown" {
		t.Fatal("uncertain parent resubmitted", work, err)
	}
	noEffect := RegistryMaintenanceResult{Code: "PREVIEW_UNAVAILABLE", At: 9, Prune: &RegistryPruneSummary{}}
	maintenanceReportFixture(t, f, change.Operation, "complete", &noEffect, state.Forbidden)
}

func TestPruneSummaryRequiresExactFrozenCountAndRequestedGC(t *testing.T) {
	q := RegistryMaintenanceChange{Prune: &RegistryPruneTarget{Conditions: registryclient.PruneConditions{GC: true}, Fact: RegistryPruneFact{Items: 2}}}
	r := RegistryMaintenanceResult{Code: "OK", At: 10, Native: [32]byte{1}, ReclaimedBytes: 5, Prune: &RegistryPruneSummary{Processed: 2, Deleted: 1, Skipped: 1, GCCode: "OK", GCAt: 9}}
	if !RegistryMaintenanceResultFor(q, r) {
		t.Fatal("known successful GC omitted")
	}
	for _, edit := range []func(*RegistryMaintenanceResult){
		func(r *RegistryMaintenanceResult) { r.Prune.GCCode = "" },
		func(r *RegistryMaintenanceResult) { r.Prune.Processed-- },
		func(r *RegistryMaintenanceResult) { r.Prune.GCCode = "DENIED" },
		func(r *RegistryMaintenanceResult) { r.Native = [32]byte{} },
		func(r *RegistryMaintenanceResult) { r.Prune = nil },
	} {
		raw, _ := json.Marshal(r)
		var bad RegistryMaintenanceResult
		_ = json.Unmarshal(raw, &bad)
		edit(&bad)
		if RegistryMaintenanceResultFor(q, bad) {
			t.Fatal("incomplete completion admitted", bad)
		}
	}
	q.Prune = nil
	if RegistryMaintenanceResultFor(q, r) {
		t.Fatal("single delete adopted a bulk summary")
	}
}

func TestPruneOptionalGCProtectsWholeRegistryEvenWithRepositoryFilter(t *testing.T) {
	f, spec := readyMaintenanceRegistry(t)
	plan := signedPruneFixture(t, f, spec.ID, false, registryclient.PruneConditions{Repositories: []string{"team/app"}, GC: true}, 0)
	change := plan.Change
	change.Operation = "prune-with-gc"
	f.apply("manager", RegistryPruneAction, plan.Expected, change, state.Applied)
	image := spec.Authority + "/other/app@sha256:" + strings.Repeat("a", 64)
	if f.p.imageCacheAvailable(f.s, "node-b", image) == nil {
		t.Fatal("new reference crossed whole-store GC fence")
	}
	maintenanceReportFixture(t, f, change.Operation, "begin", nil, state.Applied)
	work, err := f.p.RegistryMaintenanceWork(f.s, change.OwnerKey(), RegistryMaintenanceWorkRequest{Operation: change.Operation, At: 3, Images: []string{image}})
	if err != nil || !work.Allowed {
		t.Fatal("GC could not check retired images outside deletion filter", work, err)
	}
	result := RegistryMaintenanceResult{Code: "OK", At: 10, Native: [32]byte{1}, ReclaimedBytes: 11, Prune: &RegistryPruneSummary{GCCode: "OK", GCAt: 9}}
	maintenanceReportFixture(t, f, change.Operation, "complete", &result, state.Applied)
	jobs, err := f.p.RegistryMaintenanceJobs(f.s)
	summary := jobs.Summary(spec.Tenant, spec.ID)
	if err != nil || summary == nil || summary.LastGCOperation != change.Operation || summary.LastGCAt != 9 || summary.ReclaimedBytes != 11 {
		t.Fatal("actual prune GC missing from summary", summary, err)
	}
}
