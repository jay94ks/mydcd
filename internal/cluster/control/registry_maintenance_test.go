// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/registry"
)

// Shared FSM tests simulate the native ready/report facts. Actual Store, owner
// I/O and authenticated transport are separate RQ6 adapter tests.
func readyMaintenanceRegistry(t *testing.T) (*nodeStorageFixture, registry.Specification) {
	t.Helper()
	f, spec := registryFixture(t)
	f.apply("manager", "put-registry", 0, RegistryPut{spec}, state.Applied)
	registryReportFixture(t, f, RegistryReport{Tenant: spec.Tenant, ID: spec.ID, Action: "reserve", SpecRevision: 1, Generation: 1}, state.Applied)
	registryReportFixture(t, f, RegistryReport{Tenant: spec.Tenant, ID: spec.ID, Action: "serving", SpecRevision: 1, Generation: 1, Observation: &RegistryObservation{Boot: [32]byte{1}, Certificate: [32]byte{2}}}, state.Applied)
	return f, spec
}

func maintenanceReportFixture(t *testing.T, f *nodeStorageFixture, id, action string, result *RegistryMaintenanceResult, want state.Code) RegistryMaintenanceReport {
	t.Helper()
	jobs, err := f.p.RegistryMaintenanceJobs(f.s)
	if err != nil {
		t.Fatal(err)
	}
	row, ok := jobs.Record(id)
	if !ok {
		t.Fatal("missing original maintenance job")
	}
	r := RegistryMaintenanceReport{Schema: 1, Cluster: f.p.Cluster, Owner: row.Change.OwnerKey(), Operation: id, Action: action, Expected: row.Revision, RootRevision: f.s.Object(RegistryMaintenanceKey).Revision, Epoch: f.s.ModuleEpoch(), At: 3, Result: result}
	r.Signature = ed25519.Sign(f.node, RegistryMaintenanceReportBytes(r))
	cmd, err := r.Command()
	if err != nil {
		t.Fatal(err)
	}
	next, reply, err := state.ApplyTransactional(f.s, f.s.Index()+1, cmd, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
	if err != nil || reply.Code != want {
		t.Fatal(action, reply.Code, want, err)
	}
	f.s = next
	return r
}

func TestMaintenancePlanQueuesExactRunAndFencesPushNewReferencesAndDrain(t *testing.T) {
	f, spec := readyMaintenanceRegistry(t)
	digest := "sha256:" + strings.Repeat("a", 64)
	q := RegistryMaintenanceQuery{Action: "delete-registry-image", ID: spec.ID, Repository: "team/app", Reference: "stable", Digest: digest}
	before, _ := state.Encode(f.s)
	plan, err := f.p.PlanRegistryMaintenance(f.s, f.sessions["manager"], 3, spec.Tenant, q)
	if err != nil || plan.Expected != 1 || plan.Change.Run.Ready != nil || plan.InUse || plan.Change.Operation != "" || plan.RootRevision != 0 {
		t.Fatal("exact nonmutating plan", plan, err)
	}
	after, _ := state.Encode(f.s)
	if !bytes.Equal(before, after) {
		t.Fatal("plan changed the shared state")
	}
	change := plan.Change
	change.Operation = "original-delete"
	f.apply("manager", q.Action, plan.Expected, change, state.Applied)
	if f.p.RegistryPushAvailable(f.s, spec) == nil {
		t.Fatal("new push allowed across a pending maintenance job")
	}
	for _, node := range []string{"node-a", "node-b"} {
		for _, ref := range []string{spec.Authority + "/team/app:stable", spec.Authority + "/team/app@" + digest} {
			if f.p.imageCacheAvailable(f.s, node, ref) == nil {
				t.Fatal("new consumer crossed the shared pending fence", node, ref)
			}
		}
	}
	if err = f.p.imageCacheAvailable(f.s, "node-b", "different.example/team/app:stable"); err != nil {
		t.Fatal("unrelated registry fenced", err)
	}
	if _, err = f.p.PlanRegistryMaintenance(f.s, f.sessions["manager"], 3, spec.Tenant, q); err == nil {
		t.Fatal("second original job admitted for same registry")
	}
	f.apply("manager", "stop-registry", 1, RegistrySelection{Tenant: spec.Tenant, ID: spec.ID}, state.ConditionFailed)
	registryReportFixture(t, f, RegistryReport{Tenant: spec.Tenant, ID: spec.ID, Action: "drain", SpecRevision: 1, Generation: 1}, state.ConditionFailed)
	maintenanceReportFixture(t, f, change.Operation, "complete", &RegistryMaintenanceResult{Code: "OK", At: 3000, Native: [32]byte{1}}, state.ConditionFailed)
	maintenanceReportFixture(t, f, change.Operation, "begin", nil, state.Applied)
	rows, _, err := f.p.RegistryPage(f.s, f.sessions["manager"], 3, spec.Tenant, "")
	if err != nil || len(rows) != 1 || rows[0].Maintenance == nil || rows[0].Maintenance.PendingOperation != change.Operation || rows[0].Maintenance.PendingState != "running" {
		t.Fatal("public pending summary missing", rows, err)
	}
	work, err := f.p.RegistryMaintenanceWork(f.s, change.Run.Owner, RegistryMaintenanceWorkRequest{Operation: change.Operation, At: 3})
	if err != nil || !work.Allowed || work.State != "running" || work.Change.DigestValue() != change.DigestValue() {
		t.Fatal("original owner work", work, err)
	}
	maintenanceReportFixture(t, f, change.Operation, "complete", &RegistryMaintenanceResult{Code: "OK", At: 3000, Native: [32]byte{1}}, state.Applied)
	if err = f.p.RegistryPushAvailable(f.s, spec); err != nil {
		t.Fatal("completed result retained push admission fence", err)
	}
	if err = f.p.imageCacheAvailable(f.s, "node-b", spec.Authority+"/team/app:stable"); err != nil {
		t.Fatal("completed result retained consumer fence", err)
	}
	encoded, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	f.s, err = state.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	status, err := f.p.RegistryMaintenanceStatus(f.s, f.sessions["manager"], 3, spec.Tenant, change.Operation)
	if err != nil || status.State != "done" || status.Result == nil || status.Result.Native != ([32]byte{1}) || status.User != "manager" || status.Change.DigestValue() != change.DigestValue() {
		t.Fatal("original snapshot result", status, err)
	}
	jobs, _ := f.p.RegistryMaintenanceJobs(f.s)
	copy, _ := jobs.Record(change.Operation)
	copy.Origin.Signature[0] ^= 1
	fresh, _ := jobs.Record(change.Operation)
	if bytes.Equal(copy.Origin.Signature, fresh.Origin.Signature) {
		t.Fatal("public original lookup aliases frozen signature")
	}
	f.apply("manager", "stop-registry", 1, RegistrySelection{Tenant: spec.Tenant, ID: spec.ID}, state.Applied)
	registryReportFixture(t, f, RegistryReport{Tenant: spec.Tenant, ID: spec.ID, Action: "drain", SpecRevision: 1, Generation: 1}, state.Applied)
}

func TestMaintenanceCurrentRevocationAllowsOnlyOriginalOwnerSettlement(t *testing.T) {
	f, spec := readyMaintenanceRegistry(t)
	plan, err := f.p.PlanRegistryMaintenance(f.s, f.sessions["manager"], 3, spec.Tenant, RegistryMaintenanceQuery{Action: "gc-registry", ID: spec.ID})
	if err != nil {
		t.Fatal(err)
	}
	change := plan.Change
	change.Operation = "original-gc"
	f.apply("manager", "gc-registry", plan.Expected, change, state.Applied)
	maintenanceReportFixture(t, f, change.Operation, "begin", nil, state.Applied)
	if f.p.imageCacheAvailable(f.s, "node-b", spec.Authority+"/other/app:latest") == nil {
		t.Fatal("GC did not fence new references to same registry")
	}
	admin := f.sessions["admin"]
	admin.Scopes[0].Actions = append(admin.Scopes[0].Actions, access.ManageMembers)
	admin.Signature = ed25519.Sign(f.node, access.SessionBytes(admin))
	f.sessions["admin"] = admin
	catalog, _ := f.p.Catalog(f.s)
	member, _ := catalog.Membership(spec.Tenant, "manager")
	expected := member.Revision
	member.Revision, member.Enabled = 0, false
	f.apply("admin", "set-membership", expected, member, state.Applied)
	work, err := f.p.RegistryMaintenanceWork(f.s, change.Run.Owner, RegistryMaintenanceWorkRequest{Operation: change.Operation, At: 3})
	if err != nil || work.Allowed || work.State != "running" {
		t.Fatal("revocation erased original cleanup or permitted a new effect", work, err)
	}
	if _, err = f.p.RegistryMaintenanceWork(f.s, [32]byte(f.manager.Public().(ed25519.PublicKey)), RegistryMaintenanceWorkRequest{Operation: change.Operation, At: 3}); err == nil {
		t.Fatal("different key read original owner work")
	}
	if _, err = f.p.RegistryMaintenanceStatus(f.s, f.sessions["admin"], 3, "other", change.Operation); err == nil {
		t.Fatal("cross-tenant result disclosed")
	}
	maintenanceReportFixture(t, f, change.Operation, "complete", &RegistryMaintenanceResult{Code: "DENIED", At: 3000}, state.Applied)
	status, err := f.p.RegistryMaintenanceStatus(f.s, f.sessions["admin"], 3, spec.Tenant, change.Operation)
	if err != nil || status.State != "failed" || status.Result == nil || status.Result.Code != "DENIED" {
		t.Fatal("original refusal not retained", status, err)
	}
}

func TestMaintenanceUsesAcceptedAppReferencesBeforeAnyNativeContainerExists(t *testing.T) {
	f := managedDNSTaskCoreFixture(t)
	managedDNSTaskCoreBegin(t, f, "registry-protected", "10.80.1.2", "web")
	image := "docker.io/library/php@sha256:" + strings.Repeat("a", 64)
	used, err := f.p.maintenanceImagesInUse(f.s, "tenant", []string{image})
	if err != nil || !used {
		t.Fatal("accepted app/Task omitted by actual maintenance guard", used, err)
	}
	unused, err := f.p.maintenanceImagesInUse(f.s, "tenant", []string{"different.example/library/php@sha256:" + strings.Repeat("a", 64)})
	if err != nil || unused {
		t.Fatal("same digest at another registry confused with target", unused, err)
	}
	foreign, err := f.p.maintenanceImagesInUse(f.s, "other", []string{image})
	if err != nil || foreign {
		t.Fatal("foreign tenant reference leaked into tenant guard", foreign, err)
	}
}

func TestMaintenanceSummaryUsesCompletedOriginalGCNotWallClockOrRefusal(t *testing.T) {
	row := RegistryMaintenanceRecord{Origin: UserOperation{Change: Change{Action: "gc-registry"}}, Change: RegistryMaintenanceChange{Tenant: "tenant", Run: RegistryRunRef{Spec: registry.Specification{Tenant: "tenant", ID: "private"}}}, State: "done", Result: &RegistryMaintenanceResult{Code: "OK", At: 9000, ReclaimedBytes: 31, Native: [32]byte{1}}}
	row.Change.Operation = "first"
	jobs := RegistryMaintenanceJobs{Records: []RegistryMaintenanceRecord{row}}
	row.Change.Operation = "second"
	row.Result = &RegistryMaintenanceResult{Code: "OK", At: 8000, ReclaimedBytes: 9, Native: [32]byte{2}}
	jobs.Records = append(jobs.Records, row)
	row.Change.Operation, row.State = "failed-gc", "failed"
	row.Result = &RegistryMaintenanceResult{Code: "DENIED", At: 10000}
	jobs.Records = append(jobs.Records, row)
	row.Change.Operation, row.State, row.Result = "pending", "running", nil
	jobs.Records = append(jobs.Records, row)
	got := jobs.Summary("tenant", "private")
	if got == nil || got.LastGCOperation != "second" || got.LastGCAt != 8000 || got.ReclaimedBytes != 9 || got.PendingOperation != "pending" || got.PendingState != "running" || jobs.Summary("other", "private") != nil {
		t.Fatal("GC summary lost completion order/tenant boundary", got)
	}
}

func TestMaintenanceRejectsMixedQueriesBadResultsAndRetargetedSnapshot(t *testing.T) {
	f, spec := readyMaintenanceRegistry(t)
	for _, q := range []RegistryMaintenanceQuery{
		{Action: "gc-registry", ID: spec.ID, Reference: "stable"},
		{Action: "delete-registry-image", ID: spec.ID, Repository: "../escape", Reference: "stable", Digest: "sha256:" + strings.Repeat("a", 64)},
		{Action: "delete-registry-image", ID: spec.ID, Repository: "team/app", Reference: "stable"},
		{Action: "gc-registry", ID: spec.ID, Operation: "already-assigned"},
	} {
		if _, err := f.p.PlanRegistryMaintenance(f.s, f.sessions["manager"], 3, spec.Tenant, q); err == nil {
			t.Fatal("invalid selection accepted", q)
		}
	}
	clipped := f.sessions["manager"]
	clipped.Scopes = []access.Scope{{Tenant: spec.Tenant, Actions: []access.Action{access.Read}}}
	clipped.Signature = ed25519.Sign(f.node, access.SessionBytes(clipped))
	if _, err := f.p.PlanRegistryMaintenance(f.s, clipped, 3, spec.Tenant, RegistryMaintenanceQuery{Action: "gc-registry", ID: spec.ID}); err == nil {
		t.Fatal("reader allowed to create management intent")
	}
	plan, err := f.p.PlanRegistryMaintenance(f.s, f.sessions["manager"], 3, spec.Tenant, RegistryMaintenanceQuery{Action: "gc-registry", ID: spec.ID})
	if err != nil {
		t.Fatal(err)
	}
	change := plan.Change
	change.Operation = "snapshot-gc"
	f.apply("manager", "gc-registry", plan.Expected, change, state.Applied)
	maintenanceReportFixture(t, f, change.Operation, "begin", nil, state.Applied)
	maintenanceReportFixture(t, f, change.Operation, "complete", &RegistryMaintenanceResult{Code: "OK", At: 3000}, state.Forbidden)
	jobs, err := f.p.RegistryMaintenanceJobs(f.s)
	if err != nil {
		t.Fatal(err)
	}
	jobs.Records[0].Change.Run.Generation++
	jobs.Revision++
	raw, _ := json.Marshal(jobs)
	writes, code := writeCheckpoint(f.s, RegistryMaintenanceKey, f.p.Cluster, f.p.TrustRoot, jobs.Revision, raw)
	if code != state.Applied {
		t.Fatal(code)
	}
	// Only this corruption fixture bypasses validation; ordinary FSM commits
	// and snapshot restore must reject the retained unsigned target replacement.
	cmd := state.Command{Kind: state.Module, Actor: "anchor", Epoch: f.s.ModuleEpoch(), RequestID: "corrupted-maintenance-checkpoint", Key: RegistryMaintenanceKey, Expected: f.s.Object(RegistryMaintenanceKey).Revision, Value: "fixed-fixture"}
	corrupt, result, err := state.ApplyReduced(f.s, f.s.Index()+1, cmd, nil, func(state.State, state.Command) (map[string][]byte, state.Code) { return writes, state.Applied })
	if err != nil || result.Code != state.Applied {
		t.Fatal("corruption fixture", result, err)
	}
	if _, err = f.p.RegistryMaintenanceJobs(corrupt); err == nil {
		t.Fatal("unsigned target replacement survived checkpoint decoding")
	}
	if f.p.Validate(f.s, corrupt, cmd) == nil {
		t.Fatal("unsigned target replacement survived FSM/snapshot validation")
	}
}
