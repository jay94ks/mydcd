// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/imagesource"
)

func maintenanceSourceFixture(t *testing.T) (*nodeStorageFixture, RegistryMaintenanceQuery) {
	t.Helper()
	f, _ := registryFixture(t)
	session := f.sessions["manager"]
	session.Scopes[0].Actions = append(session.Scopes[0].Actions, access.Deploy)
	session.Signature = ed25519.Sign(f.node, access.SessionBytes(session))
	f.sessions["manager"] = session
	spec := imagesource.Source{Tenant: "tenant", ID: "private", Authority: "external.example", Repository: "team/**", Enabled: true, Auth: "none"}
	f.apply("manager", "put-external-registry", 0, ExternalRegistryPut{Spec: spec}, state.Applied)
	bind, err := f.p.PlanExternalRegistryBind(f.s, session, 2, "tenant", spec.ID, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	f.apply("manager", "bind-external-registry", bind.Expected, bind.Selection, state.Applied)
	digest := "sha256:" + strings.Repeat("a", 64)
	return f, RegistryMaintenanceQuery{Action: "delete-registry-image", External: true, ID: spec.ID, Repository: "team/app", Reference: digest, Digest: digest}
}

func TestExternalMaintenanceSharesJobFenceAndRetainsEvidenceAcrossReaderClosure(t *testing.T) {
	f, q := maintenanceSourceFixture(t)
	plan, err := f.p.PlanRegistryMaintenance(f.s, f.sessions["manager"], 3, "tenant", q)
	if err != nil || plan.Change.External == nil || plan.Expected != 2 || plan.Change.ExpectedRevision() != 2 || plan.Change.Authority() != "external.example" || plan.Change.Query(q.Action) != q {
		t.Fatal("approved external source plan", plan, err)
	}
	change := plan.Change
	change.Operation = "external-delete-original"
	if !change.Valid(f.p.Cluster, q.Action) {
		t.Fatal("frozen external target invalid")
	}
	f.apply("manager", q.Action, plan.Expected, change, state.Applied)
	if held, err := f.p.ExternalRegistryMaintenancePending(f.s, "tenant", q.ID); err != nil || !held {
		t.Fatal("external original missing pending fence", held, err)
	}
	if held, err := f.p.RegistryMaintenancePending(f.s, "tenant", q.ID); err != nil || held {
		t.Fatal("external source confused with same-name managed registry", held, err)
	}
	if err = f.p.imageCacheAvailable(f.s, "node-b", "external.example/team/app@"+q.Digest); err == nil {
		t.Fatal("new app reference crossed external delete fence")
	}
	maintenanceReportFixture(t, f, change.Operation, "begin", nil, state.Applied)
	work, err := f.p.RegistryMaintenanceWork(f.s, change.OwnerKey(), RegistryMaintenanceWorkRequest{Operation: change.Operation, At: 3})
	if err != nil || !work.Allowed || work.Change.External == nil || work.Change.External.ReadSet != change.External.ReadSet {
		t.Fatal("original installed reader work", work, err)
	}
	// Source revocation stops new I/O. A signed real local I/O join may return
	// source usage, but cannot settle an uncertain remote image effect.
	f.apply("manager", "delete-external-registry", 2, RegistrySelection{Tenant: "tenant", ID: q.ID}, state.Applied)
	maintenanceReportFixture(t, f, change.Operation, "uncertain", nil, state.Applied)
	work, err = f.p.RegistryMaintenanceWork(f.s, change.OwnerKey(), RegistryMaintenanceWorkRequest{Operation: change.Operation, At: 3})
	if err != nil || work.Allowed || work.State != "unknown" {
		t.Fatal("unknown operation authorized a fresh external DELETE", work, err)
	}
	raw, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	f.s, err = state.Decode(raw)
	if err != nil || f.p.Validate(f.s, f.s, state.Command{}) != nil {
		t.Fatal("unknown original did not survive snapshot", err)
	}
	entries, err := f.p.ExternalRegistries(f.s)
	if err != nil || len(entries) != 1 || entries[0].Reader == nil {
		t.Fatal("revocation erased pending reader evidence", entries, err)
	}
	reader := entries[0].Reader
	proof := ExternalRegistryReaderClosed{Schema: 1, Cluster: f.p.Cluster, Owner: reader.Owner, Tenant: "tenant", ID: q.ID, Generation: reader.Generation, Index: f.s.Index(), Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(ExternalRegistriesKey).Revision, At: 3, Closed: true}
	proof.Signature = ed25519.Sign(f.node, ExternalRegistryReaderClosedBytes(proof))
	cmd, err := proof.Command()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.p.ResolveExternalRegistryClose(f.s, proof.Owner, []byte(cmd.Value)); err != nil {
		t.Fatal("actual source I/O join unnecessarily blocked by remote uncertainty", err)
	}
	next, result, err := state.ApplyTransactional(f.s, f.s.Index()+1, cmd, f.p.Validate, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
	if err != nil || result.Code != state.Applied {
		t.Fatal("original signed reader closure", result, err)
	}
	f.s = next
	entries, err = f.p.ExternalRegistries(f.s)
	if err != nil || entries[0].Reader != nil || entries[0].Closed == nil || entries[0].Closed.Reader.Generation != change.External.Selection.Generation {
		t.Fatal("closed source lost original reader evidence", err)
	}
	if held, err := f.p.ExternalRegistryMaintenancePending(f.s, "tenant", q.ID); err != nil || !held {
		t.Fatal("local I/O join settled the remote image operation", held, err)
	}
	maintenanceReportFixture(t, f, change.Operation, "complete", &RegistryMaintenanceResult{Code: "DENIED", At: 3000}, state.Forbidden)
	// An original positive receipt can settle the same job, even after source
	// revocation. This fixture simulates that owner proof; it does not claim a
	// remote server can synthesize one from a later 404.
	maintenanceReportFixture(t, f, change.Operation, "complete", &RegistryMaintenanceResult{Code: "OK", At: 3000, Native: [32]byte{1}}, state.Applied)
	jobs, err := f.p.RegistryMaintenanceJobs(f.s)
	if err != nil || jobs.Summary("tenant", q.ID) != nil {
		t.Fatal("external delete polluted managed registry GC summary", err)
	}
}

func TestExternalMaintenanceCurrentSpecificityReadSetAndScopeAreFrozen(t *testing.T) {
	f, q := maintenanceSourceFixture(t)
	plan, err := f.p.PlanRegistryMaintenance(f.s, f.sessions["manager"], 3, "tenant", q)
	if err != nil {
		t.Fatal(err)
	}
	change := plan.Change
	change.Operation = "source-before-narrower-definition"
	for _, bad := range []RegistryMaintenanceQuery{
		{Action: "gc-registry", External: true, ID: q.ID},
		{Action: q.Action, ID: q.ID, Repository: q.Repository, Reference: q.Reference, Digest: q.Digest},
		{Action: q.Action, External: true, ID: q.ID, Repository: "foreign/app", Reference: q.Reference, Digest: q.Digest},
	} {
		if _, err = f.p.PlanRegistryMaintenance(f.s, f.sessions["manager"], 3, "tenant", bad); err == nil {
			t.Fatal("wrong managed/external or repository scope accepted", bad)
		}
	}
	changed := change
	copy := *changed.External
	changed.External = &copy
	changed.External.ReadSet[0] ^= 1
	f.apply("manager", q.Action, plan.Expected, changed, state.ConditionFailed)
	narrow := imagesource.Source{Tenant: "tenant", ID: "narrow", Authority: "external.example", Repository: "team/app", Enabled: true, Auth: "none"}
	f.apply("manager", "put-external-registry", 0, ExternalRegistryPut{Spec: narrow}, state.Applied)
	f.apply("manager", q.Action, plan.Expected, change, state.ConditionFailed)
	if _, err = f.p.PlanRegistryMaintenance(f.s, f.sessions["manager"], 3, "tenant", q); err == nil {
		t.Fatal("broader source deleted through a newly narrower definition")
	}
}

func TestExternalUnknownTargetCannotBeBypassedWithNewNarrowerSourceID(t *testing.T) {
	f, q := maintenanceSourceFixture(t)
	plan, err := f.p.PlanRegistryMaintenance(f.s, f.sessions["manager"], 3, "tenant", q)
	if err != nil {
		t.Fatal(err)
	}
	change := plan.Change
	change.Operation = "old-source-unknown-delete"
	f.apply("manager", q.Action, plan.Expected, change, state.Applied)
	maintenanceReportFixture(t, f, change.Operation, "begin", nil, state.Applied)
	maintenanceReportFixture(t, f, change.Operation, "uncertain", nil, state.Applied)
	narrow := imagesource.Source{Tenant: "tenant", ID: "narrow", Authority: "external.example", Repository: "team/app", Enabled: true, Auth: "none"}
	f.apply("manager", "put-external-registry", 0, ExternalRegistryPut{Spec: narrow}, state.Applied)
	bind, err := f.p.PlanExternalRegistryBind(f.s, f.sessions["manager"], 3, "tenant", narrow.ID, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	f.apply("manager", "bind-external-registry", bind.Expected, bind.Selection, state.Applied)
	q.ID = narrow.ID
	if _, err := f.p.PlanRegistryMaintenance(f.s, f.sessions["manager"], 3, "tenant", q); err == nil {
		t.Fatal("new source ID bypassed the original unknown image fence")
	}
	target, err := f.p.externalMaintenanceTarget(f.s, "tenant", narrow.ID, q.Repository, 3)
	if err != nil {
		t.Fatal(err)
	}
	replacement := RegistryMaintenanceChange{Tenant: "tenant", Operation: "not-a-new-image-lifetime", Repository: q.Repository, Reference: q.Reference, Digest: q.Digest, External: &target}
	f.apply("manager", q.Action, target.Revision, replacement, state.ConditionFailed)
}
