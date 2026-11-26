// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

func tenantFixtureState(t *testing.T, f *backupCoreFixture) access.Tenant {
	t.Helper()
	users, err := f.p.Catalog(f.s)
	if err != nil {
		t.Fatal(err)
	}
	tenant, ok := users.Tenant("tenant")
	if !ok {
		t.Fatal("tenant missing")
	}
	return tenant
}
func tenantFixtureReport(t *testing.T, f *backupCoreFixture) TenantRetirementReport {
	t.Helper()
	tenant := tenantFixtureState(t, f)
	original := tenant.Retirement
	if original == nil {
		t.Fatal("original retirement missing")
	}
	owner := [32]byte(f.node.Public().(ed25519.PublicKey))
	proof := access.TenantReport{Cluster: f.p.Cluster, Tenant: tenant.ID, Operation: original.Operation, Node: "node-a", Owner: owner, StartedRevision: original.StartedRevision, InventoryHash: original.InventoryHash, OwnersHash: original.OwnersHash, Sequence: 1, Quiesced: true}
	proof.Signature = ed25519.Sign(f.node, access.TenantReportBytes(proof))
	return TenantRetirementReport{Schema: 1, Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(CatalogKey).Revision, Proof: proof}
}

// These signed facts exercise the product FSM and reusable retirement core.
// They do not claim that a real Docker Volume was removed by this unit test.
func TestTenantRetirementKeepsRetainedDataAndRequiresOriginalOwnerClosure(t *testing.T) {
	f := newBackupCore(t)
	f.apply("other-tenant", "create-tenant", 0, TenantID{ID: "other"}, state.Applied)
	catalog, _ := f.p.Catalog(f.s)
	other, _ := catalog.Tenant("other")
	f.apply("other-node", "set-nodes", other.Revision, NodeAssignment{Tenant: "other", Nodes: []string{"node-a"}}, state.Applied)
	foreign := volumes.Scope{Cluster: f.p.Cluster, Tenant: "other", App: "app", ID: "data", Generation: 1}
	f.apply("other-volume", "create-volume", 0, volumeFact(t, foreign, "node-a", f.node), state.Applied)
	selection := TenantRetirementSelection{Tenant: "tenant", Operation: "tenant-delete"}
	f.apply("retire-begin", "begin-tenant-retirement", tenantFixtureState(t, f).Revision, selection, state.Applied)
	tenant := tenantFixtureState(t, f)
	if tenant.Phase != access.TenantRetiring || tenant.Retirement == nil || len(tenant.Retirement.Targets) < 2 {
		t.Fatal("FSM did not freeze original owner and Volume")
	}
	originalHash := tenant.Retirement.InventoryHash
	status, err := f.p.TenantRetirementStatus(f.s, "tenant", "")
	if err != nil || status.RemainingCount == 0 || status.OwnerCount != 1 {
		t.Fatal("kept data missing from census", status, err)
	}
	report := tenantFixtureReport(t, f)
	raw, _ := json.Marshal(report)
	if _, err := f.p.ResolveTenantRetirementReport(f.s, report.Proof.Owner, raw); err == nil {
		t.Fatal("signed zero skipped retained Volume")
	}
	f.apply("early-finish", "finish-tenant-retirement", tenant.Revision, selection, state.Invalid)
	f.apply("no-new-tenant-work", "begin-volume-create", 0, VolumeCreate{Scope: volumes.Scope{Cluster: f.p.Cluster, Tenant: "tenant", App: "new", ID: "data", Generation: 1}, Node: "node-a", UID: 10001, GID: 10001, Mode: 0700, QuotaMode: "observe"}, state.Forbidden)
	f.apply("explicit-delete", "delete-volume", f.core().Revision(), f.scope, state.Applied)
	work, err := f.p.VolumeDeletePermit(f.s, report.Proof.Owner, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	proof := volumes.NativeRemoved{Schema: 1, Scope: f.scope, Owner: work.Native.Owner, Key: volumes.NativeKey(work.Native.Spec), Generation: work.Native.Generation, DeleteRevision: work.Revision}
	proof.Signature = ed25519.Sign(f.node, volumes.NativeRemovedBytes(proof))
	raw, _ = json.Marshal(VolumeDeleteReport{Operation: "delete", Schema: 1, Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(VolumesKey).Revision, At: 2, Proof: proof})
	command, err := f.p.ResolveVolumeDeleteReport(f.s, report.Proof.Owner, raw)
	if err != nil {
		t.Fatal(err)
	}
	next, result, err := state.ApplyAdmitted(f.s, f.s.Index()+1, command, f.p.Validate, f.p.Reduce, f.p.AdmitModule)
	if err != nil || result.Code != state.Applied {
		t.Fatal("explicit original native closure", result, err)
	}
	f.s = next
	f.apply("missing-owner-finish", "finish-tenant-retirement", tenantFixtureState(t, f).Revision, selection, state.Invalid)
	report = tenantFixtureReport(t, f)
	raw, _ = json.Marshal(report)
	command, err = f.p.ResolveTenantRetirementReport(f.s, report.Proof.Owner, raw)
	if err != nil {
		t.Fatal(err)
	}
	next, result, err = state.ApplyAdmitted(f.s, f.s.Index()+1, command, f.p.Validate, f.p.Reduce, f.p.AdmitModule)
	if err != nil || result.Code != state.Applied {
		t.Fatal("original signed owner closure", result, err)
	}
	f.s = next
	// A lost reply resolves the SAME command, despite its old root CAS.
	replay, err := f.p.ResolveTenantRetirementReport(f.s, report.Proof.Owner, raw)
	if err != nil || replay != command {
		t.Fatal("original report replay changed", err)
	}
	if receipt, found := f.s.LookupResult(replay); !found || receipt != result {
		t.Fatal("original owner receipt lost")
	}
	encoded, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	f.s, err = state.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	f.apply("retire-finish", "finish-tenant-retirement", tenantFixtureState(t, f).Revision, selection, state.Applied)
	tenant = tenantFixtureState(t, f)
	if tenant.Phase != access.TenantDeleted || tenant.Enabled || tenant.Retirement.InventoryHash != originalHash || f.p.tenantRetirementEvidence(f.s, tenant) != nil {
		t.Fatal("tombstone lost original evidence")
	}
	if f.p.Validate(f.s, f.s, state.Command{}) != nil {
		t.Fatal("deleted tenant invalidates terminal historical Volume")
	}
	v, err := f.p.Volumes(f.s)
	if err != nil {
		t.Fatal(err)
	}
	otherVolume, exists := v.Volume(foreign)
	if !exists || otherVolume.Deleted() {
		t.Fatal("other tenant Volume was removed")
	}
	f.apply("no-reused-tenant-id", "create-tenant", 0, TenantID{ID: "tenant"}, state.ConditionFailed)
}

func TestTenantRetirementInputRejectsSuppliedInventoryAndForeignOwner(t *testing.T) {
	if _, err := InputChange([]byte(`{"schema":1,"action":"begin-tenant-retirement","expected":1,"payload":{"Tenant":"tenant","Operation":"remove","Targets":[]}}`), "admin"); err == nil {
		t.Fatal("CLI inventory accepted")
	}
	f := newBackupCore(t)
	f.apply("begin", "begin-tenant-retirement", tenantFixtureState(t, f).Revision, TenantRetirementSelection{Tenant: "tenant", Operation: "remove"}, state.Applied)
	report := tenantFixtureReport(t, f)
	for _, alter := range []func(*TenantRetirementReport){
		func(r *TenantRetirementReport) { r.Proof.Owner = [32]byte{1} },
		func(r *TenantRetirementReport) { r.Proof.InventoryHash = [32]byte{1} },
		func(r *TenantRetirementReport) { r.Proof.Operation = "different" },
		func(r *TenantRetirementReport) { r.Proof.StartedRevision++ },
	} {
		bad := report
		alter(&bad)
		raw, _ := json.Marshal(bad)
		if _, err := f.p.ResolveTenantRetirementReport(f.s, bad.Proof.Owner, raw); err == nil {
			t.Fatal("foreign/stale owner proof accepted")
		}
	}
}
