// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/tenancy"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

func createCore(t *testing.T) (*backupCoreFixture, VolumeCreate) {
	t.Helper()
	f := newBackupCore(t)
	for _, tenant := range []string{"", "tenant"} {
		f.apply("create-limit-"+tenant, "set-node-quota", 0, tenancy.NodeLimit{Tenant: tenant, Node: "node-a", MaxConsumers: 4}, state.Applied)
	}
	q := VolumeCreate{Scope: f.scope, Node: "node-a", UID: 10001, GID: 10001, Mode: 0750, QuotaMode: "observe"}
	q.Scope.ID = "created"
	return f, q
}

func commitCreation(t *testing.T, f *backupCoreFixture, r VolumeCreateReport, want state.Code) state.Command {
	t.Helper()
	r.Schema, r.Operation, r.Epoch, r.RootRevision, r.At = 1, "create", f.s.ModuleEpoch(), f.s.Object(VolumesKey).Revision, 2
	r.Signature = ed25519.Sign(f.node, VolumeCreateReportBytes(r))
	raw, _ := json.Marshal(r)
	cmd, err := f.p.ResolveVolumeCreateReport(f.s, [32]byte(f.node.Public().(ed25519.PublicKey)), raw)
	if err != nil {
		t.Fatal(err)
	}
	next, result, err := state.ApplyAdmitted(f.s, f.s.Index()+1, cmd, f.p.Validate, f.p.Reduce, f.p.AdmitModule)
	if err != nil || result.Code != want {
		t.Fatal("create report", result, want, err)
	}
	f.s = next
	return cmd
}

func TestVolumeCreateReservationCompetesWithRawRestoreAndPublishesExactReady(t *testing.T) {
	f, q := createCore(t)
	f.apply("reserve-created", "begin-volume-create", 0, q, state.Applied)
	job, ok := f.view().Creation(q.Scope)
	if !ok || job.Phase != "Reserved" || f.view().volumeReservations() != 2 || f.view().Quiescent() {
		t.Fatal("creation not reserved")
	}
	if _, ok := f.view().Native("tenant", "app", "created"); ok || f.view().restoreTargetAvailable(q.Scope) {
		t.Fatal("pending create exposed as usable or restore target")
	}
	f.apply("duplicate", "begin-volume-create", 0, q, state.ConditionFailed)
	f.apply("raw-bypass", "create-volume", 0, volumeFact(t, q.Scope, "node-a", f.node), state.ConditionFailed)
	bad := q
	bad.Scope.ID = "hard"
	bad.QuotaMode = "hard"
	f.apply("hard", "begin-volume-create", 0, bad, state.Invalid)
	owner := [32]byte(f.node.Public().(ed25519.PublicKey))
	permit, err := f.p.VolumeCreatePermit(f.s, owner, q.Scope)
	if err != nil || permit.Spec != job.Spec || permit.Capacity != 4 {
		t.Fatal("fixed creation permit", err)
	}
	if _, err := f.p.VolumeCreatePermit(f.s, [32]byte{1}, q.Scope); err == nil {
		t.Fatal("foreign owner admitted")
	}
	encoded, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	f.s, err = state.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	commitCreation(t, f, VolumeCreateReport{Scope: q.Scope, Revision: 1, Prepared: true}, state.Applied)
	ready := restoreReady(t, f, job.Spec)
	cmd := commitCreation(t, f, VolumeCreateReport{Scope: q.Scope, Revision: 2, Ready: &ready}, state.Applied)
	native, exists := f.view().Native("tenant", "app", "created")
	if !exists || !sameVolumeNative(native, ready) || !f.view().Quiescent() || f.view().volumeReservations() != 2 {
		t.Fatal("native publication changed reservation or original materialization")
	}
	original, known := f.s.LookupResult(cmd)
	_, replay, err := state.ApplyAdmitted(f.s, f.s.Index()+1, cmd, f.p.Validate, f.p.Reduce, f.p.AdmitModule)
	if !known || err != nil || replay != original {
		t.Fatal("lost final ACK changed original result")
	}
}

func TestVolumeCreateCancelFencesLateReadyAndKeepsGenerationFloor(t *testing.T) {
	f, q := createCore(t)
	f.apply("reserve-created", "begin-volume-create", 0, q, state.Applied)
	job, _ := f.view().Creation(q.Scope)
	commitCreation(t, f, VolumeCreateReport{Scope: q.Scope, Revision: 1, Prepared: true}, state.Applied)
	ready := restoreReady(t, f, job.Spec)
	f.apply("cancel", "cancel-volume-create", 2, q.Scope, state.Applied)
	commitCreation(t, f, VolumeCreateReport{Scope: q.Scope, Revision: 2, Ready: &ready}, state.ConditionFailed)
	if _, ok := f.view().Native("tenant", "app", "created"); ok {
		t.Fatal("late Ready escaped cancellation")
	}
	proof := volumes.NativeRemoved{Schema: 1, Scope: q.Scope, Owner: ready.Owner, Key: volumes.NativeKey(job.Spec), Generation: 1, DeleteRevision: 3}
	proof.Signature = ed25519.Sign(f.node, volumes.NativeRemovedBytes(proof))
	commitCreation(t, f, VolumeCreateReport{Scope: q.Scope, Revision: 3, Gone: &proof}, state.Applied)
	if f.view().volumeReservations() != 1 || !f.view().Quiescent() {
		t.Fatal("cancel released no reservation or left work active")
	}
	f.apply("reused-generation", "begin-volume-create", 0, q, state.ConditionFailed)
	q.Scope.Generation++
	f.apply("explicit-next-generation", "begin-volume-create", 0, q, state.Applied)
}

func TestVolumeCreateCurrentRevocationDeniesReadyButAllowsOriginalCleanup(t *testing.T) {
	f, q := createCore(t)
	f.apply("reserve-created", "begin-volume-create", 0, q, state.Applied)
	job, _ := f.view().Creation(q.Scope)
	c, _ := f.p.Catalog(f.s)
	tenant, _ := c.Tenant("tenant")
	f.apply("revoke-placement", "set-nodes", tenant.Revision, NodeAssignment{Tenant: "tenant"}, state.Applied)
	owner := job.Spec.NodeKey
	if _, err := f.p.VolumeCreatePermit(f.s, owner, q.Scope); err == nil {
		t.Fatal("revoked placement got native creation permit")
	}
	commitCreation(t, f, VolumeCreateReport{Scope: q.Scope, Revision: 1, Prepared: true}, state.Forbidden)
	f.apply("cleanup-cancel", "cancel-volume-create", 1, q.Scope, state.Applied)
	if work, err := f.p.VolumeCreatePermit(f.s, owner, q.Scope); err != nil || work.Phase != "Cancelling" {
		t.Fatal("placement revocation blocked original cleanup", err)
	}
}
