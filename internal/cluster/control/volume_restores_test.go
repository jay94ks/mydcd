// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

func restoreCore(t *testing.T) (*backupCoreFixture, VolumeRestoreBegin) {
	t.Helper()
	f := newBackupCore(t)
	f.limits()
	f.begin("one", state.Applied)
	f.commitReport(f.report("one", "ready"), state.Applied)
	backup, _ := f.view().Backup(f.scope, "one")
	target := backup.Binding.Source.Spec
	target.Scope.ID = "restored"
	target.Materialization = "r-copy"
	return f, VolumeRestoreBegin{Backup: VolumeBackupSelection{Scope: f.scope, ID: "one"}, ID: "copy", Target: target, MaxBytes: 32768}
}

func TestVolumeRestorePublicPageExcludesOriginalCredentialsAndStaging(t *testing.T) {
	f, q := restoreCore(t)
	restoreLimits(f, q.MaxBytes, 1)
	f.apply("restore", "begin-volume-restore", 2, q, state.Applied)
	c, err := f.p.Catalog(f.s)
	if err != nil {
		t.Fatal(err)
	}
	page, next, err := f.view().RestorePage(c, "admin", "tenant", "")
	if err != nil || next != "" || len(page) != 1 || page[0].Target != q.Target.Scope || page[0].Phase != "Reserved" {
		t.Fatal("public restore view", page, err)
	}
	raw, _ := json.Marshal(page)
	for _, forbidden := range []string{"Origin", "Session", "Staging", "Consumer", "Signature", q.Target.Materialization} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Fatal("private restore metadata leaked", forbidden)
		}
	}
	backup, _, err := f.view().BackupPage(c, "admin", "tenant", "")
	if err != nil || len(backup) != 1 || backup[0].Owner != q.Target.NodeKey || backup[0].UID != q.Target.UID || backup[0].GID != q.Target.GID || backup[0].Mode != q.Target.Mode {
		t.Fatal("public source restore profile", err)
	}
}
func restoreLimits(f *backupCoreFixture, stageBytes uint64, count uint32) {
	f.t.Helper()
	for _, tenant := range []string{"", "tenant"} {
		limit := f.view().backupLimits[backupLimitKey(tenant, "node-a")]
		f.apply(fmt.Sprintf("staging-limit-%s-%d", tenant, f.s.Index()), "set-volume-backup-limit", limit.Revision, VolumeBackupLimit{Tenant: tenant, Node: "node-a", Bytes: 1 << 20, Count: 2, StagingBytes: stageBytes, StagingCount: count}, state.Applied)
	}
}
func restoreReady(t *testing.T, f *backupCoreFixture, spec volumes.NativeSpec) volumes.NativeReady {
	t.Helper()
	raw, _ := json.Marshal(spec)
	c := engine.Client{Owner: engine.Owner(spec.Scope.Cluster, spec.NodeKey)}
	id, err := c.Identity("volume", volumes.NativeKey(spec), reconcile.Resource{Present: true, Generation: 1, Spec: string(raw)})
	if err != nil {
		t.Fatal(err)
	}
	r := volumes.NativeReady{Schema: 1, Spec: spec, Generation: 1, Owner: volumes.Owner{Node: spec.Node, Key: spec.NodeKey, Native: id.Name}}
	r.Signature = ed25519.Sign(f.node, volumes.NativeReadyBytes(r))
	return r
}
func restoreReport(t *testing.T, f *backupCoreFixture, q VolumeRestoreBegin, kind string) VolumeRestoreReport {
	t.Helper()
	selection := VolumeRestoreSelection{Backup: q.Backup, ID: q.ID}
	j, ok := f.view().Restore(selection)
	if !ok {
		t.Fatal("missing restore")
	}
	r := VolumeRestoreReport{Operation: "restore", Schema: 1, Selection: selection, Binding: j.Binding.Digest(), Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(VolumesKey).Revision, Revision: j.Revision, At: 2, Kind: kind, ArtifactReturned: true}
	r.Closed = volumes.Gone{Scope: q.Target.Scope, Consumer: j.Binding.Consumer, Stopped: true, MountsGone: true}
	r.Closed.Signature = ed25519.Sign(f.node, volumes.GoneBytes(r.Closed))
	if kind == "restored" {
		ready := restoreReady(t, f, q.Target)
		r.Target = &ready
		r.FilesSynced, r.CopyVerified = true, true
	} else {
		r.TargetGone = true
	}
	r.Signature = ed25519.Sign(f.node, VolumeRestoreReportBytes(r))
	return r
}
func commitRestoreReport(t *testing.T, f *backupCoreFixture, r VolumeRestoreReport, want state.Code) state.Result {
	t.Helper()
	raw, _ := json.Marshal(r)
	cmd, err := f.p.ResolveVolumeRestoreReport(f.s, [32]byte(f.node.Public().(ed25519.PublicKey)), raw)
	if err != nil {
		t.Fatal(err)
	}
	next, result, err := state.ApplyAdmitted(f.s, f.s.Index()+1, cmd, f.p.Validate, f.p.Reduce, f.p.AdmitModule)
	if err != nil || result.Code != want {
		t.Fatal("restore report", result.Code, want, err)
	}
	f.s = next
	return result
}

func TestVolumeRestoreAtomicStagingReservationAndBackupHold(t *testing.T) {
	f, q := restoreCore(t)
	f.apply("restore-no-budget", "begin-volume-restore", 2, q, state.ConditionFailed)
	if len(f.view().Restores()) != 0 {
		t.Fatal("partial restore reservation")
	}
	restoreLimits(f, q.MaxBytes, 1)
	f.apply("restore", "begin-volume-restore", 2, q, state.Applied)
	selection := VolumeRestoreSelection{Backup: q.Backup, ID: q.ID}
	j, _ := f.view().Restore(selection)
	if j.Phase != "Reserved" || j.Revision != 1 || f.view().Quiescent() {
		t.Fatal("untracked pending restore")
	}
	if _, ok := f.view().Native(q.Target.Scope.Tenant, q.Target.Scope.App, q.Target.Scope.ID); ok {
		t.Fatal("unverified staging exposed to app")
	}
	f.apply("backup-delete-held", "delete-volume-backup", 2, q.Backup, state.ConditionFailed)
	f.apply("staging-adopt", "create-volume", 0, restoreReady(t, f, q.Target), state.ConditionFailed)
	other := q
	other.ID = "other"
	other.Target.Scope.ID = "other"
	other.Target.Materialization = "r-other"
	f.apply("parallel-source", "begin-volume-restore", 2, other, state.ConditionFailed)
	limit := f.view().backupLimits[backupLimitKey("", "node-a")]
	f.apply("staging-shrink", "set-volume-backup-limit", limit.Revision, VolumeBackupLimit{Node: "node-a", Bytes: 1 << 20, Count: 2}, state.ConditionFailed)
	store := f.view()
	copy, _ := store.Restore(selection)
	copy.Staging[0] = 'x'
	copy.Binding.Origin.Session.Scopes[0].Actions[0] = "forged"
	original, _ := store.Restore(selection)
	if original.Staging[0] != '{' || original.Binding.Origin.Session.Scopes[0].Actions[0] == "forged" {
		t.Fatal("mutable restore view")
	}
	raw, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := state.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	v, err := f.p.Volumes(restored)
	if err != nil {
		t.Fatal("typed restore checkpoint", err)
	}
	if r, ok := v.Restore(selection); !ok || r.Binding.Digest() != j.Binding.Digest() {
		t.Fatal("lost original binding")
	}
}

func TestVolumeRestorePublishesOnlyVerifiedTargetAndOriginalReplay(t *testing.T) {
	f, q := restoreCore(t)
	restoreLimits(f, q.MaxBytes, 1)
	f.apply("restore", "begin-volume-restore", 2, q, state.Applied)
	r := restoreReport(t, f, q, "restored")
	for _, alter := range []func(*VolumeRestoreReport){
		func(r *VolumeRestoreReport) { r.FilesSynced = false }, func(r *VolumeRestoreReport) { r.CopyVerified = false }, func(r *VolumeRestoreReport) { r.ArtifactReturned = false }, func(r *VolumeRestoreReport) { r.TargetGone = true }, func(r *VolumeRestoreReport) { r.Closed.Consumer.Lease.Token++ }, func(r *VolumeRestoreReport) { r.Binding = [32]byte{1} },
	} {
		bad := r
		alter(&bad)
		bad.Signature = ed25519.Sign(f.node, VolumeRestoreReportBytes(bad))
		raw, _ := json.Marshal(bad)
		if _, err := f.p.ResolveVolumeRestoreReport(f.s, q.Target.NodeKey, raw); err == nil {
			t.Fatal("invalid copy/closure proof admitted")
		}
	}
	first := commitRestoreReport(t, f, r, state.Applied)
	second := commitRestoreReport(t, f, r, state.Applied)
	if first.Index != second.Index {
		t.Fatal("original restore report replay changed result")
	}
	registry := f.view()
	ready, ok := registry.Native("tenant", "app", "restored")
	if !ok || ready.Spec != q.Target {
		t.Fatal("verified target not published")
	}
	target, ok := registry.Volume(q.Target.Scope)
	if !ok || len(target.Consumers()) != 0 || target.Revision() != 3 {
		t.Fatal("target restore writer retained/duplicated")
	}
	if len(f.core().Consumers()) != 0 {
		t.Fatal("source Volume changed")
	}
	f.apply("backup-delete-after-restore", "delete-volume-backup", 2, q.Backup, state.Applied)
	f.commitReport(f.report("one", "gone"), state.Applied)
	if _, err := f.p.Volumes(f.s); err != nil {
		t.Fatal("restored target depends on deleted source backup", err)
	}
	limit := f.view().backupLimits[backupLimitKey("", "node-a")]
	f.apply("published-target-budget-held", "set-volume-backup-limit", limit.Revision, VolumeBackupLimit{Node: "node-a", Bytes: 1 << 20, Count: 2}, state.ConditionFailed)
}

func TestVolumeRestoreCancelClosesOriginalAfterRevocation(t *testing.T) {
	f, q := restoreCore(t)
	restoreLimits(f, q.MaxBytes, 1)
	f.apply("restore", "begin-volume-restore", 2, q, state.Applied)
	selection := VolumeRestoreSelection{Backup: q.Backup, ID: q.ID}
	c, err := f.p.Catalog(f.s)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := c.Tenant("tenant")
	f.apply("revoke-node", "set-nodes", tenant.Revision, NodeAssignment{Tenant: "tenant"}, state.Applied)
	if _, err = f.p.VolumeRestorePermit(f.s, q.Target.NodeKey, selection, false); err == nil {
		t.Fatal("revoked copy permit")
	}
	f.apply("restore-cancel", "cancel-volume-restore", 1, selection, state.Applied)
	if _, err = f.p.VolumeRestorePermit(f.s, q.Target.NodeKey, selection, true); err != nil {
		t.Fatal("original cleanup denied", err)
	}
	late := restoreReport(t, f, q, "restored")
	commitRestoreReport(t, f, late, state.ConditionFailed)
	if _, ok := f.view().Native("tenant", "app", "restored"); ok {
		t.Fatal("cancel race published target")
	}
	f.apply("backup-delete-still-held", "delete-volume-backup", 2, q.Backup, state.ConditionFailed)
	r := restoreReport(t, f, q, "cancelled")
	bad := r
	bad.ArtifactReturned = false
	bad.Signature = ed25519.Sign(f.node, VolumeRestoreReportBytes(bad))
	raw, _ := json.Marshal(bad)
	if _, err = f.p.ResolveVolumeRestoreReport(f.s, q.Target.NodeKey, raw); err == nil {
		t.Fatal("released reservation without original artifact return")
	}
	commitRestoreReport(t, f, r, state.Applied)
	if !f.view().Quiescent() {
		t.Fatal("cancelled stage not settled")
	}
	f.apply("backup-delete-after-cancel", "delete-volume-backup", 2, q.Backup, state.Applied)
	if f.view().restoreTargetAvailable(q.Target.Scope) {
		t.Fatal("cancelled target generation reused")
	}
	next := q.Target.Scope
	next.Generation++
	if !f.view().restoreTargetAvailable(next) {
		t.Fatal("explicit fresh target generation blocked")
	}
}

func TestVolumeRestoreSharedBudgetAndTargetSlotAdmission(t *testing.T) {
	f, q := restoreCore(t)
	restoreLimits(f, q.MaxBytes, 1)
	f.begin("two", state.Applied)
	f.commitReport(f.report("two", "ready"), state.Applied)
	f.apply("restore-one", "begin-volume-restore", 2, q, state.Applied)
	other := q
	other.Backup.ID = "two"
	other.ID = "other"
	other.Target.Materialization = "r-other"
	other.Target.Scope.ID = "other"
	f.apply("restore-stage-limit", "begin-volume-restore", 2, other, state.ConditionFailed)
	if len(f.view().Restores()) != 1 {
		t.Fatal("partial second staging reservation")
	}
	wrong := q
	wrong.ID = "foreign"
	wrong.Target.Materialization = "r-foreign"
	wrong.Target.Scope.Tenant = "foreign"
	f.apply("restore-cross-tenant", "begin-volume-restore", 2, wrong, state.Forbidden)
	// Reserved target slots count against normal Volume admission, without
	// allocating hundreds of signed fixtures or exercising native effects.
	if got := f.view().volumeReservations(); got != len(f.view().entries)+1 {
		t.Fatal("staging slot not reserved", got)
	}
}
