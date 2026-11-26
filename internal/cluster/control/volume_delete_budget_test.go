// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

func TestRestoreDeletionReturnsStagingReservationOnlyAfterOriginalGone(t *testing.T) {
	f, q := restoreCore(t)
	restoreLimits(f, q.MaxBytes, 1)
	f.apply("restore", "begin-volume-restore", 2, q, state.Applied)
	commitRestoreReport(t, f, restoreReport(t, f, q, "restored"), state.Applied)
	target, ok := f.view().Volume(q.Target.Scope)
	if !ok {
		t.Fatal("missing restored target")
	}
	f.apply("delete-target", "delete-volume", target.Revision(), q.Target.Scope, state.Applied)
	shrink := func(id string, want state.Code) {
		t.Helper()
		old := f.view().backupLimits[backupLimitKey("", "node-a")]
		f.apply(id, "set-volume-backup-limit", old.Revision, VolumeBackupLimit{Node: "node-a", Bytes: old.Bytes, Count: old.Count}, want)
	}
	shrink("before-original-gone", state.ConditionFailed)
	owner := [32]byte(f.node.Public().(ed25519.PublicKey))
	work, err := f.p.VolumeDeletePermit(f.s, owner, q.Target.Scope)
	if err != nil {
		t.Fatal(err)
	}
	proof := volumes.NativeRemoved{Schema: 1, Scope: q.Target.Scope, Owner: work.Native.Owner, Key: volumes.NativeKey(q.Target), Generation: work.Native.Generation, DeleteRevision: work.Revision}
	proof.Signature = ed25519.Sign(f.node, volumes.NativeRemovedBytes(proof))
	raw, _ := json.Marshal(VolumeDeleteReport{Schema: 1, Operation: "delete", Epoch: 1, RootRevision: f.s.Object(VolumesKey).Revision, At: 2, Proof: proof})
	cmd, err := f.p.ResolveVolumeDeleteReport(f.s, owner, raw)
	if err != nil {
		t.Fatal(err)
	}
	next, result, err := state.ApplyAdmitted(f.s, f.s.Index()+1, cmd, f.p.Validate, f.p.Reduce, f.p.AdmitModule)
	if err != nil || result.Code != state.Applied {
		t.Fatal("Gone publication", result, err)
	}
	f.s = next
	shrink("after-original-gone", state.Applied)
	job, ok := f.view().Restore(VolumeRestoreSelection{Backup: q.Backup, ID: q.ID})
	if !ok || job.Phase != "Restored" || job.Report == nil || f.view().volumeReservations() != 1 {
		t.Fatal("budget release erased restore history or original source")
	}
}
