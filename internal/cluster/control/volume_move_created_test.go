// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

// A volume made by a creation job keeps that job's Ready record. Committing
// a move changes the volume's native, and the old record must stay valid.
func TestMoveCommitKeepsCreationReadyHistoryValid(t *testing.T) {
	f, base := moveCore(t)
	for _, tenant := range []string{"", "tenant"} {
		f.apply("create-limit-"+tenant, "set-node-quota", 0, tenancy.NodeLimit{Tenant: tenant, Node: "node-a", MaxConsumers: 4}, state.Applied)
	}
	for _, tenant := range []string{"", "tenant"} {
		limit := f.view().backupLimits[backupLimitKey(tenant, "node-a")]
		expected := limit.Revision
		limit.Revision, limit.Owner = 0, [32]byte{}
		limit.Original = &OriginalVolumeLimit{Bytes: 4 * 65536, Count: 4}
		f.apply("create-capacity-"+tenant, "set-volume-backup-limit", expected, limit, state.Applied)
	}
	q := VolumeCreate{Scope: f.scope, Node: "node-a", UID: 10001, GID: 10001, Mode: 0750, QuotaMode: "observe", CapacityBytes: 65536}
	q.Scope.ID = "created"
	f.apply("reserve-created", "begin-volume-create", 0, q, state.Applied)
	job, _ := f.view().Creation(q.Scope)
	commitCreation(t, f, VolumeCreateReport{Scope: q.Scope, Revision: 1, Prepared: true}, state.Applied)
	ready := restoreReady(t, f, job.Spec)
	commitCreation(t, f, VolumeCreateReport{Scope: q.Scope, Revision: 2, Ready: &ready}, state.Applied)
	f.scope = q.Scope

	target := ready.Spec
	target.Node, target.NodeKey, target.Materialization = "node-b", base.Target.NodeKey, "m-move"
	_, revision := f.core().Owner()
	begin := base
	begin.Scope, begin.OwnerRevision, begin.Target = f.scope, revision, target
	f.apply("move", "begin-volume-move", f.core().Revision(), begin, state.Applied)
	applyMoveReport(t, f, moveReport(t, f, "fenced"), state.Applied)
	applyMoveReport(t, f, moveReport(t, f, "reader"), state.Applied)
	j, _, _ := f.view().Move(VolumeMoveSelection{Scope: f.scope, ID: begin.ID})
	manifest := volumes.Manifest{Binding: j.Binding, Artifact: [32]byte{18}, Bytes: 4096, Files: 2, DataBytes: 17, ReadOnly: true}
	manifest.Signature = ed25519.Sign(f.node, volumes.ManifestBytes(manifest))
	r := moveReport(t, f, "manifest")
	r.Manifest = &manifest
	r.Signature = ed25519.Sign(f.node, VolumeMoveReportBytes(r))
	applyMoveReport(t, f, r, state.Applied)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{124}, 32))
	moved := volumes.NativeReady{Schema: 1, Spec: j.Target, Generation: 1, Owner: j.Binding.Target}
	moved.Signature = ed25519.Sign(key, volumes.NativeReadyBytes(moved))
	copy := volumes.CopyProof{Binding: j.Binding, Artifact: manifest.Artifact, Bytes: manifest.Bytes, DigestVerified: true, Synced: true, NoWriters: true}
	copy.Signature = ed25519.Sign(key, volumes.CopyBytes(copy))
	r = moveReport(t, f, "copied")
	r.Copy, r.Target, r.ArtifactReturned = &copy, &moved, true
	r.Signature = ed25519.Sign(key, VolumeMoveReportBytes(r))
	applyMoveOwnerReport(t, f, j.Binding.Target.Key, r, state.Applied)
	applyMoveReport(t, f, moveReport(t, f, "reader-gone"), state.Applied)

	f.apply("commit", "commit-volume-move", f.core().Revision(), VolumeMoveCommit{Selection: j.Selection(), OwnerRevision: j.Binding.SourceOwnerRevision, Target: moved}, state.Applied)
	if native, _ := f.view().Native("tenant", "app", "created"); !sameVolumeNative(native, moved) {
		t.Fatal("move did not publish the target native")
	}
	if c, ok := f.view().Creation(q.Scope); !ok || c.Phase != "Ready" || !sameVolumeNative(*c.Ready, ready) {
		t.Fatal("creation history changed")
	}
}
