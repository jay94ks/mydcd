// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

func signedMoveReport(f *backupCoreFixture, job VolumeMove, kind string, key ed25519.PrivateKey) VolumeMoveReport {
	r := VolumeMoveReport{Operation: "move", Schema: 1, Selection: job.Selection(), Binding: job.Digest(), Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(VolumesKey).Revision, Revision: f.core().Revision(), At: 2, Kind: kind}
	r.Signature = ed25519.Sign(key, VolumeMoveReportBytes(r))
	return r
}

func completedMoveCore(t *testing.T) (*backupCoreFixture, VolumeMove, ed25519.PrivateKey) {
	t.Helper()
	f, job, targetKey := activeMoveCore(t)
	for _, owner := range []volumes.Owner{job.Binding.Source, job.Binding.Target} {
		kind, key := "cleanup-source", f.node
		if owner == job.Binding.Target {
			kind, key = "cleanup-target", targetKey
		}
		proof := volumes.CleanupProof{Binding: job.Binding, Owner: owner, TransferClosed: true, RetainedFenced: owner == job.Binding.Source}
		proof.Signature = ed25519.Sign(key, volumes.CleanupBytes(proof))
		r := signedMoveReport(f, job, kind, key)
		r.Cleanup = &proof
		r.Signature = ed25519.Sign(key, VolumeMoveReportBytes(r))
		applyMoveOwnerReport(t, f, owner.Key, r, state.Applied)
	}
	return f, job, targetKey
}

func TestMoveHistoryAllowsFreshReverseCommitAndRetainsEveryOriginalNative(t *testing.T) {
	f, first, sourceKey := completedMoveCore(t)
	writer := f.core().Consumers()[0]
	gone := volumes.Gone{Scope: f.scope, Consumer: writer, Stopped: true, MountsGone: true}
	gone.Signature = ed25519.Sign(sourceKey, volumes.GoneBytes(gone))
	f.apply("close-first-target-writer", "release-volume", f.core().Revision(), gone, state.Applied)
	target := first.Source.Spec
	target.Materialization = "m-back"
	_, ownerRevision := f.core().Owner()
	q := VolumeMoveBegin{Scope: f.scope, ID: "back", OwnerRevision: ownerRevision, Target: target, Compatibility: first.Binding.Compatibility, MaxBytes: first.Binding.MaxBytes, MaxEntries: first.MaxEntries, CapacityBytes: first.CapacityBytes, ExpiresAt: first.ExpiresAt}
	// A reverse copy cannot borrow the retained old source's physical capacity.
	f.apply("reverse-needs-extra-capacity", "begin-volume-move", f.core().Revision(), q, state.ConditionFailed)
	for _, tenant := range []string{"", f.scope.Tenant} {
		limit := f.view().backupLimits[backupLimitKey(tenant, target.Node)]
		expected := limit.Revision
		limit.Revision, limit.Owner = 0, [32]byte{}
		limit.Original = &OriginalVolumeLimit{Bytes: 2 * first.CapacityBytes, Count: 2}
		f.apply("reverse-capacity-"+tenant, "set-volume-backup-limit", expected, limit, state.Applied)
	}
	f.apply("reverse-original", "begin-volume-move", f.core().Revision(), q, state.Applied)
	job, _, ok := f.view().Move(VolumeMoveSelection{Scope: f.scope, ID: q.ID})
	if !ok || job.Source.Spec != first.Target || job.Binding.Target.Native == first.Binding.Source.Native {
		t.Fatal("reverse reused the obsolete retained source or changed current source")
	}
	fence := volumes.FenceProof{Binding: job.Binding, FenceThrough: ownerRevision, Stopped: true, MountsGone: true, StartsSettled: true, Synced: true}
	fence.Signature = ed25519.Sign(sourceKey, volumes.FenceBytes(fence))
	r := signedMoveReport(f, job, "fenced", sourceKey)
	r.Fence = &fence
	r.Signature = ed25519.Sign(sourceKey, VolumeMoveReportBytes(r))
	applyMoveOwnerReport(t, f, job.Binding.Source.Key, r, state.Applied)
	applyMoveOwnerReport(t, f, job.Binding.Source.Key, signedMoveReport(f, job, "reader", sourceKey), state.Applied)
	manifest := volumes.Manifest{Binding: job.Binding, Artifact: [32]byte{29}, Bytes: 4096, Files: 2, DataBytes: 17, ReadOnly: true}
	manifest.Signature = ed25519.Sign(sourceKey, volumes.ManifestBytes(manifest))
	r = signedMoveReport(f, job, "manifest", sourceKey)
	r.Manifest = &manifest
	r.Signature = ed25519.Sign(sourceKey, VolumeMoveReportBytes(r))
	applyMoveOwnerReport(t, f, job.Binding.Source.Key, r, state.Applied)
	ready := volumes.NativeReady{Schema: 1, Spec: job.Target, Generation: 1, Owner: job.Binding.Target}
	ready.Signature = ed25519.Sign(f.node, volumes.NativeReadyBytes(ready))
	copy := volumes.CopyProof{Binding: job.Binding, Artifact: manifest.Artifact, Bytes: manifest.Bytes, DigestVerified: true, Synced: true, NoWriters: true}
	copy.Signature = ed25519.Sign(f.node, volumes.CopyBytes(copy))
	r = signedMoveReport(f, job, "copied", f.node)
	r.Target, r.Copy, r.ArtifactReturned = &ready, &copy, true
	r.Signature = ed25519.Sign(f.node, VolumeMoveReportBytes(r))
	applyMoveOwnerReport(t, f, job.Binding.Target.Key, r, state.Applied)
	reader, ok := f.core().MoveReader(job.Binding)
	if !ok {
		t.Fatal("reverse original reader lost")
	}
	closed := volumes.Gone{Scope: f.scope, Consumer: reader, Stopped: true, MountsGone: true}
	closed.Signature = ed25519.Sign(sourceKey, volumes.GoneBytes(closed))
	r = signedMoveReport(f, job, "reader-gone", sourceKey)
	r.Closed = &closed
	r.Signature = ed25519.Sign(sourceKey, VolumeMoveReportBytes(r))
	applyMoveOwnerReport(t, f, job.Binding.Source.Key, r, state.Applied)
	f.apply("reverse-owner", "commit-volume-move", f.core().Revision(), VolumeMoveCommit{Selection: job.Selection(), OwnerRevision: ownerRevision, Target: ready}, state.Applied)
	for _, scope := range []VolumeMoveSelection{first.Selection(), job.Selection()} {
		if _, _, ok := f.view().Move(scope); !ok {
			t.Fatal("later owner commit erased an original move")
		}
	}
	native, ok := f.view().Native(f.scope.Tenant, f.scope.App, f.scope.ID)
	holds, err := f.view().originalHolds(f.s)
	if !ok || native.Spec != job.Target || native.Owner == first.Binding.Source || len(f.core().Retained()) != 2 || err != nil || len(holds) != 3 {
		t.Fatal("reverse lost fresh target or either retained physical source", err)
	}
	raw, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	f.s, err = state.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.p.Volumes(f.s); err != nil {
		t.Fatal("reverse native history did not survive Snapshot", err)
	}
	// Keep individually signed source/target metadata and the original user
	// envelope valid, but contradict the previous committed target's mode.
	// This tests historical reference validation, not a bad-signature shortcut.
	v := f.view()
	bad := v.moves[moveKey(job.Selection())]
	bad.Source.Spec.Mode = 0700
	bad.Source.Signature = ed25519.Sign(sourceKey, volumes.NativeReadyBytes(bad.Source))
	bad.Target.Mode = 0700
	var begin VolumeMoveBegin
	if err = json.Unmarshal(bad.Origin.Change.Payload, &begin); err != nil {
		t.Fatal(err)
	}
	begin.Target = bad.Target
	bad.Origin.Change.Payload, _ = json.Marshal(begin)
	bad.Origin.Signature = ed25519.Sign(f.admin, OperationBytes(bad.Origin))
	if bad.Verify() != nil {
		t.Fatal("history counterexample must retain valid individual signatures")
	}
	v.moves[moveKey(bad.Selection())] = bad
	e := v.entries[volumeKey(f.scope)]
	e.Native.Spec = bad.Target
	e.Native.Signature = ed25519.Sign(f.node, volumes.NativeReadyBytes(e.Native))
	v.entries[volumeKey(f.scope)] = e
	if f.p.validateMoves(v) == nil {
		t.Fatal("historical source spec replaced the prior committed physical target")
	}
}
