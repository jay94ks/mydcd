// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

func TestVolumeMoveCopyProofTargetAuthorityAndInactiveStaging(t *testing.T) {
	f, q := moveCore(t)
	f.apply("move", "begin-volume-move", f.core().Revision(), q, state.Applied)
	applyMoveReport(t, f, moveReport(t, f, "fenced"), state.Applied)
	applyMoveReport(t, f, moveReport(t, f, "reader"), state.Applied)
	j, _, _ := f.view().Move(VolumeMoveSelection{Scope: f.scope, ID: q.ID})
	manifest := volumes.Manifest{Binding: j.Binding, Artifact: [32]byte{3}, Bytes: 4096, Files: 2, DataBytes: 17, ReadOnly: true}
	manifest.Signature = ed25519.Sign(f.node, volumes.ManifestBytes(manifest))
	r := moveReport(t, f, "manifest")
	r.Manifest = &manifest
	r.Signature = ed25519.Sign(f.node, VolumeMoveReportBytes(r))
	applyMoveReport(t, f, r, state.Applied)
	targetKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{124}, 32))
	target := volumes.NativeReady{Schema: 1, Spec: j.Target, Generation: 1, Owner: j.Binding.Target}
	target.Signature = ed25519.Sign(targetKey, volumes.NativeReadyBytes(target))
	proof := volumes.CopyProof{Binding: j.Binding, Artifact: manifest.Artifact, Bytes: manifest.Bytes, DigestVerified: true, Synced: true, NoWriters: true}
	proof.Signature = ed25519.Sign(targetKey, volumes.CopyBytes(proof))
	r = moveReport(t, f, "copied")
	r.Copy = &proof
	r.Target = &target
	r.ArtifactReturned = true
	r.Signature = ed25519.Sign(targetKey, VolumeMoveReportBytes(r))
	applyTarget := func(report VolumeMoveReport, want state.Code) {
		t.Helper()
		raw, _ := json.Marshal(report)
		cmd, err := f.p.ResolveVolumeMoveReport(f.s, j.Binding.Target.Key, raw)
		if err != nil {
			t.Fatal(err)
		}
		next, out, err := state.ApplyAdmitted(f.s, f.s.Index()+1, cmd, f.p.Validate, f.p.Reduce, f.p.AdmitModule)
		if err != nil || out.Code != want {
			t.Fatal("target copy report", out.Code, want, err)
		}
		f.s = next
	}
	if f.core().CheckActivation(j.StagingConsumer()) == nil {
		t.Fatal("native staging acquired app Start authority")
	}
	for _, test := range []string{"source-signer", "artifact-reference", "wrong-target"} {
		t.Run(test, func(t *testing.T) {
			bad := r
			ready := target
			caller := j.Binding.Target.Key
			switch test {
			case "source-signer":
				caller = j.Binding.Source.Key
			case "artifact-reference":
				bad.ArtifactReturned = false
			case "wrong-target":
				ready.Spec.Mode = 0700
				ready.Signature = ed25519.Sign(targetKey, volumes.NativeReadyBytes(ready))
				bad.Target = &ready
			}
			bad.Signature = ed25519.Sign(targetKey, VolumeMoveReportBytes(bad))
			raw, _ := json.Marshal(bad)
			if _, err := f.p.ResolveVolumeMoveReport(f.s, caller, raw); err == nil {
				t.Fatal("invalid native copy proof admitted")
			}
		})
	}
	bad := r
	wrong := proof
	wrong.Artifact = [32]byte{9}
	wrong.Signature = ed25519.Sign(targetKey, volumes.CopyBytes(wrong))
	bad.Copy = &wrong
	bad.Signature = ed25519.Sign(targetKey, VolumeMoveReportBytes(bad))
	applyTarget(bad, state.ConditionFailed)
	applyTarget(r, state.Applied)
	_, move, ok := f.view().Move(j.Selection())
	owner, revision := f.core().Owner()
	if !ok || move.Phase != volumes.Verified || move.Verified == nil || owner != j.Binding.Source || revision != j.Binding.SourceOwnerRevision || len(f.core().Consumers()) != 1 || f.core().CheckActivation(j.StagingConsumer()) == nil {
		t.Fatal("copy proof changed owner/writer or lost original source reference")
	}
	if _, err := f.p.VolumeMovePermit(f.s, j.Binding.Target.Key, VolumeMovePermitRequest{Selection: j.Selection(), Kind: "receive"}, 2); err == nil {
		t.Fatal("new target writes after Verified")
	}
	if _, err := f.p.VolumeMovePermit(f.s, j.Binding.Source.Key, VolumeMovePermitRequest{Selection: j.Selection(), Kind: "cleanup"}, j.ExpiresAt); err != nil {
		t.Fatal("verified source cleanup after expiry", err)
	}
	// The plan's expiry no longer blocks starting the app once Verified; this
	// fixture has no app, so that is the first refusal left.
	if got := f.p.ExplainVolumeMoveActivate(f.s, j.Binding.Target.Key, j.Selection(), j.ExpiresAt+60); got != "NO_APP_TARGET" {
		t.Fatal("verified activate after expiry:", got)
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
		t.Fatal("native proof lost through Snapshot", err)
	}
	commit := VolumeMoveCommit{Selection: j.Selection(), OwnerRevision: j.Binding.SourceOwnerRevision, Target: target}
	f.apply("commit-reader-held", "commit-volume-move", f.core().Revision(), commit, state.Forbidden)
	applyMoveReport(t, f, moveReport(t, f, "reader-gone"), state.Applied)
	if len(f.core().Consumers()) != 0 {
		t.Fatal("original reader not settled")
	}
	badCommit := commit
	badCommit.OwnerRevision++
	f.apply("commit-wrong-owner-revision", "commit-volume-move", f.core().Revision(), badCommit, state.ConditionFailed)
	f.apply("commit-original", "commit-volume-move", f.core().Revision(), commit, state.Applied)
	owner, revision = f.core().Owner()
	_, committed, _ := f.view().Move(j.Selection())
	registered, _ := f.view().Native(f.scope.Tenant, f.scope.App, f.scope.ID)
	if owner != j.Binding.Target || revision != committed.CommitRevision || committed.Phase != volumes.OwnerCommitted || committed.Irreversible || VolumeNativeDigest(registered) != VolumeNativeDigest(target) || f.core().CheckActivation(j.StagingConsumer()) == nil {
		t.Fatal("owner/native publication was not atomic or granted Start")
	}
	f.apply("commit-then-cancel", "cancel-volume-move", f.core().Revision(), j.Selection(), state.ConditionFailed)
	f.apply("writer-before-arm", "acquire-volume", f.core().Revision(), VolumeAcquire{Scope: f.scope, Consumer: "database", Generation: 2, Writable: true}, state.ConditionFailed)
	// The old app Goal remains a reference to the retained physical source.
	// This fixed Goal tests storage projection, not a fabricated App claim.
	retained := true
	config := deployment.ComposeVolume{}
	config.Sfc.Node = j.Binding.Source.Node
	config.Sfc.Retain = &retained
	config.Sfc.Quota = "observe"
	config.Sfc.Capacity = deployment.VolumeSize(j.SourceCapacity)
	goal := deployment.GoalCommand{Schema: 1, Cluster: f.p.Cluster, Tenant: f.scope.Tenant, App: f.scope.App, Kind: "volume", Node: j.Binding.Source.Node, Owner: j.Binding.Source.Key}
	goal.Config, _ = json.Marshal(config)
	goalRaw, _ := json.Marshal(goal)
	key := deployment.ResourceKey("volume", f.scope.Tenant, f.scope.App, f.scope.ID)
	candidate, result, err := state.ApplyChecked(f.s, f.s.Index()+1, state.Command{Actor: "anchor", Epoch: 1, RequestID: "original-volume-goal", Key: key, Value: string(goalRaw)}, nil)
	if err != nil || result.Code != state.Applied {
		t.Fatal(result, err)
	}
	v := f.view()
	holds, err := v.originalHolds(candidate)
	if err != nil || len(holds) != 2 || holds[volumeKey(f.scope)].node != j.Binding.Target.Node || holds["move/"+moveKey(j.Selection())].node != j.Binding.Source.Node || v.validateOriginalStorage(candidate) != nil {
		t.Fatal("retained Goal/physical reservation lost", err)
	}
	if v.originalGoalRetainedByMove(f.scope, goal, j.SourceCapacity+1) {
		t.Fatal("retained source capacity inflated")
	}
	goal.Owner = [32]byte{255}
	if v.originalGoalRetainedByMove(f.scope, goal, j.SourceCapacity) {
		t.Fatal("foreign Goal adopted")
	}
	raw, err = state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	f.s, err = state.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.p.Volumes(f.s); err != nil {
		t.Fatal("committed native/owner Snapshot", err)
	}
}
