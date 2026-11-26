// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

func TestVolumeMoveTargetPreparationBoundIdentitySnapshotAndAppGate(t *testing.T) {
	f, q := moveCore(t)
	f.apply("move", "begin-volume-move", f.core().Revision(), q, state.Applied)
	j, _, _ := f.view().Move(VolumeMoveSelection{Scope: f.scope, ID: q.ID})
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{124}, 32))
	ready := volumes.NativeReady{Schema: 1, Spec: j.Target, Generation: 1, Owner: j.Binding.Target}
	ready.Signature = ed25519.Sign(key, volumes.NativeReadyBytes(ready))
	proof := volumes.TargetPreparation{Binding: j.Binding, Target: ready, Empty: true, NoWriters: true, SpaceChecked: true, ProtocolReady: true}
	proof.Signature = ed25519.Sign(key, volumes.TargetPreparationBytes(proof))
	r := moveReport(t, f, "prepared")
	r.Preparation = &proof
	r.Signature = ed25519.Sign(key, VolumeMoveReportBytes(r))
	raw, _ := json.Marshal(r)
	if _, err := f.p.ResolveVolumeMoveReport(f.s, j.Binding.Source.Key, raw); err == nil {
		t.Fatal("source supplied target preparation")
	}
	bad := r
	badProof := proof
	badProof.SpaceChecked = false
	badProof.Signature = ed25519.Sign(key, volumes.TargetPreparationBytes(badProof))
	bad.Preparation = &badProof
	bad.Signature = ed25519.Sign(key, VolumeMoveReportBytes(bad))
	badRaw, _ := json.Marshal(bad)
	if _, err := f.p.ResolveVolumeMoveReport(f.s, j.Binding.Target.Key, badRaw); err == nil {
		t.Fatal("unchecked target space accepted")
	}
	cmd, err := f.p.ResolveVolumeMoveReport(f.s, j.Binding.Target.Key, raw)
	if err != nil {
		t.Fatal(err)
	}
	next, out, err := state.ApplyAdmitted(f.s, f.s.Index()+1, cmd, f.p.Validate, f.p.Reduce, f.p.AdmitModule)
	if err != nil || out.Code != state.Applied {
		t.Fatal(out, err)
	}
	f.s = next
	_, m, ok := f.view().Move(j.Selection())
	owner, revision := f.core().Owner()
	if !ok || m.Phase != volumes.Prepared || m.Preparation == nil || owner != j.Binding.Source || revision != j.Binding.SourceOwnerRevision || f.core().CheckActivation(j.StagingConsumer()) == nil {
		t.Fatal("preparation changed phase/owner/writer")
	}
	m.Preparation.Signature[0] ^= 1
	_, original, _ := f.view().Move(j.Selection())
	if bytes.Equal(m.Preparation.Signature, original.Preparation.Signature) {
		t.Fatal("preparation view aliases snapshot")
	}
	encoded, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	f.s, err = state.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.p.Volumes(f.s); err != nil {
		t.Fatal("prepared target Snapshot", err)
	}
	if _, err = f.p.VolumeMovePermit(f.s, j.Binding.Source.Key, VolumeMovePermitRequest{Selection: j.Selection(), Kind: "quiesce"}, 2); err == nil {
		t.Fatal("unbound move retired an app")
	}
	app := q
	app.ID = "other"
	app.Target.Materialization = "m-other"
	app.App = &VolumeMoveApp{Operation: "missing", Revision: 1}
	f.apply("missing-app", "begin-volume-move", f.core().Revision(), app, state.Forbidden)
	applyMoveReport(t, f, moveReport(t, f, "fenced"), state.Applied)
}
