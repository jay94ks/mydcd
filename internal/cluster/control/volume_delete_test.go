// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

func TestVolumeDeleteAuthorityRetainsBackupAndRequiresExactNativeGone(t *testing.T) {
	f := newBackupCore(t)
	f.limits()
	f.begin("one", state.Applied)
	f.apply("busy-delete", "delete-volume", f.core().Revision(), f.scope, state.ConditionFailed)
	f.commitReport(f.report("one", "ready"), state.Applied)
	f.apply("delete", "delete-volume", f.core().Revision(), f.scope, state.Applied)
	if !f.core().Deleting() || f.view().Quiescent() {
		t.Fatal("deletion not retained as pending work")
	}
	f.begin("after-delete", state.ConditionFailed)
	owner := [32]byte(f.node.Public().(ed25519.PublicKey))
	work, err := f.p.VolumeDeletePermit(f.s, owner, f.scope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.p.VolumeDeletePermit(f.s, [32]byte{1}, f.scope); err == nil {
		t.Fatal("foreign member obtained delete permit")
	}
	proof := volumes.NativeRemoved{Schema: 1, Scope: f.scope, Owner: work.Native.Owner, Key: volumes.NativeKey(work.Native.Spec), Generation: work.Native.Generation, DeleteRevision: work.Revision}
	for _, mutate := range []func(*volumes.NativeRemoved){
		func(p *volumes.NativeRemoved) { p.Key += "/other" },
		func(p *volumes.NativeRemoved) { p.Generation++ },
		func(p *volumes.NativeRemoved) { p.DeleteRevision++ },
	} {
		bad := proof
		mutate(&bad)
		bad.Signature = ed25519.Sign(f.node, volumes.NativeRemovedBytes(bad))
		raw, _ := json.Marshal(VolumeDeleteReport{Schema: 1, Operation: "delete", Epoch: 1, RootRevision: f.s.Object(VolumesKey).Revision, At: 2, Proof: bad})
		if _, err := f.p.ResolveVolumeDeleteReport(f.s, owner, raw); err == nil {
			t.Fatal("wrong original native accepted")
		}
	}
	proof.Signature = ed25519.Sign(f.node, volumes.NativeRemovedBytes(proof))
	raw, _ := json.Marshal(VolumeDeleteReport{Schema: 1, Operation: "delete", Epoch: 1, RootRevision: f.s.Object(VolumesKey).Revision, At: 2, Proof: proof})
	cmd, err := f.p.ResolveVolumeDeleteReport(f.s, owner, raw)
	if err != nil {
		t.Fatal(err)
	}
	next, result, err := state.ApplyAdmitted(f.s, f.s.Index()+1, cmd, f.p.Validate, f.p.Reduce, f.p.AdmitModule)
	if err != nil || result.Code != state.Applied {
		t.Fatal("native Gone not published", result, err)
	}
	f.s = next
	encoded, err := state.Encode(next)
	if err != nil {
		t.Fatal(err)
	}
	f.s, err = state.Decode(encoded)
	if err != nil || !f.core().Deleted() {
		t.Fatal("deleted tombstone lost after Snapshot", err)
	}
	if _, ok := f.view().Native("tenant", "app", "data"); ok {
		t.Fatal("deleted original exposed as usable native")
	}
	backup, ok := f.view().Backup(f.scope, "one")
	if !ok || backup.Phase != "Ready" || !f.view().Quiescent() {
		t.Fatal("independent backup erased or pending deletion lost")
	}
	_, replay, err := state.ApplyAdmitted(f.s, f.s.Index()+1, cmd, f.p.Validate, f.p.Reduce, f.p.AdmitModule)
	if err != nil || replay != result {
		t.Fatal("original Gone result changed", err)
	}
}
