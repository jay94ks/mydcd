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

func applyMoveOwnerReport(t *testing.T, f *backupCoreFixture, caller [32]byte, r VolumeMoveReport, want state.Code) {
	t.Helper()
	raw, _ := json.Marshal(r)
	cmd, err := f.p.ResolveVolumeMoveReport(f.s, caller, raw)
	if err != nil {
		t.Fatal(err)
	}
	next, result, err := state.ApplyAdmitted(f.s, f.s.Index()+1, cmd, f.p.Validate, f.p.Reduce, f.p.AdmitModule)
	if err != nil || result.Code != want {
		t.Fatal("move owner report", r.Kind, result.Code, want, err)
	}
	f.s = next
}

// Only the final activation input is a signed pure-core fixture. This tests
// report authorization/CAS/storage, not an actual native Task or the app
// activation producer, which the normal Runtime fixture covers separately.
func verifiedMoveCore(t *testing.T) (*backupCoreFixture, VolumeMove, ed25519.PrivateKey, volumes.NativeReady) {
	t.Helper()
	f, q := moveCore(t)
	f.apply("move", "begin-volume-move", f.core().Revision(), q, state.Applied)
	applyMoveReport(t, f, moveReport(t, f, "fenced"), state.Applied)
	applyMoveReport(t, f, moveReport(t, f, "reader"), state.Applied)
	j, _, _ := f.view().Move(VolumeMoveSelection{Scope: f.scope, ID: q.ID})
	manifest := volumes.Manifest{Binding: j.Binding, Artifact: [32]byte{18}, Bytes: 4096, Files: 2, DataBytes: 17, ReadOnly: true}
	manifest.Signature = ed25519.Sign(f.node, volumes.ManifestBytes(manifest))
	r := moveReport(t, f, "manifest")
	r.Manifest = &manifest
	r.Signature = ed25519.Sign(f.node, VolumeMoveReportBytes(r))
	applyMoveReport(t, f, r, state.Applied)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{124}, 32))
	ready := volumes.NativeReady{Schema: 1, Spec: j.Target, Generation: 1, Owner: j.Binding.Target}
	ready.Signature = ed25519.Sign(key, volumes.NativeReadyBytes(ready))
	copy := volumes.CopyProof{Binding: j.Binding, Artifact: manifest.Artifact, Bytes: manifest.Bytes, DigestVerified: true, Synced: true, NoWriters: true}
	copy.Signature = ed25519.Sign(key, volumes.CopyBytes(copy))
	r = moveReport(t, f, "copied")
	r.Copy, r.Target, r.ArtifactReturned = &copy, &ready, true
	r.Signature = ed25519.Sign(key, VolumeMoveReportBytes(r))
	applyMoveOwnerReport(t, f, j.Binding.Target.Key, r, state.Applied)
	applyMoveReport(t, f, moveReport(t, f, "reader-gone"), state.Applied)
	return f, j, key, ready
}

func activeMoveCore(t *testing.T) (*backupCoreFixture, VolumeMove, ed25519.PrivateKey) {
	t.Helper()
	f, j, key, ready := verifiedMoveCore(t)
	f.apply("commit", "commit-volume-move", f.core().Revision(), VolumeMoveCommit{Selection: j.Selection(), OwnerRevision: j.Binding.SourceOwnerRevision, Target: ready}, state.Applied)
	c, err := f.p.Catalog(f.s)
	if err != nil {
		t.Fatal(err)
	}
	v := f.view()
	e := v.entries[volumeKey(f.scope)]
	e.State, err = e.State.Arm(c, "admin", j.Binding.ID, e.State.Revision())
	if err != nil {
		t.Fatal(err)
	}
	var writer volumes.Consumer
	e.State, writer, err = e.State.Acquire(c, "admin", e.State.Revision(), "target-task", 2, true)
	if err != nil {
		t.Fatal(err)
	}
	active := volumes.ActiveProof{Binding: j.Binding, Consumer: writer, Running: true}
	active.Signature = ed25519.Sign(key, volumes.ActiveBytes(active))
	e.State, err = e.State.RecordActive(active)
	if err != nil {
		t.Fatal(err)
	}
	e.Grants = []volumeGrant{{Consumer: writer, Principal: "admin"}}
	v.entries[volumeKey(f.scope)] = e
	writes, code := f.p.volumeCheckpoint(f.s, v)
	if code != state.Applied {
		t.Fatal(code)
	}
	var result state.Result
	f.s, result, err = state.ApplyReduced(f.s, f.s.Index()+1, state.Command{Kind: state.Module, Actor: "anchor", Epoch: f.s.ModuleEpoch(), RequestID: "active-core-fixture", Key: VolumesKey, Expected: f.s.Object(VolumesKey).Revision, Value: "fixture"}, f.p.Validate, func(state.State, state.Command) (map[string][]byte, state.Code) { return writes, state.Applied })
	if err != nil || result.Code != state.Applied {
		t.Fatal("publish active fixture under current root CAS", result.Code, err)
	}
	return f, j, key
}

func TestVolumeMoveOwnerCleanupAfterExpiryAndRevocationRetainsWriterAndSource(t *testing.T) {
	f, j, targetKey := activeMoveCore(t)
	c, err := f.p.Catalog(f.s)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := c.Tenant(j.Binding.Scope.Tenant)
	f.apply("revoke-target-placement", "set-nodes", tenant.Revision, NodeAssignment{Tenant: tenant.ID, Nodes: []string{j.Binding.Source.Node}}, state.Applied)
	for _, kind := range []string{"cleanup-source", "cleanup-target"} {
		key, owner := f.node, j.Binding.Source
		if kind == "cleanup-target" {
			key, owner = targetKey, j.Binding.Target
		}
		if _, err := f.p.VolumeMovePermit(f.s, owner.Key, VolumeMovePermitRequest{Selection: j.Selection(), Kind: kind}, j.ExpiresAt+1); err != nil {
			t.Fatal("existing native fact cleanup required a new start grant", kind, err)
		}
		proof := volumes.CleanupProof{Binding: j.Binding, Owner: owner, TransferClosed: true, RetainedFenced: kind == "cleanup-source"}
		proof.Signature = ed25519.Sign(key, volumes.CleanupBytes(proof))
		r := moveReport(t, f, kind)
		r.At, r.Cleanup = j.ExpiresAt+1, &proof
		r.Signature = ed25519.Sign(key, VolumeMoveReportBytes(r))
		bad := r
		bad.Revision--
		bad.Signature = ed25519.Sign(key, VolumeMoveReportBytes(bad))
		applyMoveOwnerReport(t, f, owner.Key, bad, state.ConditionFailed)
		applyMoveOwnerReport(t, f, owner.Key, r, state.Applied)
	}
	_, move, _ := f.view().Move(j.Selection())
	if move.Phase != volumes.Completed || move.ReaderClosed == nil || move.SourceCleanup == nil || move.TargetCleanup == nil || len(f.core().Consumers()) != 1 || len(f.core().Retained()) != 1 {
		t.Fatal("completion lost retained source/current writer or omitted a cleanup fact")
	}
	encoded, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	f.s, err = state.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	_, restored, ok := f.view().Move(j.Selection())
	if !ok || restored.Phase != volumes.Completed || restored.ReaderClosed.Consumer != move.ReaderClosed.Consumer || !bytes.Equal(restored.ReaderClosed.Signature, move.ReaderClosed.Signature) {
		t.Fatal("snapshot lost original closure/completion")
	}
}

func TestVolumeMoveCleanupRejectsWrongSignerAndMixedProofs(t *testing.T) {
	f, j, key := activeMoveCore(t)
	proof := volumes.CleanupProof{Binding: j.Binding, Owner: j.Binding.Target, TransferClosed: true}
	proof.Signature = ed25519.Sign(key, volumes.CleanupBytes(proof))
	r := moveReport(t, f, "cleanup-target")
	r.Cleanup = &proof
	for _, name := range []string{"source-caller", "wrong-inner-signature", "wrong-binding", "retained-target", "mixed-active"} {
		t.Run(name, func(t *testing.T) {
			bad, inner := r, proof
			caller := j.Binding.Target.Key
			switch name {
			case "source-caller":
				caller = j.Binding.Source.Key
			case "wrong-inner-signature":
				inner.Signature = ed25519.Sign(f.node, volumes.CleanupBytes(inner))
			case "wrong-binding":
				inner.Binding.StartedRevision++
				inner.Signature = ed25519.Sign(key, volumes.CleanupBytes(inner))
			case "retained-target":
				inner.RetainedFenced = true
				inner.Signature = ed25519.Sign(key, volumes.CleanupBytes(inner))
			case "mixed-active":
				_, move, _ := f.view().Move(j.Selection())
				bad.Active = move.Activated
			}
			bad.Cleanup = &inner
			bad.Signature = ed25519.Sign(key, VolumeMoveReportBytes(bad))
			raw, _ := json.Marshal(bad)
			if _, err := f.p.ResolveVolumeMoveReport(f.s, caller, raw); err == nil {
				t.Fatal("unrelated/mixed cleanup fact admitted")
			}
		})
	}
}
