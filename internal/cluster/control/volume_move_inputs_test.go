// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

func TestMoveInputProofBindsOriginalJobConsumerReadSetAndFreshness(t *testing.T) {
	f, q := moveCore(t)
	f.apply("move", "begin-volume-move", f.core().Revision(), q, state.Applied)
	j, _, _ := f.view().Move(VolumeMoveSelection{Scope: f.scope, ID: q.ID})
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{124}, 32))
	p := VolumeMoveInputProof{Schema: 1, Selection: j.Selection(), Binding: j.Digest(), ReadSet: [32]byte{4}, Consumer: j.Binding.Target.Key, At: 10}
	p.Signature = ed25519.Sign(key, VolumeMoveInputProofBytes(p))
	if err := p.Verify(j, p.ReadSet, j.Binding.Target.Key, 10); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []VolumeMoveInputProof{
		func() VolumeMoveInputProof { b := p; b.Binding[0]++; return b }(),
		func() VolumeMoveInputProof { b := p; b.ReadSet[0]++; return b }(),
		func() VolumeMoveInputProof { b := p; b.Consumer = j.Binding.Source.Key; return b }(),
		func() VolumeMoveInputProof { b := p; b.Selection.ID = "foreign"; return b }(),
	} {
		if bad.Verify(j, p.ReadSet, j.Binding.Target.Key, 10) == nil {
			t.Fatal("foreign/stale signed fact accepted")
		}
	}
	if p.Verify(j, p.ReadSet, p.Consumer, 41) == nil || p.Verify(j, p.ReadSet, p.Consumer, 9) == nil {
		t.Fatal("stale/future fact accepted")
	}
	if _, err := f.p.VolumeMovePermit(f.s, j.Binding.Target.Key, VolumeMovePermitRequest{Selection: j.Selection(), Kind: "prepare-inputs"}, 2); err == nil {
		t.Fatal("unbound move acquired app inputs")
	}
}

func TestMoveInputPermitKeepsLocalPlansOffTheBoundedWire(t *testing.T) {
	inputs := VolumeMoveInputs{ReadSet: [32]byte{1}, CommandIndex: 10, Reads: []AppInputRead{{Realm: string(bytes.Repeat([]byte{'a'}, 256<<10))}}}
	raw, err := json.Marshal(inputs)
	if err != nil || len(raw) > 512 || bytes.Contains(raw, []byte("Reads")) {
		t.Fatal("local metadata widened permit wire", err)
	}
	old, err := json.Marshal(VolumeMovePermit{})
	if err != nil || bytes.Contains(old, []byte("Inputs")) {
		t.Fatal("legacy permit bytes changed", err)
	}
	var got VolumeMoveInputs
	if err = json.Unmarshal(raw, &got); err != nil || got.ReadSet != inputs.ReadSet || got.CommandIndex != inputs.CommandIndex || len(got.Reads) != 0 {
		t.Fatal("bounded public read-set roundtrip", err)
	}
}

func TestMovePreparationReadSetRefreshOwnsEvidenceAndStopsAtFence(t *testing.T) {
	f, q := moveCore(t)
	f.apply("move", "begin-volume-move", f.core().Revision(), q, state.Applied)
	j, _, _ := f.view().Move(VolumeMoveSelection{Scope: f.scope, ID: q.ID})
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{124}, 32))
	ready := volumes.NativeReady{Schema: 1, Spec: j.Target, Generation: 1, Owner: j.Binding.Target}
	ready.Signature = ed25519.Sign(key, volumes.NativeReadyBytes(ready))
	proof := volumes.TargetPreparation{Binding: j.Binding, Target: ready, Empty: true, NoWriters: true, SpaceChecked: true, ProtocolReady: true}
	proof.Signature = ed25519.Sign(key, volumes.TargetPreparationBytes(proof))
	raw, _ := json.Marshal(proof)
	if bytes.Contains(raw, []byte("Inputs")) {
		t.Fatal("legacy schema1 bytes changed")
	}
	core, err := f.core().RecordTargetPreparation(proof)
	if err != nil {
		t.Fatal(err)
	}
	digest := [32]byte{1}
	proof.Inputs = &digest
	proof.InputsAt = 1
	proof.Signature = ed25519.Sign(key, volumes.TargetPreparationBytes(proof))
	core, err = core.RecordTargetPreparation(proof)
	if err != nil {
		t.Fatal("original nil evidence cannot be enriched", err)
	}
	digest[0] = 2
	m, _ := core.Move(j.Binding.ID)
	if *m.Preparation.Inputs != ([32]byte{1}) {
		t.Fatal("stored input digest aliases caller")
	}
	m.Preparation.Inputs[0] = 3
	m, _ = core.Move(j.Binding.ID)
	if *m.Preparation.Inputs != ([32]byte{1}) {
		t.Fatal("view aliases snapshot")
	}
	proof.Signature = ed25519.Sign(key, volumes.TargetPreparationBytes(proof))
	core, err = core.RecordTargetPreparation(proof)
	if err != nil {
		t.Fatal("current read-set refresh", err)
	}
	old := proof
	old.Inputs = nil
	old.InputsAt = 0
	old.Signature = ed25519.Sign(key, volumes.TargetPreparationBytes(old))
	if _, err = core.RecordTargetPreparation(old); err == nil {
		t.Fatal("evidence downgrade")
	}
	fence := volumes.FenceProof{Binding: j.Binding, FenceThrough: j.Binding.SourceOwnerRevision, Stopped: true, MountsGone: true, StartsSettled: true, Synced: true}
	fence.Signature = ed25519.Sign(f.node, volumes.FenceBytes(fence))
	core, err = core.RecordFence(fence)
	if err != nil {
		t.Fatal(err)
	}
	digest[0] = 4
	proof.Signature = ed25519.Sign(key, volumes.TargetPreparationBytes(proof))
	if _, err = core.RecordTargetPreparation(proof); err == nil {
		t.Fatal("rewrote preparation after fencing")
	}
	if _, err = core.Encode(); err != nil {
		t.Fatal("lost original proof during encode", err)
	}
}

func TestMovePreparationBindsResourceOnlyOwnersAndExactNativeSource(t *testing.T) {
	owner := [32]byte{11}
	rows := []VolumeMoveResourceRead{{Key: "network/source", Kind: "native-bridge", Node: "node-a", Owner: owner, Source: deployment.ObjectRef{Key: "network/source", Revision: 9, Generation: 7}, Spec: [32]byte{1}}}
	inputs := &VolumeMoveInputs{Resources: rows}
	if !moveInputConsumer(inputs, owner) || moveInputConsumer(inputs, [32]byte{12}) {
		t.Fatal("resource-only owner was omitted or delegated")
	}
	before, err := movePreparationDigest([32]byte{2}, nil, rows)
	if err != nil {
		t.Fatal(err)
	}
	rows[0].Source.Revision++
	after, err := movePreparationDigest([32]byte{2}, nil, rows)
	if err != nil || before == after {
		t.Fatal("native source change did not invalidate preparation", err)
	}
	rows[0].Source.Revision--
	after, err = movePreparationDigest([32]byte{3}, nil, rows)
	if err != nil || before == after {
		t.Fatal("another job borrowed resource preparation", err)
	}
	inputs.ReadSet = before
	inputs.CommandIndex = 9
	inputs.Resources[0].Key = string(bytes.Repeat([]byte{'x'}, 256<<10))
	raw, err := json.Marshal(inputs)
	if err != nil || len(raw) > 512 || bytes.Contains(raw, []byte("Resources")) {
		t.Fatal("local resource plan widened wire permit", err)
	}
}
