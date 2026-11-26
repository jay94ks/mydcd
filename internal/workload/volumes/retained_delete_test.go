// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func TestRetainedDeleteKeepsCurrentWriterHistoryAndNativeReuseFence(t *testing.T) {
	f, m := armedMoveFixture(t)
	writer := f.acquire("current-target", 2, true)
	f.activate(m, writer)
	f.cleanup(m)
	before, _ := f.s.Encode()
	if bytes.Contains(before, []byte("SourceDeletion")) {
		t.Fatal("nil retained deletion changed existing schema1 bytes")
	}
	owner, ownerRevision := f.s.Owner()
	f.set(f.s.BeginRetainedDelete(f.c, "admin", m.Binding.ID, f.s.Revision()))
	pending, _ := f.s.Move(m.Binding.ID)
	if pending.SourceDeletion == nil || pending.SourceDeletion.Gone != nil || len(f.s.Retained()) != 1 || f.s.CheckActivation(writer) != nil {
		t.Fatal("pending source deletion released its hold or current writer")
	}
	proof := NativeRemoved{Schema: 1, Scope: f.s.Scope(), Owner: m.Binding.Source, Key: "volume/tenant/app/mysql/initial", Generation: 1, DeleteRevision: pending.SourceDeletion.Revision}
	proof.Signature = ed25519.Sign(f.a, NativeRemovedBytes(proof))
	f.set(f.s.CompleteRetainedDelete(m.Binding.ID, proof))
	completed, _ := f.s.Move(m.Binding.ID)
	current, revision := f.s.Owner()
	if len(f.s.Retained()) != 0 || completed.Phase != Completed || completed.Fence == nil || completed.SourceDeletion.Gone == nil || current != owner || revision != ownerRevision || f.s.CheckActivation(writer) != nil || len(f.s.d.Used) != 2 {
		t.Fatal("source deletion changed ownership, writer, old facts or used-native history")
	}
	replayed, err := f.s.CompleteRetainedDelete(m.Binding.ID, proof)
	if err != nil || replayed.Revision() != f.s.Revision() {
		t.Fatal("original native Gone replay changed deletion", err)
	}
	if _, err = f.s.Prepare(f.c, "admin", f.s.Revision(), revision, "reuse-deleted", m.Binding.Source, m.Binding.Compatibility, m.Binding.MaxBytes); err == nil {
		t.Fatal("deleted obsolete native became reusable")
	}
	if _, err = f.s.BeginDelete(f.c, "admin", f.s.Revision()); err == nil {
		t.Fatal("source deletion let current writer be deleted")
	}
	f.set(f.s.Release(f.gone(writer)))
	f.set(f.s.BeginDelete(f.c, "admin", f.s.Revision()))
}

func TestRetainedDeleteRejectsIncompleteMoveAndMixedNativeFacts(t *testing.T) {
	f, m := armedMoveFixture(t)
	if _, err := f.s.BeginRetainedDelete(f.c, "admin", m.Binding.ID, f.s.Revision()); err == nil {
		t.Fatal("unsettled move's source deletion accepted")
	}
	writer := f.acquire("current-target", 2, true)
	f.activate(m, writer)
	f.cleanup(m)
	f.set(f.s.BeginRetainedDelete(f.c, "admin", m.Binding.ID, f.s.Revision()))
	pending, _ := f.s.Move(m.Binding.ID)
	for _, scenario := range []string{"target", "other-scope", "revision", "wrong-signer"} {
		proof := NativeRemoved{Schema: 1, Scope: f.s.Scope(), Owner: m.Binding.Source, Key: "volume/tenant/app/mysql/initial", Generation: 1, DeleteRevision: pending.SourceDeletion.Revision}
		signer := f.a
		switch scenario {
		case "target":
			proof.Owner, signer = m.Binding.Target, f.b
		case "other-scope":
			proof.Scope.ID = "other"
		case "revision":
			proof.DeleteRevision++
		case "wrong-signer":
			signer = f.b
		}
		proof.Signature = ed25519.Sign(signer, NativeRemovedBytes(proof))
		if _, err := f.s.CompleteRetainedDelete(m.Binding.ID, proof); err == nil {
			t.Fatal("unrelated native deletion fact admitted", scenario)
		}
	}
	if _, err := f.s.BeginRetainedDelete(f.c, "admin", m.Binding.ID, f.s.Revision()); err == nil {
		t.Fatal("second request replaced original pending deletion")
	}
}
