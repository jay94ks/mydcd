// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"
)

func TestUnchangedMoveCancellationPreservesOriginalWriterAndOwnerRevision(t *testing.T) {
	for _, sourceFirst := range []bool{true, false} {
		t.Run(map[bool]string{true: "source-first", false: "target-first"}[sourceFirst], func(t *testing.T) {
			f := makeFixture(t)
			writer := f.acquire("database", 1, true)
			m := f.prepare("move", f.target)
			f.set(f.s.Cancel(f.c, "admin", m.Binding.ID, f.s.Revision()))
			proof := CleanupProof{Binding: m.Binding, Owner: m.Binding.Source, TransferClosed: true, Unchanged: true}
			proof.Signature = ed25519.Sign(f.a, CleanupBytes(proof))
			if sourceFirst {
				f.set(f.s.RecordCleanup(proof))
			} else {
				f.set(f.s.RecordCancelTarget(f.cancelProof(m)))
			}
			if _, err := f.s.SettleCancel(m.Binding, f.s.Revision()); err == nil {
				t.Fatal("one side alone completed cancellation")
			}
			if sourceFirst {
				f.set(f.s.RecordCancelTarget(f.cancelProof(m)))
			} else {
				f.set(f.s.RecordCleanup(proof))
			}
			if _, err := f.s.RecordFence(f.fence(m)); err == nil {
				t.Fatal("source fence admitted after positive unchanged receipt")
			}
			if _, err := f.s.SettleCancel(m.Binding, f.s.Revision()-1); err == nil {
				t.Fatal("stale cancellation CAS accepted")
			}
			f.set(f.s.SettleCancel(m.Binding, f.s.Revision()))
			owner, revision := f.s.Owner()
			done, _ := f.s.Move(m.Binding.ID)
			if owner != m.Binding.Source || revision != m.Binding.SourceOwnerRevision || done.Phase != Cancelled || done.CancelRevision == 0 || done.Fence != nil || len(f.s.Consumers()) != 1 || f.s.Consumers()[0] != writer || f.s.CheckActivation(writer) != nil {
				t.Fatal("untouched source was retired, unfenced, or given a replacement writer")
			}
			before := f.s.Revision()
			replay, err := f.s.FinishCancel(f.c, "admin", m.Binding.ID, before, m.Binding.SourceOwnerRevision)
			if err != nil || replay.Revision() != before {
				t.Fatal("original completed cancellation was replaced", err)
			}
			// The preserved owner revision remains the next original source.
			next := f.target
			next.Native = "sfc-another-stage"
			f.prepare("another", next)
		})
	}
}

func TestUnchangedMoveCancellationRejectsSourceEffectsAndLegacyReaderAbsence(t *testing.T) {
	for _, scenario := range []string{"fence", "live-reader", "legacy-returned-reader", "manifest"} {
		t.Run(scenario, func(t *testing.T) {
			f := makeFixture(t)
			m := f.prepare("move", f.target)
			f.set(f.s.RecordFence(f.fence(m)))
			if scenario != "fence" {
				s, reader, err := f.s.AcquireMoveReader(f.c, "admin", f.s.Revision(), m.Binding)
				f.set(s, err)
				if scenario == "legacy-returned-reader" {
					// Model the old lease-only return before optional receipt storage.
					f.set(f.s.release(f.gone(reader)))
					if !f.s.HadMoveReader(m.Binding) {
						t.Fatal("reader generation floor was lost")
					}
				} else if scenario == "manifest" {
					f.set(f.s.BeginCopy(f.manifest(m, [32]byte{16})))
				}
			}
			f.set(f.s.Cancel(f.c, "admin", m.Binding.ID, f.s.Revision()))
			proof := CleanupProof{Binding: m.Binding, Owner: m.Binding.Source, TransferClosed: true, Unchanged: true}
			proof.Signature = ed25519.Sign(f.a, CleanupBytes(proof))
			before, _ := f.s.Encode()
			if _, err := f.s.RecordCleanup(proof); err == nil {
				t.Fatal("source effects/unknown reader were described as untouched")
			}
			after, _ := f.s.Encode()
			if !bytes.Equal(before, after) {
				t.Fatal("rejected proof changed original evidence")
			}
		})
	}
}

func TestCleanupProofUnchangedOmissionPreservesSchemaOneSigningBytes(t *testing.T) {
	f := makeFixture(t)
	m := f.prepare("move", f.target)
	p := CleanupProof{Binding: m.Binding, Owner: m.Binding.Source, TransferClosed: true, RetainedFenced: true}
	legacy := struct {
		Binding                        Binding
		Owner                          Owner
		TransferClosed, RetainedFenced bool
		Signature                      []byte
	}{Binding: p.Binding, Owner: p.Owner, TransferClosed: p.TransferClosed, RetainedFenced: p.RetainedFenced}
	raw, _ := json.Marshal(legacy)
	want := append([]byte("sfc-volume-move-cleanup-1\x00"), raw...)
	if !bytes.Equal(want, CleanupBytes(p)) {
		t.Fatal("new optional cancellation flag changed existing schema1 signatures")
	}
}
