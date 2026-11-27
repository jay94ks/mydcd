// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/reconcile"
)

func TestMoveReaderAfterDurableFence(t *testing.T) {
	f := makeFixture(t)
	m := f.prepare("move", f.target)
	f.set(f.s.RecordFence(f.fence(m)))
	// The actual cold archive requires a readonly source pin AFTER fencing.
	// A task activation must remain forbidden while that reader is present.
	s, reader, err := f.s.AcquireMoveReader(f.c, "admin", f.s.Revision(), m.Binding)
	if err != nil {
		t.Fatal("fenced migration cannot acquire its original archive reader", err)
	}
	f.set(s, nil)
	if err = f.s.CheckMoveReader(m.Binding, reader); err != nil || f.s.CheckActivation(reader) == nil {
		t.Fatal("archive reader was not isolated from Task activation", err)
	}
	revision := f.s.Revision()
	s, again, err := f.s.AcquireMoveReader(f.c, "admin", revision-1, m.Binding)
	if err != nil || again != reader || s.Revision() != revision {
		t.Fatal("original acquisition replay replaced its token", err)
	}
	manifest := f.manifest(m, [32]byte{9})
	f.set(f.s.BeginCopy(manifest))
	f.set(f.s.VerifyCopy(f.copy(m, manifest)))
	if _, err = f.s.CommitOwner(f.c, "admin", m.Binding.ID, f.s.Revision(), m.Binding.SourceOwnerRevision); err == nil {
		t.Fatal("owner CAS passed an unreturned archive reader")
	}
	f.set(f.s.CloseMoveReader(m.Binding, f.gone(reader)))
	f.set(f.s.CommitOwner(f.c, "admin", m.Binding.ID, f.s.Revision(), m.Binding.SourceOwnerRevision))
}

func TestMoveReaderRejectsOtherBindingsAndCancellation(t *testing.T) {
	f := makeFixture(t)
	m := f.prepare("move", f.target)
	if _, _, err := f.s.AcquireMoveReader(f.c, "admin", f.s.Revision(), m.Binding); err == nil {
		t.Fatal("unfenced source acquired a reader")
	}
	f.set(f.s.RecordFence(f.fence(m)))
	wrong := m.Binding
	wrong.SourceOwnerRevision++
	if _, _, err := f.s.AcquireMoveReader(f.c, "admin", f.s.Revision(), wrong); err == nil {
		t.Fatal("wrong original binding accepted")
	}
	if _, _, err := f.s.Acquire(f.c, "admin", f.s.Revision(), "task", 1, false); err == nil {
		t.Fatal("ordinary reader bypassed move admission")
	}
	s, reader, err := f.s.AcquireMoveReader(f.c, "admin", f.s.Revision(), m.Binding)
	f.set(s, err)
	f.set(f.s.Cancel(f.c, "admin", m.Binding.ID, f.s.Revision()))
	if f.s.CheckMoveReader(m.Binding, reader) == nil {
		t.Fatal("cancelling source granted new I/O")
	}
	if _, _, err := f.s.AcquireMoveReader(f.c, "admin", f.s.Revision(), m.Binding); err == nil {
		t.Fatal("cancellation reacquired original reader")
	}
	proof := CleanupProof{Binding: m.Binding, Owner: m.Binding.Source, TransferClosed: true, RetainedFenced: true}
	proof.Signature = ed25519.Sign(f.a, CleanupBytes(proof))
	if _, err := f.s.RecordCleanup(proof); err == nil {
		t.Fatal("source closed before original reader returned")
	}
	f.set(f.s.RecordCancelTarget(f.cancelProof(m)))
	f.set(f.s.CloseMoveReader(m.Binding, f.gone(reader)))
	f.set(f.s.RecordCleanup(proof))
	f.set(f.s.FinishCancel(f.c, "admin", m.Binding.ID, f.s.Revision(), m.Binding.SourceOwnerRevision))
}

func TestMoveReaderReceiptOwnershipReplayAndClosedAcquisition(t *testing.T) {
	for _, phase := range []Phase{SourceFenced, Copying, Verified, Cancelling} {
		t.Run(string(phase), func(t *testing.T) {
			f := makeFixture(t)
			m := f.prepare("move", f.target)
			f.set(f.s.RecordFence(f.fence(m)))
			s, reader, err := f.s.AcquireMoveReader(f.c, "admin", f.s.Revision(), m.Binding)
			f.set(s, err)
			if phase == Copying || phase == Verified {
				manifest := f.manifest(m, [32]byte{19})
				f.set(f.s.BeginCopy(manifest))
				if phase == Verified {
					f.set(f.s.VerifyCopy(f.copy(m, manifest)))
				}
			} else if phase == Cancelling {
				f.set(f.s.Cancel(f.c, "admin", m.Binding.ID, f.s.Revision()))
			}
			before := f.s
			gone := f.gone(reader)
			closed, err := before.CloseMoveReader(m.Binding, gone)
			if err != nil {
				t.Fatal(err)
			}
			// Mutating either the caller's receipt or an exported view must not
			// corrupt the product state, and the original state keeps its pin.
			gone.Signature[0] ^= 1
			view, _ := closed.Move(m.Binding.ID)
			view.ReaderClosed.Signature[0] ^= 1
			if len(before.Consumers()) != 1 || len(closed.Consumers()) != 0 {
				t.Fatal("receipt mutated original publication or retained a live pin")
			}
			f.set(closed, nil)
			stored, _ := f.s.Move(m.Binding.ID)
			if stored.ReaderClosed == nil || stored.ReaderClosed.Consumer != reader || stored.Phase != phase {
				t.Fatal("snapshot lost exact signed receipt/phase")
			}
			revision := f.s.Revision()
			replay, err := f.s.CloseMoveReader(m.Binding, f.gone(reader))
			if err != nil || replay.Revision() != revision {
				t.Fatal("closure replay changed the original receipt", err)
			}
			if _, _, err = f.s.AcquireMoveReader(f.c, "admin", revision, m.Binding); err == nil || f.s.CheckMoveReader(m.Binding, reader) == nil {
				t.Fatal("closed original reader was admitted again")
			}
			bad := f.gone(reader)
			bad.Consumer.Lease.Token++
			bad.Signature = ed25519.Sign(f.a, GoneBytes(bad))
			if _, err = f.s.CloseMoveReader(m.Binding, bad); err == nil {
				t.Fatal("another reader replaced the original receipt")
			}
		})
	}
}

func TestMoveReaderReceiptLegacyBytesAndLiveConsumerRejection(t *testing.T) {
	f := makeFixture(t)
	m := f.prepare("move", f.target)
	f.set(f.s.RecordFence(f.fence(m)))
	s, reader, err := f.s.AcquireMoveReader(f.c, "admin", f.s.Revision(), m.Binding)
	f.set(s, err)
	legacy, err := f.s.Encode()
	if err != nil || bytes.Contains(legacy, []byte("ReaderClosed")) {
		t.Fatal("nil receipt changed existing schema1 bytes", err)
	}
	decoded, err := Decode(legacy)
	if err != nil {
		t.Fatal(err)
	}
	again, err := decoded.Encode()
	if err != nil || !bytes.Equal(legacy, again) {
		t.Fatal("legacy bytes did not roundtrip", err)
	}
	var disk snapshot
	if err = json.Unmarshal(legacy, &disk); err != nil {
		t.Fatal(err)
	}
	gone := f.gone(reader)
	disk.Moves[0].ReaderClosed = &gone
	invalid, _ := json.Marshal(disk)
	if _, err = Decode(invalid); err == nil {
		t.Fatal("snapshot accepted a returned reader still in the live set")
	}
}

func TestMoveReaderReceiptSnapshotRequiresOriginalLeaseHistory(t *testing.T) {
	f := makeFixture(t)
	m := f.prepare("move", f.target)
	f.set(f.s.RecordFence(f.fence(m)))
	s, reader, err := f.s.AcquireMoveReader(f.c, "admin", f.s.Revision(), m.Binding)
	f.set(s, err)
	manifest := f.manifest(m, [32]byte{37})
	f.set(f.s.BeginCopy(manifest))
	f.set(f.s.VerifyCopy(f.copy(m, manifest)))
	f.set(f.s.CloseMoveReader(m.Binding, f.gone(reader)))
	f.set(f.s.CommitOwner(f.c, "admin", m.Binding.ID, f.s.Revision(), m.Binding.SourceOwnerRevision))
	f.set(f.s.Arm(f.c, "admin", m.Binding.ID, f.s.Revision()))
	writer := f.acquire("target", 1, true)
	original, err := f.s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*snapshot){
		"missing-reader-floor": func(d *snapshot) {
			for i, floor := range d.Floors {
				if floor.ID == reader.ID {
					d.Floors = append(d.Floors[:i], d.Floors[i+1:]...)
					break
				}
			}
		},
		"different-reader-generation": func(d *snapshot) {
			for i := range d.Floors {
				if d.Floors[i].ID == reader.ID {
					d.Floors[i].Generation++
				}
			}
		},
		"unissued-reader-token": func(d *snapshot) {
			closed := d.Moves[0].ReaderClosed
			closed.Consumer.Lease.Token = d.Pins.Next + 1
			closed.Signature = ed25519.Sign(f.a, GoneBytes(*closed))
		},
		"returned-token-still-live-under-other-consumer": func(d *snapshot) {
			// The active consumer has another ID and owner. Checking only
			// equality with ReaderClosed.Consumer would miss this conflict.
			d.Consumers[0].Lease = reader.Lease
			d.Pins.Active = []reconcile.Lease{reader.Lease}
		},
	} {
		t.Run(name, func(t *testing.T) {
			var disk snapshot
			if err := json.Unmarshal(original, &disk); err != nil {
				t.Fatal(err)
			}
			change(&disk)
			raw, err := json.Marshal(disk)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = Decode(raw); err == nil {
				t.Fatal("snapshot accepted a closure without its issued, returned original lease")
			}
			current, err := Decode(original)
			if err != nil || len(current.Consumers()) != 1 || current.Consumers()[0] != writer || current.CheckActivation(writer) != nil {
				t.Fatal("invalid snapshot corrupted the original target writer", err)
			}
		})
	}
}

func TestGeneralReleaseKeepsOriginalMoveReaderReceipt(t *testing.T) {
	f := makeFixture(t)
	m := f.prepare("move", f.target)
	f.set(f.s.RecordFence(f.fence(m)))
	s, reader, err := f.s.AcquireMoveReader(f.c, "admin", f.s.Revision(), m.Binding)
	f.set(s, err)
	before, _ := f.s.Encode()
	bad := f.gone(reader)
	bad.Consumer.Lease.Token++
	bad.Signature = ed25519.Sign(f.a, GoneBytes(bad))
	if _, err := f.s.Release(bad); err == nil {
		t.Fatal("general release invented another original reader token")
	}
	after, _ := f.s.Encode()
	if !bytes.Equal(before, after) {
		t.Fatal("invalid general release changed original state")
	}
	gone := f.gone(reader)
	f.set(f.s.Release(gone))
	move, _ := f.s.Move(m.Binding.ID)
	if len(f.s.Consumers()) != 0 || move.ReaderClosed == nil || move.ReaderClosed.Consumer != reader || !bytes.Equal(move.ReaderClosed.Signature, gone.Signature) || !f.s.HadMoveReader(m.Binding) {
		t.Fatal("general release lost original receipt/floor")
	}
	revision := f.s.Revision()
	f.set(f.s.Release(gone))
	if f.s.Revision() != revision {
		t.Fatal("original closure replay changed the returned lease")
	}
}

func TestLegacyLeaseOnlyReturnCannotCommitMoveOwner(t *testing.T) {
	f := makeFixture(t)
	m := f.prepare("move", f.target)
	f.set(f.s.RecordFence(f.fence(m)))
	s, reader, err := f.s.AcquireMoveReader(f.c, "admin", f.s.Revision(), m.Binding)
	f.set(s, err)
	manifest := f.manifest(m, [32]byte{38})
	f.set(f.s.BeginCopy(manifest))
	f.set(f.s.VerifyCopy(f.copy(m, manifest)))
	// The former primitive returned only A3; this models old schema1 input,
	// not a currently reachable alternative production return implementation.
	f.set(f.s.release(f.gone(reader)))
	before, _ := f.s.Encode()
	if !f.s.HadMoveReader(m.Binding) || len(f.s.Consumers()) != 0 {
		t.Fatal("legacy input lost its returned reader floor")
	}
	if _, err := f.s.CommitOwner(f.c, "admin", m.Binding.ID, f.s.Revision(), m.Binding.SourceOwnerRevision); err == nil {
		t.Fatal("legacy reader absence permitted owner CAS")
	}
	after, _ := f.s.Encode()
	if !bytes.Equal(before, after) {
		t.Fatal("legacy commit failure mutated original source/evidence")
	}
}
