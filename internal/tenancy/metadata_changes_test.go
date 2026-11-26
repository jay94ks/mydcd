// SPDX-License-Identifier: Apache-2.0

package tenancy

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestMetadataNetworkReservationCancelsWithoutNativeClaimAndPreservesSource(t *testing.T) {
	f := two(t)
	original, _ := f.n.Network("first", "lan")
	target := changeTarget(f, "first", "lan", "10.9.0.0/24")
	beforePlan, err := f.n.AddressPlan(1)
	if err != nil {
		t.Fatal(err)
	}
	f.n, err = f.n.PlanMetadataChange(f.c, "admin", "first", "lan", "metadata", original.Revision, target)
	if err != nil {
		t.Fatal(err)
	}
	change, _ := f.n.Change("first", "lan")
	if !change.MetadataOnly || CandidateNativeID(change) != "" {
		t.Fatal("metadata reservation advertised a native candidate")
	}
	raw := snapshotBytes(t, f.n)
	f.n, err = Decode(raw)
	if err != nil {
		t.Fatal("metadata reservation snapshot", err)
	}
	if _, err = f.n.PlanChange(f.c, "admin", "first", "lan", "metadata", original.Revision, target); err == nil {
		t.Fatal("same request changed the persisted native/metadata contract")
	}
	for _, proof := range []ChangeCandidateClose{{Gone: true}, {Signature: []byte{1}}, candidateClose(f.n, change, f.b)} {
		if _, err = f.n.CancelChange(f.c, "admin", "first", "lan", change.Generation, change.Revision, proof); err == nil || !bytes.Equal(raw, snapshotBytes(t, f.n)) {
			t.Fatal("metadata candidate accepted native evidence or altered original reservation", err)
		}
	}
	for _, identity := range []struct {
		actor                string
		generation, revision uint64
	}{{"nobody", change.Generation, change.Revision}, {"admin", change.Generation + 1, change.Revision}, {"admin", change.Generation, change.Revision + 1}} {
		if _, err = f.n.CancelChange(f.c, identity.actor, "first", "lan", identity.generation, identity.revision, ChangeCandidateClose{}); err == nil {
			t.Fatal("metadata cancellation bypassed cleanup authorization or original CAS")
		}
	}
	f.n, err = f.n.CancelChange(f.c, "admin", "first", "lan", change.Generation, change.Revision, ChangeCandidateClose{})
	if err != nil {
		t.Fatal(err)
	}
	live, _ := f.n.Network("first", "lan")
	closed, _ := f.n.Change("first", "lan")
	if !sameNetwork(live, original) || closed.Phase != ChangeCancelled || !closed.MetadataOnly || closed.CandidateClosed != nil || !sameNetwork(closed.Target, target) {
		t.Fatal("cancel changed original source or invented native Gone")
	}
	plan, err := f.n.AddressPlan(1)
	a, _ := json.Marshal(beforePlan)
	b, _ := json.Marshal(plan)
	if err != nil || !bytes.Equal(a, b) {
		t.Fatal("metadata cancellation changed the address plan", err)
	}
	if _, err = Decode(snapshotBytes(t, f.n)); err != nil {
		t.Fatal("metadata cancellation snapshot", err)
	}
}

func TestMetadataNetworkCancellationCannotReverseDrainOrRelaxLegacyEvidence(t *testing.T) {
	for _, metadata := range []bool{false, true} {
		f := two(t)
		original, _ := f.n.Network("first", "lan")
		target := changeTarget(f, "first", "lan", "10.9.0.0/24")
		var err error
		if metadata {
			f.n, err = f.n.PlanMetadataChange(f.c, "admin", "first", "lan", "reserved", original.Revision, target)
		} else {
			f.n, err = f.n.PlanChange(f.c, "admin", "first", "lan", "reserved", original.Revision, target)
		}
		if err != nil {
			t.Fatal(err)
		}
		change, _ := f.n.Change("first", "lan")
		if !metadata {
			raw := snapshotBytes(t, f.n)
			if bytes.Contains(raw, []byte("MetadataOnly")) {
				t.Fatal("legacy schema1 bytes gained a metadata marker")
			}
			if _, err = f.n.CancelChange(f.c, "admin", "first", "lan", change.Generation, change.Revision, ChangeCandidateClose{}); err == nil {
				t.Fatal("unmarked native candidate was inferred never executed")
			}
		}
		f.n, err = f.n.BeginChangeDrain(f.c, "admin", "first", "lan", change.Generation, change.Revision)
		if err != nil {
			t.Fatal(err)
		}
		change, _ = f.n.Change("first", "lan")
		raw := snapshotBytes(t, f.n)
		if _, err = f.n.CancelChange(f.c, "admin", "first", "lan", change.Generation, change.Revision, ChangeCandidateClose{}); err == nil || !bytes.Equal(raw, snapshotBytes(t, f.n)) {
			t.Fatal("cancellation reversed an original Drain", metadata, err)
		}
	}
}
