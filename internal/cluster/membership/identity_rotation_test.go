// SPDX-License-Identifier: Apache-2.0

package membership

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"slices"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
)

func TestIdentityRotationRevokesCurrentKeyPreservesOriginalInstallationAndResources(t *testing.T) {
	d, signer, old := runtimeMembers(t)
	entry, _ := d.Entry("b")
	original, _ := json.Marshal(entry)
	next := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{91}, ed25519.SeedSize))
	proof := lifecycle.IdentityProof{Schema: 1, Cluster: d.Cluster, Node: "b", Operation: "replace-b", Old: memberKey(old), New: memberKey(next), Prepared: [32]byte{1}}
	proof.OldSignature = ed25519.Sign(old, lifecycle.IdentityProofBytes(proof))
	proof.NewSignature = ed25519.Sign(next, lifecycle.IdentityProofBytes(proof))
	n, err := d.BeginIdentityRotation("b", "replace-b", entry.Revision, 20, json.RawMessage(`{"original":"replace-b"}`))
	d = checked(t, n, err)
	if d.Quiescent() {
		t.Fatal("original rotation receipt can expire before installation")
	}
	bad := proof
	bad.NewSignature = nil
	n, err = d.PrepareIdentityRotation("b", "replace-b", bad)
	assertRejected(t, d, n, err)
	n, err = d.PrepareIdentityRotation("b", "replace-b", proof)
	d = checked(t, n, err)
	if !d.MemberKey(proof.Old) || d.MemberKey(proof.New) {
		t.Fatal("preparation activated a key")
	}
	n, err = d.ActivateIdentityRotation("b", "replace-b", 22)
	d = checked(t, n, err)
	current, _ := d.Entry("b")
	if current.Peer != entry.Peer || !bytes.Equal(current.Ack.Signature, entry.Ack.Signature) || current.CurrentPeer().Key != identityHex(proof.New) {
		t.Fatal("rotation rewrote original native/ACK identity")
	}
	if d.MemberKey(proof.Old) || d.WorkKey(proof.Old) || d.ReplicationKey(proof.Old) || slices.Contains(d.SessionIssuers(), proof.Old) || !d.MemberKey(proof.New) || !d.ReplicationKey(proof.New) || !d.HistoricalMemberKey(proof.Old) || !d.OwnsResource(proof.New, proof.Old) || d.OwnsResource(proof.Old, proof.New) {
		t.Fatal("historic key leaked current authority or original resource owner lost")
	}
	t1, _ := d.Topology()
	if t1.Configuration().Index != 14 {
		t.Fatal("identity metadata fabricated native configuration index")
	}
	raw, err := d.Encode()
	if err != nil {
		t.Fatal(err)
	}
	d, err = Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	n, err = d.InstalledIdentityRotation("b", "replace-b", 23)
	d = checked(t, n, err)
	if !d.Quiescent() {
		t.Fatal("installed key replacement never settles")
	}
	row, _ := d.IdentityRotation("b", "replace-b")
	row.Proof.NewSignature[0] ^= 1
	saved, _ := d.IdentityRotation("b", "replace-b")
	if !saved.Proof.Valid() {
		t.Fatal("returned rotation aliases private persisted state")
	}
	unchanged, _ := json.Marshal(entry)
	if !bytes.Equal(original, unchanged) {
		t.Fatal("original entry mutated")
	}
	// Suffrage changes compare the installed current identity while their
	// original peer/ACK and reconcile recipes remain in the retained namespace.
	entry, _ = d.Entry("b")
	n, err = d.ChangeVote("b", entry.Revision, false, json.RawMessage(`{"original":"demote-replaced-b"}`))
	d = checked(t, n, err)
	d = dispatch(t, d, "b", signer, 14)
	target := entry.Peer
	target.Voter = false
	d = observe(t, d, "b", 24, target)
	topology, err := d.Topology()
	if err != nil {
		t.Fatal(err)
	}
	configuration := topology.Configuration()
	configuration.Index = 24
	configuration.Members[1].Voter = false
	n, err = d.InstallConfiguration(configuration)
	d = checked(t, n, err)
	current, _ = d.Entry("b")
	if current.Peer.Key != entry.Peer.Key || current.CurrentPeer().Key != identityHex(proof.New) || current.Peer.Voter || !bytes.Equal(current.Ack.Signature, entry.Ack.Signature) || !d.WorkKey(proof.New) || d.WorkKey(proof.Old) {
		t.Fatal("demotion after replacement lost current authority or original installation")
	}
}
