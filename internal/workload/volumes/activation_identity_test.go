// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/engine"
)

// Native SDK responses here are explicit local fixtures. The product gate,
// owner/pin journal and actual driver identity calculation are reused.
func TestNewTaskIdentityKeepsOriginalVolumeGateAndUncertainStart(t *testing.T) {
	f := activationTest(t)
	old := makeFixture(t).a
	next := private(79)
	proof := lifecycle.IdentityProof{Schema: 1, Cluster: f.ref.Scope.Cluster, Node: f.ref.Consumer.Owner.Node, Operation: "replace-node", Old: public(old), New: public(next), Prepared: [32]byte{1}}
	proof.OldSignature = ed25519.Sign(old, lifecycle.IdentityProofBytes(proof))
	proof.NewSignature = ed25519.Sign(next, lifecycle.IdentityProofBytes(proof))
	chain := []lifecycle.IdentityTransition{{Proof: proof, Index: 50, Revision: 50}}
	ref := f.ref
	ref.TaskOwner = engine.Owner(ref.Scope.Cluster, proof.New)
	raw, _ := json.Marshal(struct {
		Node         string
		ResourceKeys []lifecycle.IdentityTransition
	}{ref.TaskOwner, chain})
	ref.Task.Spec = string(raw)
	if ref.Validate() != nil {
		t.Fatal("valid physical-node original Volume reference rejected")
	}
	id, err := f.docker.IdentityForOwner(ref.TaskOwner, "container", ref.TaskKey, ref.Task)
	if err != nil {
		t.Fatal(err)
	}
	f.http.mu.Lock()
	f.http.value.Name = "/" + id.Name
	f.http.value.Config.Labels = id.Labels
	f.http.exists = true
	f.http.loseStart = true
	f.http.mu.Unlock()
	s := f.open(t)
	defer s.Close()
	if err = s.Activate(context.Background(), ref); err == nil {
		t.Fatal("lost new Task Start acknowledged")
	}
	gate, err := s.Checkpoint(ref)
	if err != nil || gate.Starting == nil || *gate.Starting != f.ref.Consumer || gate.Owner != f.ref.Consumer.Owner {
		t.Fatal("rotation replaced original Volume gate/uncertainty", err)
	}
	if _, err = s.Fence(ref, ref.Consumer.OwnerRevision); err == nil {
		t.Fatal("new Task's unknown Start bypassed original writer fence")
	}
	bad := ref
	bad.TaskOwner = f.docker.Owner
	if bad.Validate() == nil {
		t.Fatal("Task owner changed without original recipe")
	}
	chain[0].Proof.NewSignature[0] ^= 1
	raw, _ = json.Marshal(struct {
		Node         string
		ResourceKeys []lifecycle.IdentityTransition
	}{ref.TaskOwner, chain})
	bad = ref
	bad.Task.Spec = string(raw)
	if bad.Validate() == nil {
		t.Fatal("invalid new-key proof accepted")
	}
}
