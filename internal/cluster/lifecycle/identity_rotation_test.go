// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"crypto/ed25519"
	"testing"
)

func TestIdentityRootKeepsGenesisAndRequiresBothOriginalOperationPossessions(t *testing.T) {
	old, private := fixtureKey(1)
	next, newPrivate := fixtureKey(90)
	root, err := Prepare(Init, [32]byte{1}, old, Member{ID: "node-a", Key: old, Voter: true}, "init-a")
	if err != nil {
		t.Fatal(err)
	}
	uninstalled := root
	root, err = root.Install(root.Cluster, Configuration{Index: 100, Members: []Member{root.Self}}, 101)
	if err != nil {
		t.Fatal(err)
	}
	proof := IdentityProof{Schema: 1, Cluster: root.Cluster, Node: "node-a", Operation: "replace-a", Old: old, New: next, Prepared: [32]byte{1}}
	proof.OldSignature = ed25519.Sign(private, IdentityProofBytes(proof))
	proof.NewSignature = ed25519.Sign(newPrivate, IdentityProofBytes(proof))
	if _, err := uninstalled.RotateIdentity(proof, 3); err == nil {
		t.Fatal("identity switch fabricated an uninstalled Root")
	}
	for _, mutate := range []func(*IdentityProof){func(p *IdentityProof) { p.Operation = "other" }, func(p *IdentityProof) { p.Node = "node-b" }, func(p *IdentityProof) { p.Prepared = [32]byte{2} }, func(p *IdentityProof) { p.NewSignature = nil }} {
		bad := proof
		mutate(&bad)
		if bad.Valid() {
			t.Fatal("replacement accepted a different op/target/preparation or absent new possession")
		}
	}
	root, err = root.RotateIdentity(proof, 3)
	if err != nil || root.Validate() != nil || root.Self.Key != next || root.TrustRoot != old || root.OriginalKey() != old || root.AppliedIndex != 101 || root.Installed.Index != 100 || root.Keys[0].Index != 3 {
		t.Fatal(root, err)
	}
	if root.Resume(root.Cluster, Member{ID: "node-a", Key: old}) == nil {
		t.Fatal("restart accepted old active identity")
	}
	if root.Resume(root.Cluster, Member{ID: "node-a", Key: next}) != nil {
		t.Fatal("restart rejected new installed identity")
	}
}
