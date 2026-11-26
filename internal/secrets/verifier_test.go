// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"encoding/json"
	"testing"

	"github.com/jay94ks/mydcd/internal/reconcile"
)

func TestPublishedVerifierBindingSurvivesWriteCollectionAndRejectsForeignReference(t *testing.T) {
	f := writable(t)
	if _, err := f.t.Verifier("common"); err == nil {
		t.Fatal("legacy metadata-only opaque ref became a real verifier")
	}
	o, _ := f.t.Object("common")
	request := WriteRequest{ID: "password-change", Object: o.ID, Profile: "auth", ProviderObject: verifierObject(f.t.tenant, o.ID, o.Generation), Epoch: f.t.WriteEpoch(), Kind: VerifierWrite, Protected: true}
	f = prepare(t, f, request)
	f = dispatch(t, f, request.ID)
	f = observe(t, f, observation(f, request.ID, reconcile.EffectApplied))
	w, _ := f.t.Write(request.ID)
	n, err := f.t.PublishStored(f.c, "alice", request.ID, request.Epoch, w.ExpectedObjectRevision, f.t.Revision())
	f.t = mustTree(t, n, err)
	before, err := f.t.Verifier("common")
	if err != nil || before.Reference.Revision != 1 || before.Receipt != writeReceipt(w) {
		t.Fatal("original binding publication", err)
	}
	n, err = f.t.RotateWrites(f.c, "alice", f.t.Revision(), f.t.WriteEpoch())
	f.t = mustTree(t, n, err)
	if _, ok := f.t.Write(request.ID); ok {
		t.Fatal("old write not collected")
	}
	n, err = DecodeTree(encodedTree(t, f.t))
	f.t = mustTree(t, n, err)
	after, err := f.t.Verifier("common")
	if err != nil || !before.Equal(after) {
		t.Fatal("collection/snapshot changed protected reference", err)
	}
	o, _ = f.t.Object("common")
	o.VerifierBinding.Reference.Object = "groups/tenant/foreign/1"
	f.t.objects[o.ID] = o
	if _, err = DecodeTree(encodedTree(t, f.t)); err == nil {
		t.Fatal("foreign Group verifier accepted")
	}
}
func TestApprovalCurrentTargetAndCoverReuseShareCommitPolicy(t *testing.T) {
	f := approved(t)
	batch := plan(t, f, web(f))
	for _, target := range batch.Required {
		approval := signed(f, target)
		target = approval.Payload.Target
		if err := f.a.CheckTarget(f.c, f.t, public(f.issuer), target, 110); err != nil {
			t.Fatal(err)
		}
		got, ok := f.a.Existing(f.c, f.t, target, 110)
		if !ok || !covers(got.Payload.Target, target) {
			t.Fatal("valid batch cover not reused")
		}
		target.User = "someone-else"
		if f.a.CheckTarget(f.c, f.t, public(f.issuer), target, 110) == nil {
			t.Fatal("foreign current user accepted")
		}
	}
	o, _ := f.t.Object("common")
	n, err := f.t.SetApprovalAge(f.c, "alice", o.ID, o.Revision, 1)
	f.t = mustTree(t, n, err)
	changed := plan(t, f, web(f))
	if len(f.a.Missing(f.c, f.t, changed, 110)) == 0 {
		t.Fatal("old policy/expired approval reused")
	}
	raw, err := json.Marshal(f.a)
	if err != nil || len(raw) == 0 {
		t.Fatal("public metadata encoding", err)
	}
}

func TestClusterVerifierNamespaceCannotCollideWithTenantNamedCluster(t *testing.T) {
	if verifierObject("", "group", 1) == verifierObject("cluster", "group", 1) {
		t.Fatal("cluster/tenant provider collision")
	}
	o := Object{ID: "group", Kind: Group, Generation: 1, Protected: true, VerifierRef: "record", VerifierBinding: &VerifierBinding{Reference: Reference{Profile: "auth", Object: verifierObject("cluster", "group", 1), Revision: 1, Keys: []string{"verifier"}}, Receipt: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}
	if validVerifierBinding("", o) {
		t.Fatal("legacy tenant-spelled cluster path became an active verifier")
	}
	o.VerifierBinding.Reference.Object = verifierObject("", "group", 1)
	if !validVerifierBinding("", o) {
		t.Fatal("reserved cluster verifier path denied")
	}
}

func TestVerifierReferenceIncludesOriginalWriteEpochAndWholePublicReceipt(t *testing.T) {
	f := writable(t)
	group, _ := f.t.Object("common")
	w := WriteRecord{Request: WriteRequest{ID: "same-id", Epoch: 1, Kind: VerifierWrite, Object: group.ID, Profile: "auth", ProviderObject: verifierObject(f.t.tenant, group.ID, group.Generation), Protected: true}, Writer: f.t.profiles["auth"]}
	first, err := (ProviderReceipt{Original: writeReceipt(w)}).VerifierReference()
	if err != nil || !identifier(first) {
		t.Fatal(err)
	}
	same, err := (ProviderReceipt{Original: writeReceipt(w)}).VerifierReference()
	if err != nil || same != first {
		t.Fatal("same original receipt changed ID")
	}
	w.Request.Epoch++
	next, err := (ProviderReceipt{Original: writeReceipt(w)}).VerifierReference()
	if err != nil || next == first {
		t.Fatal("collected write ID reused protected identity")
	}
	if _, err = (ProviderReceipt{Original: "not-a-public-receipt"}).VerifierReference(); err == nil {
		t.Fatal("invalid receipt accepted")
	}
}

func TestLegacyClusterVerifierWriteSettlesOriginalButIsNotAdoptedForPasswordUse(t *testing.T) {
	f := writable(t)
	tree, err := NewTree(f.t.cluster, "", "root")
	tree = mustTree(t, tree, err)
	tree, err = tree.Create(f.c, "admin", tree.Revision(), Object{ID: "common", Parent: "root", Kind: Group})
	tree = mustTree(t, tree, err)
	tree, err = tree.SetWriteProfile(f.c, "admin", tree.Revision(), WriteProfile{ID: "auth", Node: "node-b", Key: public(f.nb), Enabled: true, Verifiers: true})
	tree = mustTree(t, tree, err)
	group, _ := tree.Object("common")
	q := WriteRequest{ID: "legacy-write", Object: group.ID, Profile: "auth", ProviderObject: verifierObject("", group.ID, group.Generation), Epoch: 1, Kind: VerifierWrite, Protected: true}
	tree, err = tree.PrepareWrite(f.c, "admin", tree.Revision(), q)
	tree = mustTree(t, tree, err)
	// Reconstruct only the public record written by the previous provider path
	// convention. There is no provider call or substituted real password proof.
	w, _ := tree.Write(q.ID)
	w.Request.ProviderObject = verifierObject("cluster", group.ID, group.Generation)
	w.Journal.Desired.Spec = writeSpec(tree.cluster, tree.tenant, w)
	w.Journal.Pending.Target = w.Journal.Desired.Resource
	tree.writes[q.ID] = w
	tree, err = DecodeTree(encodedTree(t, tree))
	tree = mustTree(t, tree, err)
	tree, err = tree.DispatchWrite(f.c, "admin", q.ID, 1, tree.Revision())
	tree = mustTree(t, tree, err)
	f.t = tree
	f = observe(t, f, observation(f, q.ID, reconcile.EffectApplied))
	tree = f.t
	w, _ = tree.Write(q.ID)
	tree, err = tree.PublishStored(f.c, "admin", q.ID, 1, w.ExpectedObjectRevision, tree.Revision())
	tree = mustTree(t, tree, err)
	tree, err = DecodeTree(encodedTree(t, tree))
	tree = mustTree(t, tree, err)
	original, _ := tree.Write(q.ID)
	if original.Status() != "Published" || original.Request.ProviderObject != w.Request.ProviderObject {
		t.Fatal("legacy original result/source lost")
	}
	if _, err = tree.Verifier(group.ID); err == nil {
		t.Fatal("legacy cluster/tenant alias automatically authorized a password read")
	}
	q.ID = "explicit-new-password"
	q.ProviderObject = verifierObject("", group.ID, group.Generation)
	if _, err = tree.PrepareWrite(f.c, "admin", tree.Revision(), q); err != nil {
		t.Fatal("explicit reserved path rewrite denied", err)
	}
}
