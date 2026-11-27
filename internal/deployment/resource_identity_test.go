// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/secrets"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

func replacementResourceKey(t *testing.T, cluster [32]byte, node string, old, next ed25519.PrivateKey) []lifecycle.IdentityTransition {
	t.Helper()
	proof := lifecycle.IdentityProof{Schema: 1, Cluster: cluster, Node: node, Operation: "replace-installed", Old: public(old), New: public(next), Prepared: [32]byte{1}}
	proof.OldSignature = ed25519.Sign(old, lifecycle.IdentityProofBytes(proof))
	proof.NewSignature = ed25519.Sign(next, lifecycle.IdentityProofBytes(proof))
	return []lifecycle.IdentityTransition{{Proof: proof, Index: 50, Revision: 50}}
}

// This is a model of already committed original source and positive consumer
// closure, not evidence of native Docker shutdown or actual key installation.
func TestReplacementIdentityNewTaskBorrowsOriginalVolumeAndBridge(t *testing.T) {
	f, original, material := taskMaterialFixture(t)
	before, _ := json.Marshal(material.Volumes)
	ctx := contextFor(t, f)
	ctx.Current = frozenManagedGoals(t, original, nil)
	for _, demand := range mustResourceDemands(t, original) {
		if demand.Network != nil {
			var err error
			ctx.Networks, err = ctx.Networks.Create(f.c, "alice", ctx.Networks.Revision(), *demand.Network)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	key := private(75)
	node := ctx.Nodes["node-b"]
	node.Key = public(key)
	node.ResourceKeys = replacementResourceKey(t, f.cluster, "node-b", f.nb, key)
	ctx.Nodes["node-b"] = node
	next, err := Compile(smallCompose(t), f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	steps := stepMap(next)
	if steps[ResourceKey("task", "tenant", "php-mysql", "db")].Owner != public(key) || steps[ResourceKey("volume", "tenant", "php-mysql", "mysql-data")].Owner != public(f.nb) || steps[ResourceKey("bridge", "tenant", "php-mysql", "app/node-b")].Owner != public(f.nb) {
		t.Fatal("new task or original data owner was relabeled")
	}
	// The old writer is explicitly closed in the modeled input. Key rotation
	// alone is never supplied as that Volume consumer closure.
	core := f.v["tenant/php-mysql/mysql-data"]
	for _, consumer := range core.Consumers() {
		gone := volumes.Gone{Scope: core.Scope(), Consumer: consumer, Stopped: true, MountsGone: true}
		gone.Signature = ed25519.Sign(f.nb, volumes.GoneBytes(gone))
		core, err = core.Release(gone)
		if err != nil {
			t.Fatal(err)
		}
	}
	f.v["tenant/php-mysql/mysql-data"] = core
	need, err := next.Inputs("db", "new-task", 12, public(private(30)))
	if err != nil {
		t.Fatal(err)
	}
	// This new-key deployment needs fresh approvals; the helper's original
	// group-based IDs already name the old-key deployment's immutable proofs.
	targets, err := Required(f.cluster, f.c, f.trees, []Needs{need})
	if err != nil {
		t.Fatal(err)
	}
	issuer, _ := f.a.Issuer(public(f.issuer))
	for _, target := range targets {
		target.IssuerPolicy = issuer.Policy
		target.ApprovalID = "replacement-" + target.Group
		approval := secrets.Approval{Schema: 1, Issuer: public(f.issuer), Payload: secrets.ApprovalPayload{ApprovedAt: 100, Fact: "secret-group-use-approved", Target: target}}
		approval.Signature = ed25519.Sign(f.issuer, secrets.ApprovalBytes(approval))
		f.a, err = f.a.Commit(f.c, "alice", f.trees[target.Realm], f.a.Revision(), approval, 100, 32)
		if err != nil {
			t.Fatal(err)
		}
	}
	binding := f.reserve(need).Bindings[0]
	material.Binding = binding
	ref := projectionReference(binding)
	material.Projection = &ref
	source := ctx.Current[material.Network.Key]
	material.Network.Generation, material.Network.Revision = source.Generation, source.Revision
	_, recipe, err := next.taskRecipe("db", material, engine.Owner(f.cluster, public(key)))
	if err != nil || recipe.Node != engine.Owner(f.cluster, public(key)) || recipe.BridgeOwner != engine.Owner(f.cluster, public(f.nb)) || recipe.Volumes[0].Consumer.Owner.Key != public(f.nb) {
		t.Fatal("current task failed exact historic data consumption", err)
	}
	after, _ := json.Marshal(material.Volumes)
	if !bytes.Equal(before, after) {
		t.Fatal("native readiness/signature changed")
	}
	foreign := cloneTaskMaterial(material)
	foreign.Bridge.Owner = engine.Owner(f.cluster, public(private(76)))
	for i := range foreign.Bridge.Pools {
		foreign.Bridge.Pools[i].Owner = foreign.Bridge.Owner
	}
	if _, _, err := next.taskRecipe("db", foreign, engine.Owner(f.cluster, public(key))); err == nil {
		t.Fatal("address validation adopted an unrelated Bridge owner")
	}
	bad := binding.d
	bad.Needs.ResourceKeys = nil
	if validBinding(Binding{bad}) {
		t.Fatal("old Volume accepted without installed key transition")
	}
	bad = ownBinding(binding.d)
	bad.Needs.ResourceKeys[0].Proof.NewSignature[0] ^= 1
	if validBinding(Binding{bad}) {
		t.Fatal("invalid new-key possession proof granted data consumption")
	}
}

func mustResourceDemands(t *testing.T, b Blueprint) []ResourceDemand {
	t.Helper()
	rows, err := b.ResourceDemands()
	if err != nil {
		t.Fatal(err)
	}
	return rows
}
