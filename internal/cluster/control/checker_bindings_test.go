// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"testing"

	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/secrets"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

// Real reusable Binding/Catalog codecs and cross-reference validation. This
// is not a managed app command, quorum read or native/source readiness proof.
func TestCheckerBindingCrossReferenceRejectsMissingPinsAndChangedParent(t *testing.T) {
	f := newCheckerFixture(t)
	p := checkerPolicy()
	p.Revision = 0
	book, err := checker.NewCatalog(f.p.Cluster)
	if err != nil {
		t.Fatal(err)
	}
	book, err = book.SetPolicy(f.users, "manager", 0, p)
	if err != nil {
		t.Fatal(err)
	}
	source := checkerFact(f, f.node, "package checker\n")
	book, err = book.PutScript(f.users, "manager", 0, "tenant", "ready", source)
	if err != nil {
		t.Fatal(err)
	}
	selection := checker.Selection{PolicyRevision: 1, Scripts: []checker.NamedReference{{Name: "ready", Revision: 1}}}
	bindings, err := deployment.NewBindings(f.p.Cluster)
	if err != nil {
		t.Fatal(err)
	}
	approvals, err := secrets.NewApprovals(f.p.Cluster)
	if err != nil {
		t.Fatal(err)
	}
	owner := [32]byte(f.node.Public().(ed25519.PublicKey))
	n := deployment.Needs{Consumer: "task-web", Generation: 1, Use: secrets.Use{Tenant: "tenant", User: "manager", App: "demo", Deployment: "deploy", Service: "web", Node: "node-a", NodeKey: owner, RequesterKey: [32]byte(f.manager.Public().(ed25519.PublicKey))}, Lifecycle: &selection}
	result, err := bindings.Reserve(0, f.users, map[string]secrets.Tree{}, approvals, map[string]volumes.State{}, []deployment.Needs{n}, 100)
	if err != nil {
		t.Fatal(err)
	}
	apps := Apps{bindings: result.Inventory}
	if validateCheckerBindings(apps, book) == nil {
		t.Fatal("binding lost lifecycle reservation")
	}
	u, ok := CheckerBindingUse(result.Bindings[0])
	if !ok {
		t.Fatal("missing accepted selection")
	}
	book, err = book.Reserve(u)
	if err != nil {
		t.Fatal(err)
	}
	if validateCheckerBindings(apps, book) != nil {
		t.Fatal("matching accepted pin rejected")
	}
	if _, _, err := book.SourceForUse(u, source.ContentDigest()); err != nil {
		t.Fatal("exact source reference not retained", err)
	}
	changed := u
	changed.Owner[0] ^= 1
	if _, _, err := book.SourceForUse(changed, source.ContentDigest()); err == nil {
		t.Fatal("copied use widened consumer")
	}
	if validateCheckerBindings(Apps{bindings: bindings}, book) == nil {
		t.Fatal("orphan catalog use retained without parent")
	}
	encoded, err := book.Encode()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := checker.DecodeCatalog(encoded)
	if err != nil || validateCheckerBindings(apps, restored) != nil {
		t.Fatal("catalog restore lost exact parent", err)
	}
}
