// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/ingress"
	"reflect"
	"testing"
)

func TestIngressBlockTargetRevisionUsesPolicyBookNotStateOrRowRevision(t *testing.T) {
	f, _ := imageBuildFixture(t)
	read := func() IngressPage {
		t.Helper()
		page, err := f.p.IngressPage(f.s, f.sessions["admin"], 2, IngressQuery{Part: "blocks"})
		if err != nil {
			t.Fatal(err)
		}
		book, err := f.p.IngressManagement(f.s)
		if err != nil || page.BlockRevision != book.Revision || page.RootRevision != f.s.Object(IngressManagementKey).Revision {
			t.Fatal("policy target/storage CAS conflated", page, book.Revision, err)
		}
		return page
	}
	if page := read(); page.BlockRevision != 0 {
		t.Fatal("empty policy acquired a fabricated target", page.BlockRevision)
	}
	block := ingress.Block{ID: "target", Scope: "node", Node: "node-a", Response: "503"}
	f.apply("admin", "ingress-block", 0, IngressBlockChange{Block: block}, state.Applied)
	f.apply("admin", "ingress-unblock", 1, IngressBlockSelection{ID: block.ID}, state.Applied)
	cleared := read()
	if cleared.BlockRevision != 2 || cleared.RootRevision == cleared.BlockRevision || len(cleared.Blocks) != 1 || !cleared.Blocks[0].Removed {
		t.Fatal("original unblock target unavailable or aliased to storage CAS", cleared)
	}
	f.apply("admin", "create-tenant", 0, TenantID{ID: "unrelated"}, state.Applied)
	after := read()
	if after.Index <= cleared.Index || after.BlockRevision != cleared.BlockRevision || after.RootRevision != cleared.RootRevision {
		t.Fatal("unrelated management change moved block target", cleared, after)
	}
	other := block
	other.ID = "another"
	f.apply("admin", "ingress-block", 0, IngressBlockChange{Block: other}, state.Applied)
	latest := read()
	if latest.BlockRevision != 3 || latest.Blocks[0].Revision == latest.BlockRevision && latest.Blocks[1].Revision == latest.BlockRevision {
		t.Fatal("per-block CAS used as global target", latest)
	}
	changed := latest
	changed.BlockRevision++
	if latest.SameSelection(changed) {
		t.Fatal("collected observation accepted a different policy target")
	}
}

func TestIngressVisibleListenersCountSharedAddressOncePerNode(t *testing.T) {
	shared := []ingress.Listener{{ID: "outside", Shared: "external"}, {ID: "inside", Shared: "local"}}
	seen := map[string]bool{}
	if got := countIngressListeners("node-a", shared, seen); got != 2 {
		t.Fatal("first visible app lost its listener addresses", got)
	}
	if got := countIngressListeners("node-a", shared, seen); got != 0 {
		t.Fatal("another visible app charged the same shared addresses again", got)
	}
	if got := countIngressListeners("node-b", shared, seen); got != 2 {
		t.Fatal("different node's addresses merged with node-a", got)
	}
	if got := countIngressListeners("node-a", []ingress.Listener{{ID: "direct", Address: "192.0.2.1:8443"}}, seen); got != 1 {
		t.Fatal("direct listener disappeared from the summary", got)
	}
	// An independently authorized tenant selection gets its own census, not
	// process-global state left by another tenant or broad system query.
	if got := countIngressListeners("node-a", shared, map[string]bool{}); got != 2 {
		t.Fatal("new scoped query inherited another selection's seen addresses", got)
	}
}

func TestIngressReadRevocationCannotPublishPriorBroadSelection(t *testing.T) {
	f := newNodeStorageFixture(t)
	admin := f.sessions["admin"]
	admin.Scopes[0].Actions = append(admin.Scopes[0].Actions, access.ManageMembers)
	admin.Signature = ed25519.Sign(f.node, access.SessionBytes(admin))
	f.sessions["admin"] = admin
	f.apply("admin", "create-tenant", 0, TenantID{ID: "other"}, state.Applied)
	f.apply("admin", "set-membership", 0, access.Membership{Tenant: "other", User: "manager", Role: access.Manager, Enabled: true}, state.Applied)
	for _, tenant := range []string{"tenant", "other"} {
		f.apply("admin", "set-ingress-host-policy", 0, IngressHostPolicyChange{Tenant: tenant, Policy: ingress.HostPolicy{LocalHosts: []string{tenant + ".internal.example"}}}, state.Applied)
	}
	query := IngressQuery{Part: "policies"}
	collected, err := f.p.IngressPage(f.s, f.sessions["manager"], 2, query)
	if err != nil || len(collected.HostPolicies) != 2 {
		t.Fatal("original broad selection", collected, err)
	}
	users, err := f.p.Catalog(f.s)
	if err != nil {
		t.Fatal(err)
	}
	membership, _ := users.Membership("tenant", "manager")
	f.apply("admin", "set-membership", membership.Revision, access.Membership{Tenant: "tenant", User: "manager", Role: access.Manager, Enabled: false}, state.Applied)
	current, err := f.p.IngressPage(f.s, f.sessions["manager"], 2, query)
	if err != nil || len(current.HostPolicies) != 1 || current.HostPolicies[0].Tenant != "other" {
		t.Fatal("remaining tenant read must still be authorized", current, err)
	}
	if collected.SameSelection(current) {
		t.Fatal("re-authorizing the broad query exposed a revoked tenant's collected data")
	}
	if !current.SameSelection(current) {
		t.Fatal("unchanged selection rejected")
	}
}

// Existing actual FSM/signature fixture; this does not claim native socket
// application or real HTTP success, which belong to the RQ7 final adapter gate.
func TestIngressBlockFSMOriginalCASPermissionAndRestore(t *testing.T) {
	f, _ := imageBuildFixture(t)
	before := f.s.Objects("workload/")
	b := ingress.Block{ID: "incident", Scope: "node", Node: "node-a", Response: "503", ExpiresAt: 100, Reason: "maintenance"}
	f.apply("manager", "ingress-block", 0, IngressBlockChange{Block: b}, state.Forbidden)
	f.apply("admin", "ingress-block", 0, IngressBlockChange{Block: b}, state.Applied)
	book, err := f.p.IngressManagement(f.s)
	if err != nil || len(book.Blocks) != 1 || book.Blocks[0].Block.Actor != "admin" || book.Blocks[0].Revision != 1 {
		t.Fatal(book, err)
	}
	origin := book.Blocks[0].Origin
	f.apply("admin", "ingress-block-extend", 0, IngressBlockSelection{ID: b.ID, ExpiresAt: 200}, state.ConditionFailed)
	f.apply("admin", "ingress-block-extend", 1, IngressBlockSelection{ID: b.ID, ExpiresAt: 200}, state.Applied)
	f.apply("manager", "ingress-unblock", 2, IngressBlockSelection{ID: b.ID}, state.Forbidden)
	f.apply("admin", "ingress-unblock", 2, IngressBlockSelection{ID: b.ID}, state.Applied)
	book, err = f.p.IngressManagement(f.s)
	if err != nil || !book.Blocks[0].Removed || !reflect.DeepEqual(book.Blocks[0].Origin, origin) || len(book.ConfiguredBlocks()) != 0 {
		t.Fatal("original history or unblock lost", err)
	}
	if !reflect.DeepEqual(before, f.s.Objects("workload/")) {
		t.Fatal("emergency block changed Desired/workload")
	}
	raw, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := state.Decode(raw)
	if err != nil || f.p.Validate(state.State{}, restored, state.Command{}) != nil {
		t.Fatal("checkpoint lost block evidence", err)
	}
}
func TestIngressHostPolicyIsSystemAdminOwned(t *testing.T) {
	f, _ := imageBuildFixture(t)
	q := IngressHostPolicyChange{Tenant: "tenant", Policy: ingress.HostPolicy{LocalHosts: []string{"*.internal.example"}}}
	f.apply("manager", "set-ingress-host-policy", 0, q, state.Forbidden)
	f.apply("admin", "set-ingress-host-policy", 0, q, state.Applied)
	book, err := f.p.IngressManagement(f.s)
	if err != nil || !reflect.DeepEqual(book.HostPolicy("tenant"), q.Policy) || book.HostPolicy("unknown").ExternalAllowed || len(book.HostPolicy("unknown").LocalHosts) != 0 {
		t.Fatal("host default/ownership", err)
	}
}

func TestIngressHostPolicyRevocationPreservesStateAndDeniesNewEffects(t *testing.T) {
	f, _ := imageBuildFixture(t)
	d := deployment.IngressDeclaration{Listeners: []deployment.ListenerDeclaration{{Shared: "web"}}, Host: "shop.internal.example"}
	if err := f.p.admitIngressDeclaration(f.s, "tenant", "admin", d); err == nil {
		t.Fatal("missing host grant accepted")
	}
	f.apply("admin", "set-ingress-host-policy", 0, IngressHostPolicyChange{Tenant: "tenant", Policy: ingress.HostPolicy{LocalHosts: []string{"*.internal.example"}}}, state.Applied)
	if err := f.p.admitIngressDeclaration(f.s, "tenant", "admin", d); err != nil {
		t.Fatal("explicit host grant rejected", err)
	}
	f.apply("admin", "set-ingress-host-policy", 1, IngressHostPolicyChange{Tenant: "tenant"}, state.Applied)
	if err := f.p.admitIngressDeclaration(f.s, "tenant", "admin", d); err == nil {
		t.Fatal("revoked grant admitted new effect")
	}
	if _, err := f.p.ProjectResources(f.s); err != nil {
		t.Fatal("revocation invalidated management state", err)
	}
}
