// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
)

func TestVaultApprovalList(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	admin := passwordLogin(t, f, "admin", "admin")
	alice := passwordLogin(t, f, "alice", "alice")
	bob, _ := keyLogin(t, f, "bob", FixtureKey("bob"))
	f.SetGroupPassword("shop", "shop-db", "open-sesame")
	f.mu.Lock()
	f.w.vault = append(f.w.vault, VaultView{Realm: "shop", ID: "shop-db", Path: "shop-db", Kind: "group", MaxApprovalAge: 3600})
	f.mu.Unlock()

	// alice deploys php-shop with the protected Group and approves it.
	doc := []byte(strings.Replace(phpShopYAML, "      node: node-b\n", "      node: node-b\n      secrets: {from: [group/shop-db]}\n", 1))
	uploadApp(t, alice, "shop", "php-shop", "up-g", doc)
	apps, _ := alice.Apps(ctx, "shop", "")
	var cur AppView
	for _, a := range apps.Items {
		if a.App == "php-shop" {
			cur = a
		}
	}
	signed, err := alice.Prepare(ctx, Change{Action: ActionBeginApp, Expected: cur.Revision,
		Payload: mustPayload(t, control.AppBegin{Tenant: "shop", App: "php-shop", Deployment: cur.Deployment, Upload: "up-g", Operation: "deploy-g"})}, root(t, alice))
	if err != nil {
		t.Fatal(err)
	}
	origin, err := DecodeOperation(signed)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := alice.PlanVaultApprovals(ctx, "shop", VaultApprovalPlanRequest{Realm: "shop", ID: "compose/up-g", Origin: &origin})
	if err != nil || len(plan.Targets) != 1 {
		t.Fatalf("plan %+v %v", plan, err)
	}
	tg := plan.Targets[0]
	if code, err := alice.ApproveVault(ctx, "shop", *tg.Approver, VaultApprove{Target: tg.Target, Password: []byte("open-sesame"), Origin: &origin}); err != nil || code != "ok" {
		t.Fatalf("approve %s %v", code, err)
	}

	p, err := fc(alice).vaultApprovals(ctx, "shop", "", "")
	if err != nil || len(p.Items) != 1 {
		t.Fatalf("list %+v %v", p, err)
	}
	r := p.Items[0]
	if r.ID != tg.Target.ApprovalID || r.Group != "shop-db" || r.User != "u-alice" || r.App != "php-shop" || r.Services[0] != "db" ||
		r.Nodes[0] != "node-b" || r.Issuer != "node-a" || r.ExpiresAt != r.ApprovedAt+3600 || r.Revoked {
		t.Fatalf("row %+v", r)
	}
	// bob (reader) sees only his own: none. Other tenant / app filter.
	if b, err := fc(bob).vaultApprovals(ctx, "shop", "", ""); err != nil || len(b.Items) != 0 {
		t.Fatalf("bob %+v %v", b, err)
	}
	if x, _ := fc(alice).vaultApprovals(ctx, "shop", "shop-worker", ""); len(x.Items) != 0 {
		t.Fatalf("app filter %+v", x)
	}
	if x, _ := fc(admin).vaultApprovals(ctx, "payments", "", ""); len(x.Items) != 0 {
		t.Fatalf("payments %+v", x)
	}

	// Revoke: bob is refused, stale Expected fails, alice revokes.
	sel := VaultApprovalSelection{ID: r.ID}
	if _, res := submit(t, bob, ActionVaultRevokeApproval, p.Collection, sel, rootFor(t, bob, ActionVaultRevokeApproval)); res.Code != ResultForbidden {
		t.Fatalf("bob revoke %+v", res)
	}
	if _, res := submit(t, alice, ActionVaultRevokeApproval, p.Collection-1, sel, rootFor(t, alice, ActionVaultRevokeApproval)); res.Code != ResultConditionFailed {
		t.Fatalf("stale revoke %+v", res)
	}
	if _, res := submit(t, alice, ActionVaultRevokeApproval, p.Collection, sel, rootFor(t, alice, ActionVaultRevokeApproval)); res.Code != ResultApplied {
		t.Fatalf("revoke %+v", res)
	}
	q, _ := fc(alice).vaultApprovals(ctx, "shop", "", "")
	if !q.Items[0].Revoked || q.Items[0].RevokedAt == 0 || q.Collection <= p.Collection {
		t.Fatalf("after revoke %+v", q)
	}
	if f.GroupApproved("shop", "shop-db", origin.RequestID) {
		t.Fatal("revoked approval still counts")
	}
}

// A CD candidate's Group approval is a row of the list too.
func TestVaultApprovalListCD(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	alice := passwordLogin(t, f, "alice", "alice")
	f.SetGroupPassword("shop", "shop-db", "open-sesame")
	f.mu.Lock()
	a := f.w.apps["shop/php-shop"]
	src := a.sources[len(a.sources)-1]
	src.Document = []byte(strings.Replace(string(src.Document), "      node: node-b\n", "      node: node-b\n      secrets: {from: [group/shop-db]}\n", 1))
	a.sources[len(a.sources)-1] = src
	cand := candidateDigest("shop", "php-shop", a.view.CD.Candidate)
	f.mu.Unlock()

	sel := AppApprovalSelection{Candidate: &cand}
	reg, err := alice.AppDeliveryRegistration(ctx, "shop", "php-shop", sel)
	if err != nil || len(reg.Realms) != 1 {
		t.Fatalf("registration %+v %v", reg, err)
	}
	plan, err := alice.PlanVaultApprovals(ctx, "shop", VaultApprovalPlanRequest{Realm: "shop", ID: "compose/php-shop/cd", Origin: &reg.Origin, Selection: &reg.Selection})
	if err != nil || len(plan.Targets) != 1 {
		t.Fatalf("plan %+v %v", plan, err)
	}
	tg := plan.Targets[0]
	if code, err := alice.ApproveVault(ctx, "shop", *tg.Approver, VaultApprove{Target: tg.Target, Password: []byte("open-sesame"), Origin: &reg.Origin, Selection: &reg.Selection}); err != nil || code != "ok" {
		t.Fatalf("approve %s %v", code, err)
	}
	p, err := fc(alice).vaultApprovals(ctx, "shop", "php-shop", "")
	if err != nil || len(p.Items) != 1 || p.Items[0].ID != tg.Target.ApprovalID || p.Items[0].Group != "shop-db" {
		t.Fatalf("list %+v %v", p, err)
	}
}
