// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/imagesource"
	"github.com/jay94ks/seafield/internal/userauth"
)

// REQ-17 in sfcd's real shape: list, put/delete with the record Revision,
// bind with Group approval, registry-login-test through the reader,
// unbind/drain, pulls and image-usages ExternalSource.
func TestExternalRegistryReal(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	alice := passwordLogin(t, f, "alice", "alice")
	bob, _ := keyLogin(t, f, "bob", FixtureKey("bob"))
	page := func(c Conn) userauth.ExternalRegistriesPage {
		t.Helper()
		p, err := c.ExternalRegistryPage(ctx, "shop", "")
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	find := func(id string) control.ExternalRegistryView {
		t.Helper()
		for _, v := range page(alice).Items {
			if v.Spec.ID == id {
				return v
			}
		}
		t.Fatalf("no %s", id)
		return control.ExternalRegistryView{}
	}

	// The fixture source is put and bound on node-a.
	ex := find("example")
	if ex.Spec.Validate() != nil || ex.Spec.Repository != "shop/**" || ex.Spec.Auth != "password" || ex.Revision != 2 || ex.Reader == nil || ex.Reader.Node != "node-a" || ex.Reader.Generation != 2 {
		t.Fatalf("fixture %+v", ex)
	}
	if len(page(bob).Items) != 1 {
		t.Fatal("reader cannot list")
	}
	if _, err := bob.ExternalRegistryPage(ctx, "payments", ""); err == nil {
		t.Fatal("bob listed another tenant")
	}
	if p, err := alice.ExternalRegistryPage(ctx, "payments", ""); err != nil || len(p.Items) != 0 {
		t.Fatalf("payments %+v %v", p, err)
	}
	if r, err := alice.ProbeExternalRegistry(ctx, "shop", control.ExternalRegistryProbeQuery{ID: "example", Image: "registry.example.com/shop/cron:1.4"}); err != nil || r.Code != "OK" ||
		!r.Valid(control.ExternalRegistryProbeRead{Selection: r.Selection, Image: r.Image.Normalized}) || r.Selection.Generation != 2 {
		t.Fatalf("probe %+v %v", r, err)
	}
	if _, err := alice.ProbeExternalRegistry(ctx, "shop", control.ExternalRegistryProbeQuery{ID: "example", Image: "registry.example.com/other/x:1"}); err == nil {
		t.Fatal("image outside the source")
	}
	if _, err := bob.ProbeExternalRegistry(ctx, "shop", control.ExternalRegistryProbeQuery{ID: "example"}); err == nil {
		t.Fatal("reader probed")
	}
	if u, err := bob.ImageUsages(ctx, "shop", control.ImageUsageQuery{ExternalSource: "example"}, ""); err != nil || len(u.Rows) == 0 || u.Rows[0].Image != "registry.example.com/shop/cron:1.4" || !u.Rows[0].Valid() {
		t.Fatalf("usages %+v %v", u, err)
	}
	if p, err := bob.RegistryPulls(ctx, "shop", ""); err != nil || len(p.Rows) != 1 || p.Rows[0].Source != "example" || !p.Valid("shop", "") {
		t.Fatalf("pulls %+v %v", p, err)
	}

	// put a new source: Expected 0, then the record Revision.
	spec := imagesource.Source{Tenant: "shop", ID: "ghcr", Authority: "ghcr.io", Repository: "shop-org/**", Enabled: true, Auth: "token",
		Credential: &imagesource.Credential{Realm: "shop", ID: "mysql", UsernameKey: "MYSQL_PASSWORD", PasswordKey: "MYSQL_ROOT_PASSWORD"}}
	if _, res := submit(t, bob, ActionPutExternalRegistry, 0, control.ExternalRegistryPut{Spec: spec}, rootFor(t, bob, ActionPutExternalRegistry)); res.Code != ResultForbidden {
		t.Fatalf("reader put %v", res.Code)
	}
	if _, res := submit(t, alice, ActionPutExternalRegistry, 0, control.ExternalRegistryPut{Spec: spec}, rootFor(t, alice, ActionPutExternalRegistry)); res.Code != ResultApplied {
		t.Fatalf("put %v", res.Code)
	}
	moved := spec
	moved.Repository = "other/**"
	if _, res := submit(t, alice, ActionPutExternalRegistry, 1, control.ExternalRegistryPut{Spec: moved}, rootFor(t, alice, ActionPutExternalRegistry)); res.Code != ResultConditionFailed {
		t.Fatalf("scope change %v", res.Code)
	}
	if _, err := alice.ProbeExternalRegistry(ctx, "shop", control.ExternalRegistryProbeQuery{ID: "ghcr"}); err == nil {
		t.Fatal("probe before bind")
	}

	// bind: the credential is in the protected Group shop-db.
	f.SetGroupPassword("shop", "shop-db", "open-sesame")
	plan, err := alice.PlanExternalRegistryBind(ctx, "shop", control.ExternalRegistryBindQuery{ID: "ghcr", Node: "node-a"})
	if err != nil || plan.Expected != 1 {
		t.Fatalf("plan %+v %v", plan, err)
	}
	if _, err := alice.PlanExternalRegistryBind(ctx, "shop", control.ExternalRegistryBindQuery{ID: "ghcr", Node: "node-c"}); err == nil {
		t.Fatal("bind on a server the tenant may not use")
	}
	if _, res := submit(t, alice, ActionBindExternalRegistry, plan.Expected, plan.Selection, rootFor(t, alice, ActionBindExternalRegistry)); res.Code != ResultConditionFailed {
		t.Fatalf("unapproved bind %v", res.Code)
	}
	signed, err := alice.Prepare(ctx, Change{Action: ActionBindExternalRegistry, Expected: plan.Expected, Payload: mustPayload(t, plan.Selection)}, rootFor(t, alice, ActionBindExternalRegistry))
	if err != nil {
		t.Fatal(err)
	}
	origin, _ := DecodeOperation(signed)
	vp, err := alice.PlanVaultApprovals(ctx, "shop", VaultApprovalPlanRequest{Realm: "shop", ID: "compose/" + origin.RequestID, Origin: &origin})
	if err != nil || len(vp.Targets) != 1 || vp.Targets[0].Target.Group != "shop-db" || vp.Targets[0].Target.Purpose != "registry-source" || vp.Targets[0].Target.App != control.ExternalRegistryScope("shop", "ghcr") ||
		vp.Targets[0].Target.Services[0] != "registry" || vp.Targets[0].Target.Actions != [2]string{"resolve", "registry"} {
		t.Fatalf("approval plan %+v %v", vp, err)
	}
	if code, err := alice.ApproveVault(ctx, "shop", *vp.Targets[0].Approver, VaultApprove{Target: vp.Targets[0].Target, Password: []byte("open-sesame"), Origin: &origin}); err != nil || code != "ok" {
		t.Fatalf("approve %s %v", code, err)
	}
	if res, err := alice.Submit(ctx, signed); err != nil || res.Code != ResultApplied {
		t.Fatalf("bind %v %v", res.Code, err)
	}
	g := find("ghcr")
	if g.Revision != 2 || g.Reader == nil || g.Reader.Generation != 2 || g.Reader.Draining {
		t.Fatalf("bound %+v", g)
	}
	if r, err := alice.ProbeExternalRegistry(ctx, "shop", control.ExternalRegistryProbeQuery{ID: "ghcr"}); err != nil || r.Code != "OK" || r.Image != nil {
		t.Fatalf("login only %+v %v", r, err)
	}
	f.SetRegistryLoginResult("ghcr.io", "unauthorized")
	if r, _ := alice.ProbeExternalRegistry(ctx, "shop", control.ExternalRegistryProbeQuery{ID: "ghcr"}); r.Code != "UNAUTHORIZED" {
		t.Fatalf("forced %+v", r)
	}

	// unbind drains; the owner closes it a few seconds later; bind again.
	if _, res := submit(t, alice, ActionUnbindExternalRegistry, 2, control.RegistrySelection{Tenant: "shop", ID: "ghcr"}, rootFor(t, alice, ActionUnbindExternalRegistry)); res.Code != ResultApplied {
		t.Fatalf("unbind %v", res.Code)
	}
	if g := find("ghcr"); g.Revision != 3 || g.Reader == nil || !g.Reader.Draining {
		t.Fatalf("draining %+v", g)
	}
	if _, err := alice.PlanExternalRegistryBind(ctx, "shop", control.ExternalRegistryBindQuery{ID: "ghcr", Node: "node-a"}); err == nil {
		t.Fatal("bind while draining")
	}
	later := f.now().Add(10 * time.Second)
	f.SetClock(func() time.Time { return later })
	if g := find("ghcr"); g.Reader != nil {
		t.Fatalf("not closed %+v", g)
	}
	if _, res := submit(t, alice, ActionPutExternalRegistry, 3, control.ExternalRegistryPut{Spec: spec}, rootFor(t, alice, ActionPutExternalRegistry)); res.Code != ResultApplied {
		t.Fatalf("edit %v", res.Code)
	}
	// delete with the record Revision; the old mock's row is untouched.
	if _, res := submit(t, alice, ActionDeleteExternalRegistry, 4, control.RegistrySelection{Tenant: "shop", ID: "ghcr"}, rootFor(t, alice, ActionDeleteExternalRegistry)); res.Code != ResultApplied {
		t.Fatalf("delete %v", res.Code)
	}
	if g := find("ghcr"); !g.Deleted || g.Revision != 5 {
		t.Fatalf("deleted %+v", g)
	}
	if _, err := alice.ImageUsages(ctx, "shop", control.ImageUsageQuery{ExternalSource: "nope"}, ""); err == nil {
		t.Fatal("usages of an unknown source")
	}
}
