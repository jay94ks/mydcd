// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"slices"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
)

func TestImageTrust(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	admin := passwordLogin(t, f, "admin", "admin")
	alice := passwordLogin(t, f, "alice", "alice")

	// A new tenant trusts Docker Hub, as the sfcd catalog does.
	if _, res := submit(t, admin, ActionCreateTenant, 0, control.TenantID{ID: "fresh"}, rootFor(t, admin, ActionCreateTenant)); res.Code != ResultApplied {
		t.Fatalf("create %+v", res)
	}
	v, err := fc(admin).imageTrust(ctx, "fresh")
	if err != nil || len(v.Rules) != 1 || v.Rules[0] != (TrustRule{Registry: "docker.io", Repository: "**"}) || v.Revision == 0 || len(v.Uses) != 0 {
		t.Fatalf("fresh %+v %v", v, err)
	}

	// php-shop/db (mysql) is allowed by rule 1 only; no payments image shows.
	v, err = fc(alice).imageTrust(ctx, "shop")
	if err != nil {
		t.Fatal(err)
	}
	db := func(v ImageTrust) *ImageTrustUse {
		for i, u := range v.Uses {
			if u.App == "php-shop" && u.Service == "db" {
				return &v.Uses[i]
			}
		}
		return nil
	}
	if u := db(v); u == nil || !slices.Equal(u.Rules, []int{1}) || u.Deployment == "" {
		t.Fatalf("db %+v", v.Uses)
	}
	if slices.ContainsFunc(v.Uses, func(u ImageTrustUse) bool { return u.App == "payments-api" }) {
		t.Fatalf("payments leaked %+v", v.Uses)
	}

	// set-trust without mysql: rules and revision change, db is untrusted.
	drop := slices.DeleteFunc(slices.Clone(v.Rules), func(r TrustRule) bool { return r.Repository != "library/mysql" })
	if _, res := submit(t, alice, ActionSetTrust, v.Revision, control.TrustChange{Tenant: "shop", Remove: drop}, rootFor(t, alice, ActionSetTrust)); res.Code != ResultApplied {
		t.Fatalf("set-trust %+v", res)
	}
	w, _ := fc(alice).imageTrust(ctx, "shop")
	if w.Revision == v.Revision || len(w.Rules) != len(v.Rules)-len(drop) || db(w) == nil || len(db(w).Rules) != 0 {
		t.Fatalf("after set-trust %+v", w)
	}

	// Down php-shop: its images drop out.
	apps, _ := alice.Apps(ctx, "shop", "")
	var a AppView
	for _, x := range apps.Items {
		if x.App == "php-shop" {
			a = x
		}
	}
	if _, res := submit(t, alice, ActionDownApp, a.Revision, control.AppDown{Tenant: "shop", App: "php-shop", Operation: "down-t"}, rootFor(t, alice, ActionDownApp)); res.Code != ResultApplied {
		t.Fatalf("down %+v", res)
	}
	w, _ = fc(alice).imageTrust(ctx, "shop")
	if slices.ContainsFunc(w.Uses, func(u ImageTrustUse) bool { return u.App == "php-shop" }) {
		t.Fatalf("after down %+v", w.Uses)
	}

	// Read needed: bob has no role in payments.
	bob, _ := keyLogin(t, f, "bob", FixtureKey("bob"))
	_, err = fc(bob).imageTrust(ctx, "payments")
	wantCode(t, err, CodeDenied)
}
