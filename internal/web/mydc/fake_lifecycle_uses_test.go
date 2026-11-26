// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/control"
)

// app bindings come from the deployed app definitions.
func TestLifecycleUsesFromApps(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	alice := passwordLogin(t, f, "alice", "alice")
	bob, _ := keyLogin(t, f, "bob", FixtureKey("bob"))

	u, err := fc(alice).lifecycleUses(ctx, "shop", "http-ready")
	if err != nil || len(u.Items) != 1 {
		t.Fatalf("uses %+v %v", u, err)
	}
	if x := u.Items[0]; x.Revision != 2 || x.Kind != "app-binding" || x.App != "php-shop" || x.Service != "web" || x.Node != "node-a" {
		t.Fatalf("use %+v", x)
	}
	_, err = fc(bob).lifecycleUses(ctx, "shop", "http-ready")
	wantCode(t, err, CodeDenied)

	recRev := func() uint64 {
		p, _ := alice.Lifecycles(ctx, "shop", "")
		for _, e := range p.Items {
			if e.Name == "http-ready" {
				return e.RecordRevision
			}
		}
		t.Fatal("no record")
		return 0
	}
	sel := control.LifecycleScriptSelection{Tenant: "shop", Name: "http-ready", Revision: 2}
	if _, res := submit(t, alice, ActionRetireLifecycleScript, recRev(), sel, rootFor(t, alice, ActionRetireLifecycleScript)); res.Code != ResultApplied {
		t.Fatalf("retire %+v", res)
	}
	if _, res := submit(t, alice, ActionDeleteLifecycleScript, recRev(), sel, rootFor(t, alice, ActionDeleteLifecycleScript)); res.Code != ResultConditionFailed {
		t.Fatalf("delete pinned %+v", res)
	}
	// Down the app: the binding goes, and delete applies.
	apps, _ := alice.Apps(ctx, "shop", "")
	for _, a := range apps.Items {
		if a.App == "php-shop" {
			if _, res := submit(t, alice, ActionDownApp, a.Revision, control.AppDown{Tenant: "shop", App: "php-shop", Operation: "down-l"}, rootFor(t, alice, ActionDownApp)); res.Code != ResultApplied {
				t.Fatalf("down %+v", res)
			}
		}
	}
	if u, _ := fc(alice).lifecycleUses(ctx, "shop", "http-ready"); len(u.Items) != 0 {
		t.Fatalf("after down %+v", u)
	}
	if _, res := submit(t, alice, ActionDeleteLifecycleScript, recRev(), sel, rootFor(t, alice, ActionDeleteLifecycleScript)); res.Code != ResultApplied {
		t.Fatalf("delete %+v", res)
	}
}
