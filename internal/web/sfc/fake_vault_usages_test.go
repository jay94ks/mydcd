// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"slices"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
)

func TestVaultUsages(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	admin := passwordLogin(t, f, "admin", "admin")
	alice := passwordLogin(t, f, "alice", "alice")
	bob, _ := keyLogin(t, f, "bob", FixtureKey("bob"))
	f.mu.Lock()
	// shop-worker's current app.yaml gains {secret: mysql} on worker.
	src := f.w.apps["shop/shop-worker"].sources
	last := &src[len(src)-1]
	last.Document = []byte(strings.Replace(string(last.Document), "      node: node-b\n", "      node: node-b\n      secrets: {from: [mysql]}\n", 1))
	f.w.vault = append(f.w.vault, VaultView{Realm: "shop", ID: "shop-db", Path: "shop-db", Kind: "group", Parent: "shop", Status: "active", Revision: 31})
	f.mu.Unlock()

	// shop-worker/worker names {secret: mysql}: listed, live, by the object,
	// its Group and the realm root.
	for _, id := range []string{"mysql", "shop-db", "shop"} {
		p, err := fc(alice).vaultUsages(ctx, "shop", id, "")
		if err != nil || len(p.Items) != 1 {
			t.Fatalf("%s: %+v %v", id, p, err)
		}
		u := p.Items[0]
		if u.App != "shop-worker" || u.Service != "worker" || u.Node != "node-b" || u.Selector != "mysql" ||
			!slices.Equal(u.Secrets, []string{"mysql"}) || !u.Live || u.Deployment == "" {
			t.Fatalf("%s: %+v", id, u)
		}
	}
	if p, err := fc(admin).vaultUsages(ctx, "shop", "mysql", ""); err != nil || len(p.Items) != 1 {
		t.Fatalf("admin %+v %v", p, err)
	}
	// bob is a shop reader; alice only views payments; unknown id.
	_, err := fc(bob).vaultUsages(ctx, "shop", "mysql", "")
	wantCode(t, err, CodeDenied)
	_, err = fc(alice).vaultUsages(ctx, "payments", "stripe", "")
	wantCode(t, err, CodeDenied)
	if p, err := fc(admin).vaultUsages(ctx, "payments", "payments", ""); err != nil || len(p.Items) != 0 {
		t.Fatalf("payments root %+v %v", p, err)
	}
	_, err = fc(alice).vaultUsages(ctx, "shop", "nope", "")
	wantCode(t, err, CodeMissing)

	rev := func() uint64 {
		f.mu.Lock()
		defer f.mu.Unlock()
		i := slices.IndexFunc(f.w.vault, func(v VaultView) bool { return v.Realm == "shop" && v.ID == "mysql" })
		return f.w.vault[i].Revision
	}
	sel := struct{ Realm, ID string }{"shop", "mysql"}
	if _, res := submit(t, alice, ActionVaultRevoke, rev(), sel, rootFor(t, alice, ActionVaultRevoke)); res.Code != ResultApplied {
		t.Fatalf("revoke %+v", res)
	}
	if _, res := submit(t, alice, ActionVaultRetire, rev(), sel, rootFor(t, alice, ActionVaultRetire)); res.Code != ResultConditionFailed {
		t.Fatalf("retire while live %+v", res)
	}

	// Down shop-worker: the usage stays, not live; retire then applies.
	apps, _ := alice.Apps(ctx, "shop", "")
	var a AppView
	for _, x := range apps.Items {
		if x.App == "shop-worker" {
			a = x
		}
	}
	if _, res := submit(t, alice, ActionDownApp, a.Revision, control.AppDown{Tenant: "shop", App: "shop-worker", Operation: "down-v"}, rootFor(t, alice, ActionDownApp)); res.Code != ResultApplied {
		t.Fatalf("down %+v", res)
	}
	if p, err := fc(alice).vaultUsages(ctx, "shop", "mysql", ""); err != nil || len(p.Items) != 1 || p.Items[0].Live {
		t.Fatalf("after down %+v %v", p, err)
	}
	if _, res := submit(t, alice, ActionVaultRetire, rev(), sel, rootFor(t, alice, ActionVaultRetire)); res.Code != ResultApplied {
		t.Fatalf("retire %+v", res)
	}
}
