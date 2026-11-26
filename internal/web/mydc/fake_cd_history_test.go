// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/control"
)

func TestCDHistory(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	alice := passwordLogin(t, f, "alice", "alice")
	bob, _ := keyLogin(t, f, "bob", FixtureKey("bob"))
	cd := func() AppCD {
		apps, _ := alice.Apps(ctx, "shop", "")
		for _, a := range apps.Items {
			if a.App == "php-shop" {
				return *a.CD
			}
		}
		t.Fatal("no php-shop")
		return AppCD{}
	}
	results := func() []string {
		p, err := bob.AppDeliveryHistory(ctx, "shop", "php-shop", "")
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, r := range p.Items {
			out = append(out, r.Commit+":"+r.Result)
		}
		return out
	}
	str := func(s string) json.RawMessage { b, _ := json.Marshal(s); return b }

	// Fixture: a1b2c3d running, e4f5a6b candidate changing web's image.
	if got := results(); !slices.Equal(got, []string{"e4f5a6b:candidate", "a1b2c3d:succeeded"}) {
		t.Fatalf("history %v", got)
	}
	ch, err := bob.AppDeliveryChanges(ctx, "shop", "php-shop")
	if err != nil || ch.Count != 1 || ch.Count != cd().ChangeCount || len(ch.Services) != 1 || ch.Services[0].Service != "web" ||
		!slices.Equal(ch.Services[0].Fields[0].Path, []string{"services", "web", "image"}) ||
		string(ch.Services[0].Fields[0].Before) != `"registry.mydc.local/shop/php-shop:1.4.2"` || string(ch.Services[0].Fields[0].After) != `"registry.mydc.local/shop/php-shop:1.4.3"` {
		t.Fatalf("changes %+v %v", ch, err)
	}

	// Sync: the candidate succeeds with the deploy operation; no changes left.
	c := cd()
	q := control.AppCDChange{Tenant: "shop", App: "php-shop", Target: &c.Target,
		Choice: &control.AppDeliveryChoice{Operation: "sync-1", Candidate: c.CandidateDigest, Registration: c.Registration}}
	if _, res := submit(t, alice, ActionSyncApp, c.Revision, q, rootFor(t, alice, ActionSyncApp)); res.Code != ResultApplied {
		t.Fatalf("sync %+v", res)
	}
	p, _ := bob.AppDeliveryHistory(ctx, "shop", "php-shop", "")
	if r := p.Items[0]; r.Commit != "e4f5a6b" || r.Result != CDSucceeded || r.Operation != "sync-1" || r.FinishedAt == 0 {
		t.Fatalf("after sync %+v", r)
	}
	if ch, _ := bob.AppDeliveryChanges(ctx, "shop", "php-shop"); ch.Count != 0 || len(ch.Services) != 0 {
		t.Fatalf("synced changes %+v", ch)
	}

	// One image line changed in Git: one image path, count matches.
	doc := strings.Replace(phpShopYAML, "php-shop:1.4.2", "php-shop:1.4.4", 1)
	f.SetCDCandidate("shop", "php-shop", "f00d001", doc)
	ch, _ = bob.AppDeliveryChanges(ctx, "shop", "php-shop")
	if ch.Count != 1 || ch.Count != cd().ChangeCount || !slices.Equal(ch.Services[0].Fields[0].Path, []string{"services", "web", "image"}) {
		t.Fatalf("new candidate %+v", ch)
	}
	if got := results(); !slices.Equal(got, []string{"f00d001:candidate", "e4f5a6b:succeeded", "a1b2c3d:succeeded"}) {
		t.Fatalf("history %v", got)
	}

	// Override the image: now = the override, Git = the source values.
	path := []string{"services", "web", "image"}
	fq := control.AppCDFieldRequest{App: "php-shop", Path: path}
	fld, err := alice.AppDeliveryField(ctx, "shop", fq)
	if err != nil {
		t.Fatal(err)
	}
	ov := control.AppOverrideChange{Target: &fld.Target, Tenant: "shop", App: "php-shop", Path: path, Value: str("registry.mydc.local/shop/php-shop:hotfix"), Refs: fld.Refs}
	if _, res := submit(t, alice, ActionOverrideApp, fld.Revision, ov, rootFor(t, alice, ActionOverrideApp)); res.Code != ResultApplied {
		t.Fatalf("override %+v", res)
	}
	v, err := bob.AppDeliveryValues(ctx, "shop", fq)
	if err != nil || !v.Overridden || string(v.Current) != `"registry.mydc.local/shop/php-shop:hotfix"` ||
		string(v.GitRunning) != `"registry.mydc.local/shop/php-shop:1.4.3"` || string(v.GitCandidate) != `"registry.mydc.local/shop/php-shop:1.4.4"` ||
		v.Running != "e4f5a6b" || v.Candidate != "f00d001" {
		t.Fatalf("values %+v %v", v, err)
	}
	v, _ = bob.AppDeliveryValues(ctx, "shop", control.AppCDFieldRequest{App: "php-shop", Path: []string{"services", "db", "image"}})
	if v.Overridden || string(v.Current) != `"mysql:8.4"` || string(v.GitRunning) != `"mysql:8.4"` {
		t.Fatalf("db values %+v", v)
	}

	// A secret projection gives the selector, not a value; a removed service
	// and a changed secrets_from count.
	doc = strings.Replace(phpShopYAML, "      node: node-b\n", "      node: node-b\n      secrets_from: [mysql]\n", 1)
	doc = doc[:strings.Index(doc, "  db:\n")] + strings.Replace(doc[strings.Index(doc, "  db:\n"):], "  db:\n", "  store:\n", 1)
	f.SetCDCandidate("shop", "php-shop", "f00d002", doc)
	if got := results(); got[0] != "f00d002:candidate" || got[1] != "f00d001:abandoned" {
		t.Fatalf("superseded %v", got)
	}
	ch, _ = bob.AppDeliveryChanges(ctx, "shop", "php-shop")
	if !slices.Equal(ch.Added, []string{"store"}) || !slices.Equal(ch.Removed, []string{"db"}) || ch.Count != cd().ChangeCount {
		t.Fatalf("add/remove %+v", ch)
	}
	c = cd()
	q = control.AppCDChange{Tenant: "shop", App: "php-shop", Target: &c.Target,
		Choice: &control.AppDeliveryChoice{Operation: "sync-2", Candidate: c.CandidateDigest, Registration: c.Registration}}
	if _, res := submit(t, alice, ActionSyncApp, c.Revision, q, rootFor(t, alice, ActionSyncApp)); res.Code != ResultApplied {
		t.Fatalf("sync 2 %+v", res)
	}
	v, _ = bob.AppDeliveryValues(ctx, "shop", control.AppCDFieldRequest{App: "php-shop", Path: []string{"services", "store", "environment", "MYSQL_PASSWORD"}})
	if v.Current != nil || v.GitRunning != nil || !slices.Equal(v.Secrets, []string{"secret:mysql"}) {
		t.Fatalf("secret %+v", v)
	}

	// Not a field, not a CD app, another tenant.
	_, err = bob.AppDeliveryValues(ctx, "shop", control.AppCDFieldRequest{App: "php-shop", Path: []string{"services", "web", "x-mydc"}})
	wantCode(t, err, CodeDenied)
	_, err = bob.AppDeliveryHistory(ctx, "shop", "shop-worker", "")
	wantCode(t, err, CodeInvalid)
	_, err = bob.AppDeliveryChanges(ctx, "payments", "payments-api")
	wantCode(t, err, CodeDenied)
}
