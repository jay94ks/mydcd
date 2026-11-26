// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"slices"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/control"
)

func TestCDLocalServices(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	alice := passwordLogin(t, f, "alice", "alice")
	bob, _ := keyLogin(t, f, "bob", FixtureKey("bob"))
	// put sends a local services document as mydcd takes it: an app upload,
	// then put-app-local-services naming it ("" = clear).
	put := func(c Conn, doc, op string) ResultCode {
		t.Helper()
		l, _ := bob.AppDeliveryLocal(ctx, "shop", "php-shop")
		target := l.Target
		q := AppLocalChange{Tenant: "shop", App: "php-shop", Registration: l.Registration, Revision: l.LocalRevision, Target: &target}
		action := ActionClearAppLocalServices
		if doc != "" {
			action = ActionPutAppLocalServices
			q.Upload, q.Digest, q.Services = op, digestOf([]byte(doc)), serviceNames(doc)
			if _, res := submit(t, c, ActionBeginAppUpload, 0, control.AppUploadBegin{Tenant: "shop", App: "php-shop", ID: op, Length: len(doc), Digest: q.Digest}, rootFor(t, c, ActionBeginAppUpload)); res.Code != ResultApplied {
				return res.Code
			}
			if _, res := submit(t, c, ActionPutAppPart, 1, control.AppUploadPart{Tenant: "shop", ID: op, Data: []byte(doc)}, rootFor(t, c, ActionPutAppPart)); res.Code != ResultApplied {
				return res.Code
			}
		}
		_, res := submit(t, c, action, l.Revision, q, rootFor(t, c, action))
		return res.Code
	}
	l, err := bob.AppDeliveryLocal(ctx, "shop", "php-shop")
	if err != nil || l.LocalRevision != 0 || !slices.Equal(l.GitServices, []string{"db", "web"}) || len(l.Services) != 0 {
		t.Fatalf("empty %+v %v", l, err)
	}
	local := "services:\n  report:\n    image: registry.mydc.local/shop/report:1\n    x-mydc:\n      node: node-a\n    networks: [shop-net]\n"

	// A Git service cannot be changed or depended on; a reader cannot put.
	if c := put(alice, "services:\n  web:\n    image: x:1\n    x-mydc:\n      node: node-a\n", "loc-g"); c != ResultInvalid {
		t.Fatalf("git service %v", c)
	}
	if c := put(alice, strings.Replace(local, "    networks:", "    depends_on: [db]\n    networks:", 1), "loc-d"); c != ResultInvalid {
		t.Fatalf("depends %v", c)
	}
	if c := put(bob, local, "loc-b"); c != ResultForbidden {
		t.Fatalf("bob %v", c)
	}
	if c := put(alice, local, "loc-1"); c != ResultApplied {
		t.Fatalf("put %v", c)
	}
	l, _ = bob.AppDeliveryLocal(ctx, "shop", "php-shop")
	if !slices.Equal(l.Services, []string{"report"}) || l.LocalRevision != 1 || l.Document != local || l.Actor != "alice" {
		t.Fatalf("local %+v", l)
	}
	// Nothing runs before the next sync.
	report := func() bool {
		tasks, _ := bob.Tasks(ctx, TaskFilter{Tenant: "shop", App: "php-shop"}, "")
		return slices.ContainsFunc(tasks.Items, func(t Task) bool { return t.Service == "report" })
	}
	if report() {
		t.Fatal("report runs before a sync")
	}

	// Sync runs Git's document with the local service.
	sync := func(op string) ResultCode {
		apps, _ := alice.Apps(ctx, "shop", "")
		var c AppCD
		for _, a := range apps.Items {
			if a.App == "php-shop" {
				c = *a.CD
			}
		}
		_, res := submit(t, alice, ActionSyncApp, c.Revision, control.AppCDChange{Tenant: "shop", App: "php-shop", Target: &c.Target,
			Choice: &control.AppDeliveryChoice{Operation: op, Candidate: c.CandidateDigest, Registration: c.Registration}}, root(t, alice))
		return res.Code
	}
	if c := sync("sync-1"); c != ResultApplied {
		t.Fatalf("sync %v", c)
	}
	if !report() {
		t.Fatal("report task missing after sync")
	}
	if l, _ := bob.AppDeliveryLocal(ctx, "shop", "php-shop"); !slices.Equal(l.Services, []string{"report"}) {
		t.Fatalf("after sync %+v", l)
	}

	// Git gains a "report" service: sync stops with a named conflict.
	f.SetCDCandidate("shop", "php-shop", "c0de001", phpShopYAML+"  report:\n    image: registry.mydc.local/shop/report:2\n    x-mydc:\n      node: node-b\n")
	if l, _ := bob.AppDeliveryLocal(ctx, "shop", "php-shop"); !slices.Equal(l.Conflicts, []string{"report"}) {
		t.Fatalf("conflicts %+v", l)
	}
	if c := sync("sync-2"); c != ResultConditionFailed {
		t.Fatalf("conflict sync %v", c)
	}
	p, _ := bob.AppDeliveryHistory(ctx, "shop", "php-shop", "")
	if p.Items[0].Result != CDBlocked || p.Items[0].Reason != "name-conflict" {
		t.Fatalf("history %+v", p.Items[0])
	}
	// Removing the local service clears the conflict.
	if c := put(alice, "", "loc-2"); c != ResultApplied {
		t.Fatalf("remove %v", c)
	}
	if c := sync("sync-3"); c != ResultApplied {
		t.Fatalf("sync after remove %v", c)
	}
}
