// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
)

func TestCDFieldQueryKeepsScopeAndNeverInventsAnOwnedAnchor(t *testing.T) {
	f := deliveryControlFixture(t)
	c, _ := f.p.Catalog(f.s)
	q := AppCDFieldRequest{App: "source-app", Path: []string{"services", "web", "environment", "APP_MODE"}}
	view, err := f.p.AppDeliveryField(f.s, c, "admin", "tenant", q)
	if err != nil || view.Schema != 1 || view.Revision == 0 || len(view.Refs) != 0 || view.Override != nil {
		t.Fatal("unexecuted graph became an owned native task", view, err)
	}
	q.Path[3] = "CHANGED"
	if view.Path[3] != "APP_MODE" {
		t.Fatal("query retained caller path bytes")
	}
	if _, err := f.p.AppDeliveryField(f.s, c, "missing", "tenant", q); err == nil {
		t.Fatal("missing user could read ownership")
	}
	if _, err := f.p.AppDeliveryField(f.s, c, "admin", "other", q); err == nil {
		t.Fatal("tenant selected a foreign app")
	}
	q.Path = []string{"networks", "lan", "x-sfc", "mtu"}
	if _, err := f.p.AppDeliveryField(f.s, c, "admin", "tenant", q); err == nil {
		t.Fatal("management field exposed as an app field")
	}
}

func TestCDOverrideRejectsUnownedTaskAndRequiresCurrentSessionCDGrant(t *testing.T) {
	f := deliveryControlFixture(t)
	a, _ := f.p.Apps(f.s)
	d, _ := a.Delivery("tenant", "source-app")
	q := AppOverrideChange{Tenant: "tenant", App: "source-app", Path: []string{"services", "web", "cpus"}, Value: []byte(`"0.1"`), Refs: []deployment.ObjectRef{{Key: deployment.ResourceKey("task", "tenant", "source-app", "web"), Revision: 1, Generation: 1}}}
	f.apply("unowned-field", "override-app", d.Revision(), q, state.ConditionFailed)
	q.Path = []string{"networks", "lan", "x-sfc", "mtu"}
	f.apply("management-field", "override-app", d.Revision(), q, state.Invalid)
	q.Path = []string{"services", "web", "cpus"}
	f.session.Scopes[0].Actions = []access.Action{access.Read, access.Deploy}
	f.session.Signature = ed25519.Sign(f.node, access.SessionBytes(f.session))
	f.apply("session-without-cd", "override-app", d.Revision(), q, state.Forbidden)
}
