// SPDX-License-Identifier: Apache-2.0

package control

import (
	"fmt"
	"testing"

	"github.com/jay94ks/seafield/internal/certstore"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
)

func TestIngressRouteOverlapStopsPlanUnlessHeld(t *testing.T) {
	use := func(tenant, app, host, prefix string) ingressRouteUse {
		return ingressRouteUse{tenant, app, "node-a", "external-http", "external", host, prefix}
	}
	others := []ingressRouteUse{use("team", "shop", "shop.example", "/")}
	if code := inputCode(ingressRouteOverlap("team", "blog", []ingressRouteUse{use("team", "blog", "shop.example", "/")}, others)); code != "INGRESS_ROUTE_TAKEN" {
		t.Fatal("same host+prefix of another app was not refused", code)
	}
	if err := ingressRouteOverlap("team", "blog", []ingressRouteUse{use("team", "blog", "shop.example", "/blog")}, others); err != nil {
		t.Fatal("another prefix is free", err)
	}
	// After a forced share, blog's later deploys keep the route.
	shared := append(others, use("team", "blog", "shop.example", "/"))
	if err := ingressRouteOverlap("team", "blog", []ingressRouteUse{use("team", "blog", "shop.example", "/")}, shared); err != nil {
		t.Fatal("a route the app already serves is not new", err)
	}
}

func TestTenantRouteHostsFollowDomainOwners(t *testing.T) {
	f := newNodeStorageFixture(t)
	f.apply("admin", "create-tenant", 0, TenantID{ID: "other"}, state.Applied)
	f.apply("admin", "add-domain", 0, DomainChange{Name: "example.com"}, state.Applied)
	f.apply("admin", "add-domain", 1, DomainChange{Name: "shop.example.com", Tenant: "tenant"}, state.Applied)
	f.apply("admin", "add-domain", 2, DomainChange{Name: "other.example", Tenant: "other"}, state.Applied)
	users, _ := f.p.Catalog(f.s)
	c, _ := f.p.Certificates(f.s)
	for host, want := range map[string][2]string{
		"shop.example.com":       {HostOpen, ""},
		"*.api.shop.example.com": {HostOpen, ""},
		"www.example.com":        {HostPending, ""},
		"api.other.example":      {"", "INGRESS_DOMAIN_OTHER_TENANT"},
		"blog.example.org":       {"", "INGRESS_DOMAIN_UNKNOWN"},
		"*":                      {HostOpen, ""},
	} {
		if st, code := hostJudgment(c, users, "tenant", host); st != want[0] || code != want[1] {
			t.Fatal(host, st, code)
		}
	}
	d := func(host string) deployment.IngressDeclaration {
		return deployment.IngressDeclaration{Node: "node-a", Listeners: []deployment.ListenerDeclaration{{Shared: "external-http"}}, Routes: []deployment.IngressRouteDeclaration{{Host: host, Prefix: "/", Service: "web", Gateway: "external"}}}
	}
	if code := inputCode(f.p.admitTenantIngressHosts(f.s, "tenant", d("api.other.example"), nil)); code != "INGRESS_DOMAIN_OTHER_TENANT" {
		t.Fatal("other tenant's domain", code)
	}
	if err := f.p.admitTenantIngressHosts(f.s, "tenant", d("www.example.com"), nil); err != nil {
		t.Fatal("cluster-level host waits, the deploy goes on", err)
	}
	var many []ingressRouteUse
	for i := range certstore.MaxTenantHostRequests {
		many = append(many, ingressRouteUse{"tenant", "a", "node-a", "external-http", "external", fmt.Sprintf("h%d.example.com", i), "/"})
	}
	if code := inputCode(f.p.admitTenantIngressHosts(f.s, "tenant", d("www.example.com"), many)); code != "INGRESS_HOST_REQUESTS_LIMIT" {
		t.Fatal("waiting hosts over the limit", code)
	}

	// Decisions: only cluster-level hosts of live tenants, approved to one tenant.
	f.apply("manager", "approve-ingress-host", 3, HostDecision{"tenant", "www.example.com"}, state.Forbidden)
	f.apply("admin", "approve-ingress-host", 3, HostDecision{"tenant", "WWW.example.com"}, state.Invalid)
	f.apply("admin", "approve-ingress-host", 3, HostDecision{"tenant", "api.shop.example.com"}, state.ConditionFailed)
	f.apply("admin", "approve-ingress-host", 3, HostDecision{"missing", "www.example.com"}, state.ConditionFailed)
	f.apply("admin", "approve-ingress-host", 3, HostDecision{"tenant", "*.example.com"}, state.ConditionFailed) // covers tenant domains
	f.apply("admin", "approve-ingress-host", 3, HostDecision{"tenant", "www.example.com"}, state.Applied)
	f.apply("admin", "approve-ingress-host", 4, HostDecision{"other", "www.example.com"}, state.ConditionFailed)
	f.apply("admin", "deny-ingress-host", 4, HostDecision{"other", "www.example.com"}, state.Applied)
	c, _ = f.p.Certificates(f.s)
	if st, _ := hostJudgment(c, users, "tenant", "www.example.com"); st != HostOpen {
		t.Fatal("approved host", st)
	}
	if st, _ := hostJudgment(c, users, "other", "www.example.com"); st != HostDenied {
		t.Fatal("denied host", st)
	}
	rows, revision, err := f.p.HostRequests(f.s, "")
	if err != nil || revision != 5 || len(rows) != 2 || rows[0].Tenant != "other" || rows[0].State != HostDenied || rows[1].State != HostOpen || rows[1].DecidedBy != "admin" {
		t.Fatal("requests", rows, revision, err)
	}
	// A domain cannot be given to a tenant over another tenant's decision.
	f.apply("admin", "add-domain", 5, DomainChange{Name: "www.example.com", Tenant: "other"}, state.ConditionFailed)
	f.apply("admin", "revoke-ingress-host", 5, HostDecision{"tenant", "www.example.com"}, state.Applied)
	f.apply("admin", "revoke-ingress-host", 6, HostDecision{"tenant", "www.example.com"}, state.ConditionFailed)
	f.apply("admin", "add-domain", 6, DomainChange{Name: "www.example.com", Tenant: "other"}, state.Applied)
}
