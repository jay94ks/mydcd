// SPDX-License-Identifier: Apache-2.0

package control

import (
	"testing"

	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/ingress"
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

func TestForeignIngressHostsAreRefusedUnlessGranted(t *testing.T) {
	d := func(host string) deployment.IngressDeclaration {
		return deployment.IngressDeclaration{Node: "node-a", Listeners: []deployment.ListenerDeclaration{{Shared: "external-http"}}, Routes: []deployment.IngressRouteDeclaration{{Host: host, Prefix: "/", Service: "web", Gateway: "external"}}}
	}
	others := []ingressRouteUse{{"other", "shop", "node-b", "external-http", "external", "shop.example", "/"}}
	for _, host := range []string{"shop.example", "api.shop.example", "*.shop.example"} {
		if code := inputCode(foreignIngressHosts("team", d(host), others, ingress.HostPolicy{}, false)); code != "INGRESS_HOST_OTHER_TENANT" {
			t.Fatal(host, "of another tenant was not refused", code)
		}
	}
	for _, host := range []string{"example", "myshop.example", "blog.example"} {
		if err := foreignIngressHosts("team", d(host), others, ingress.HostPolicy{}, false); err != nil {
			t.Fatal(host, "is not under the other tenant's host", err)
		}
	}
	if err := foreignIngressHosts("other", d("api.shop.example"), others, ingress.HostPolicy{}, false); err != nil {
		t.Fatal("own tenant's host refused", err)
	}
	grant := ingress.HostPolicy{ExternalAllowed: true, ExternalHosts: []string{"api.shop.example"}}
	if err := foreignIngressHosts("team", d("api.shop.example"), others, grant, true); err != nil {
		t.Fatal("a host a system admin granted was refused", err)
	}
}
