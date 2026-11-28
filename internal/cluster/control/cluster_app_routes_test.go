// SPDX-License-Identifier: Apache-2.0

package control

import (
	"slices"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
)

func clusterAppIngress(host string) deployment.IngressDeclaration {
	d := deployment.IngressDeclaration{Node: "node-a", Listeners: []deployment.ListenerDeclaration{{Shared: "internal-https"}}, Routes: []deployment.IngressRouteDeclaration{{ID: "ui", Host: host, Gateway: "local"}}}
	d.Runtime = deployment.IngressRuntime{MaxRequests: 8, MaxConnections: 32, MaxHeaderBytes: 16384, MaxBodyBytes: 1 << 20, BufferBytes: 512 << 10, RequestTimeoutMS: 30000, DialTimeoutMS: 2000, ResponseHeaderTimeoutMS: 5000, HealthIntervalMS: 1000}
	return d
}

// A system administrator puts and removes the web cluster app's routes as a
// cluster setting; a removed record keeps its routes for the drain.
func TestClusterAppRoutesAreAClusterSetting(t *testing.T) {
	f := newBackupCore(t)
	book := func() IngressManagement {
		b, err := f.p.IngressManagement(f.s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	put := ClusterAppRouteChange{App: "web", Ingress: clusterAppIngress("sfc.example.com")}
	managedDNSChange(t, f, "bad-app", "put-cluster-app-route", 0, ClusterAppRouteChange{App: "other", Ingress: put.Ingress}, state.Invalid)
	bad := put
	bad.Ingress.Routes = []deployment.IngressRouteDeclaration{{ID: "ui", Host: "sfc.example.com", Port: 9000}}
	managedDNSChange(t, f, "bad-backend", "put-cluster-app-route", 0, bad, state.Invalid)
	managedDNSChange(t, f, "remove-none", "remove-cluster-app-route", 0, ClusterAppRouteSelection{App: "web"}, state.ConditionFailed)
	// Cluster app hosts sit under a registered cluster-level domain.
	managedDNSChange(t, f, "no-domain", "put-cluster-app-route", 0, put, state.ConditionFailed)
	managedDNSChange(t, f, "domain", "add-domain", 0, DomainChange{Name: "example.com"}, state.Applied)
	managedDNSChange(t, f, "put", "put-cluster-app-route", 0, put, state.Applied)
	if r, found := book().ClusterAppRoute("web"); !found || r.Revision != 1 || r.Ingress.Routes[0].Host != "sfc.example.com" {
		t.Fatalf("put: %+v %v", r, found)
	}
	managedDNSChange(t, f, "stale", "put-cluster-app-route", 0, put, state.ConditionFailed)
	put.Ingress = clusterAppIngress("ui.example.com")
	managedDNSChange(t, f, "change", "put-cluster-app-route", 1, put, state.Applied)
	managedDNSChange(t, f, "remove", "remove-cluster-app-route", 2, ClusterAppRouteSelection{App: "web"}, state.Applied)
	b := book()
	if _, found := b.ClusterAppRoute("web"); found || len(b.ClusterAppRoutes) != 1 || !b.ClusterAppRoutes[0].Removed || b.ClusterAppRoutes[0].Ingress.Routes[0].Host != "ui.example.com" {
		t.Fatalf("removed: %+v", b.ClusterAppRoutes)
	}
	managedDNSChange(t, f, "remove-again", "remove-cluster-app-route", 3, ClusterAppRouteSelection{App: "web"}, state.ConditionFailed)
	// put again after removal continues the revision
	managedDNSChange(t, f, "again", "put-cluster-app-route", 3, put, state.Applied)
	// a workspace app cannot take any path of a cluster app route's host:
	// ingress picks the longest prefix, so /api would take the logins
	if err := f.p.admitClusterAppRouteClaims(f.s, clusterAppIngress("ui.example.com")); err == nil {
		t.Fatal("a workspace app took the web UI's host")
	}
	api := clusterAppIngress("ui.example.com")
	api.Routes[0].Prefix = "/api"
	if err := f.p.admitClusterAppRouteClaims(f.s, api); err == nil {
		t.Fatal("a workspace app took /api under the web UI's /")
	}
	if err := f.p.admitClusterAppRouteClaims(f.s, clusterAppIngress("shop.example.com")); err != nil {
		t.Fatalf("another host: %v", err)
	}
}

func TestIngressClaimsCoverEveryPathOfAHost(t *testing.T) {
	root := clusterAppIngress("ui.example.com")
	api := clusterAppIngress("ui.example.com")
	api.Routes[0].Prefix = "/api"
	if !claimsOverlap(ingressClaims(root), ingressClaims(api)) || !claimsOverlap(ingressClaims(api), ingressClaims(root)) {
		t.Fatal("/ and /api of one host must overlap both ways")
	}
}

func TestIngressClaimsFollowGatewayAndListener(t *testing.T) {
	a := clusterAppIngress("ui.example.com")
	both := clusterAppIngress("ui.example.com")
	both.Routes[0].Gateway = "both"
	external := clusterAppIngress("ui.example.com")
	external.Routes[0].Gateway = "external"
	elsewhere := clusterAppIngress("ui.example.com")
	elsewhere.Node = "node-b"
	listener := clusterAppIngress("ui.example.com")
	listener.Listeners[0].Shared = "public-https"
	for name, c := range map[string]struct {
		d    deployment.IngressDeclaration
		want bool
	}{"both": {both, true}, "external only": {external, false}, "other server": {elsewhere, false}, "other listener": {listener, false}} {
		if got := claimsOverlap(ingressClaims(a), ingressClaims(c.d)); got != c.want {
			t.Errorf("%s: %v", name, got)
		}
	}
}

func TestClusterAppHostPolicyAllowsOnlyTheRouteHosts(t *testing.T) {
	both := clusterAppIngress("ui.example.com")
	both.Routes[0].Gateway = "both"
	local := clusterAppIngress("admin.example.com")
	book := IngressManagement{ClusterAppRoutes: []ClusterAppRouteRecord{
		{App: "web", Revision: 1, Ingress: both},
		{App: "gone", Revision: 2, Removed: true, Ingress: local},
	}}
	p := book.ClusterAppHostPolicy()
	if !p.ExternalAllowed || !slices.Equal(p.ExternalHosts, []string{"ui.example.com"}) || !slices.Equal(p.LocalHosts, []string{"ui.example.com"}) {
		t.Fatalf("policy: %+v", p)
	}
	if p := (IngressManagement{}).ClusterAppHostPolicy(); p.ExternalAllowed || len(p.ExternalHosts)+len(p.LocalHosts) != 0 {
		t.Fatalf("empty: %+v", p)
	}
}
