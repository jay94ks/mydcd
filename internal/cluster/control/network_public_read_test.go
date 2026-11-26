// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/tenancy"
	"net/netip"
	"testing"
)

func TestNetworkClosureReadRequiresExactCurrentCleanupRealm(t *testing.T) {
	f, _, _ := managedDNSProjectionFixture(t)
	resources, err := f.p.Resources(f.s)
	if err != nil {
		t.Fatal(err)
	}
	n := resources.Networks.AllNetworks()[0]
	target := n
	target.Generation, target.Revision, target.PendingChange = 0, 0, 0
	target.Owner = [32]byte{}
	f.apply("public-closure-plan", "plan-network-change", n.Revision, NetworkChangePlan{Tenant: n.Tenant, ID: n.ID, Change: "public-closure", Target: target}, state.Applied)
	f.apply("public-closure-drain", "drain-network", n.Revision, NetworkSelection{Tenant: n.Tenant, ID: n.ID}, state.Applied)
	read := func(session access.Session, tenant string) error {
		t.Helper()
		_, err := f.p.PublicRead(f.s, session, 2, "network-closure", tenant, PublicReadQuery{Name: n.ID}, "")
		return err
	}
	manager := f.session
	manager.Scopes = []access.Scope{{Tenant: n.Tenant, Actions: []access.Action{access.ManageNetwork}}}
	manager.Signature = ed25519.Sign(f.node, access.SessionBytes(manager))
	if err := read(manager, n.Tenant); err != nil {
		t.Fatal("same-realm cleanup manager positive control", err)
	}
	if err := read(manager, "foreign"); !errors.Is(err, access.ErrDenied) {
		t.Fatal("foreign tenant closure disclosed", err)
	}
	for _, scope := range []access.Scope{{Tenant: n.Tenant, Actions: []access.Action{access.Read}}, {Tenant: "foreign", Actions: []access.Action{access.ManageNetwork}}} {
		session := manager
		session.Scopes = []access.Scope{scope}
		session.Signature = ed25519.Sign(f.node, access.SessionBytes(session))
		if err := read(session, n.Tenant); !errors.Is(err, access.ErrDenied) {
			t.Fatal("wrong action or foreign cleanup scope read closure", err)
		}
	}
}

func TestNetworkClosureReadNeverAcceptsUnrelatedOwnerLifetimeOrNonterminalCounts(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{72}, 32))
	owner := [32]byte(key.Public().(ed25519.PublicKey))
	target := NetworkReadTarget{Network: tenancy.Network{Tenant: "tenant", ID: "member", Node: "node-a", Owner: owner, Generation: 4, Revision: 9}}
	proof := tenancy.NetworkClosure{Cluster: [32]byte{8}, Tenant: "tenant", Network: "member", Node: "node-a", Owner: owner, Generation: 4, Revision: 9, NativeGone: true}
	sign := func(p *tenancy.NetworkClosure) { p.Signature = ed25519.Sign(key, tenancy.NetworkClosureBytes(*p)) }
	sign(&proof)
	if !target.VerifyClosure(proof.Cluster, proof) {
		t.Fatal("original terminal proof refused")
	}
	for _, mutate := range []func(*tenancy.NetworkClosure){func(p *tenancy.NetworkClosure) { p.Tenant = "foreign" }, func(p *tenancy.NetworkClosure) { p.Generation++ }, func(p *tenancy.NetworkClosure) { p.Revision++ }, func(p *tenancy.NetworkClosure) { p.PendingEndpoints = 1 }, func(p *tenancy.NetworkClosure) { p.PendingPins = 1 }, func(p *tenancy.NetworkClosure) { p.PendingFlows = 1 }, func(p *tenancy.NetworkClosure) { p.NativeGone = false }, func(p *tenancy.NetworkClosure) { p.Node = "node-b" }} {
		bad := proof
		mutate(&bad)
		sign(&bad)
		if target.VerifyClosure(proof.Cluster, bad) {
			t.Fatal("unrelated/nonterminal proof accepted")
		}
	}
}

func TestPublishedRouteEndpointUsesTheLogicalNameAcceptedByPropose(t *testing.T) {
	f, _, definition := managedDNSProjectionFixture(t)
	page, err := f.p.PublicRead(f.s, f.session, 2, "route-endpoints", definition.Tenant, PublicReadQuery{}, "")
	if err != nil || len(page.Rows) != 2 {
		t.Fatal("named member discovery", page, err)
	}
	resources, err := f.p.Resources(f.s)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range page.Rows {
		endpoint := row.RouteEndpoint
		if endpoint == nil || endpoint.Network != definition.Network {
			t.Fatal("internal member ID was published as proposal network", row)
		}
		bound, err := f.p.routeEndpoint(f.s, resources.Networks, RouteEndpoint{Tenant: endpoint.Tenant, Network: endpoint.Network, Node: endpoint.Node, Pool: endpoint.Pool})
		if err != nil || bound.Tenant != definition.Tenant {
			t.Fatal("published endpoint cannot be consumed by original proposal reducer", bound, err)
		}
	}
}
func TestNetworkDNSPolicyProjectionOwnsEveryPolicyFieldAndExactSourceCAS(t *testing.T) {
	f, _, definition := managedDNSProjectionFixture(t)
	resources, err := f.p.Resources(f.s)
	if err != nil {
		t.Fatal(err)
	}
	var member tenancy.Network
	for _, n := range resources.Networks.AllNetworks() {
		if n.Tenant == definition.Tenant && n.Logical == definition.Network {
			member = n
			break
		}
	}
	view, target, err := f.p.NetworkDNSView(f.s, member)
	if err != nil || view == nil || target.Network != definition.Network || view.Revision != f.s.Object(target.Source.Key).Revision || view.Policy.TTL != definition.Policy.TTL || view.Ready != nil || len(view.Resolvers) != 0 {
		t.Fatal("policy/CAS became actual readiness", view, target, err)
	}
	if len(view.Policy.Upstreams) > 0 {
		view.Policy.Upstreams[0] = netip.MustParseAddrPort("192.0.2.20:53")
	}
	again, _, err := f.p.NetworkDNSView(f.s, member)
	if err != nil || len(definition.Policy.Upstreams) > 0 && again.Policy.Upstreams[0] != definition.Policy.Upstreams[0] {
		t.Fatal("returned policy mutated source", err)
	}
}
