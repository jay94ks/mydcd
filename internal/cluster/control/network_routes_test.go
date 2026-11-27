// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"net/netip"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/workload"
)

// Reuses real product reducers and explicit installation model facts. Policy
// Active below is not native nft readiness, address admission or packet flow.
func routeControlFixture(t *testing.T) (*backupCoreFixture, RouteProposal) {
	f, proposal, _ := routeControlOwnersFixture(t)
	return f, proposal
}

func TestIsolatedRouteOwnerCannotAcquireNewPolicyButCanWithdrawOriginal(t *testing.T) {
	f, proposal := routeControlFixture(t)
	resources, _ := f.p.Resources(f.s)
	f.apply("original-route-before-isolation", "propose-route", resources.Networks.Revision(), proposal, state.Applied)
	resources, _ = f.p.Resources(f.s)
	original, found := resources.Networks.Route(proposal.Source.Tenant, proposal.ID)
	if !found {
		t.Fatal("original route missing")
	}
	isolateVolumeCore(t, f)
	f.apply("deny-approval-after-isolation", "approve-route", original.Revision, RouteSelection{Tenant: proposal.Source.Tenant, SourceTenant: proposal.Source.Tenant, ID: proposal.ID}, state.Forbidden)
	fresh := proposal
	fresh.ID = "fresh-isolated-route"
	f.apply("deny-proposal-after-isolation", "propose-route", resources.Networks.Revision(), fresh, state.ConditionFailed)
	resources, _ = f.p.Resources(f.s)
	unchanged, _ := resources.Networks.Route(proposal.Source.Tenant, proposal.ID)
	if unchanged.Revision != original.Revision || len(unchanged.Approvals) != len(original.Approvals) {
		t.Fatal("denied new policy changed original approvals")
	}
	f.apply("withdraw-original-isolated-route", "withdraw-route", original.Revision, RouteSelection{Tenant: proposal.Source.Tenant, SourceTenant: proposal.Source.Tenant, ID: proposal.ID}, state.Applied)
}

func routeControlOwnersFixture(t *testing.T) (*backupCoreFixture, RouteProposal, map[[32]byte]ed25519.PrivateKey) {
	t.Helper()
	f, second, dns := managedDNSProjectionFixture(t)
	// Reuse the managed networks, not an unrelated live DNS lifetime. Epoch
	// tests must meet storageQuiescent without relaxing the product barrier.
	dns.Policy.Enabled = false
	managedDNSChange(t, f, "route-disable-unstarted-dns", "configure-network-dns", f.s.Object(services.ManagedDNSKey(dns.Tenant, dns.Network)).Revision, dns, state.Applied)
	f.session.Scopes[0].Actions = append(f.session.Scopes[0].Actions, access.ManageRoutes)
	f.session.Signature = ed25519.Sign(f.node, access.SessionBytes(f.session))
	f.apply("route-other-tenant", "create-tenant", 0, TenantID{ID: "other"}, state.Applied)
	catalog, _ := f.p.Catalog(f.s)
	other, _ := catalog.Tenant("other")
	f.apply("route-other-nodes", "set-nodes", other.Revision, NodeChangeTo("other", other.AllowedNodes, []string{"node-b"}), state.Applied)
	f.apply("route-other-quota", "set-node-quota", 0, tenancy.NodeLimit{Tenant: "other", Node: "node-b", Capacity: workload.Resources{CPU: 8, Memory: 80}, Networks: 4, MaxConsumers: 8, PacketQueuePackets: 4, PacketQueueBytes: 8192}, state.Applied)
	r, _ := f.p.Resources(f.s)
	definition := tenancy.TUNDefinition{Tenant: "other", Name: "dest", Members: []tenancy.TUNNode{{Node: "node-b", Pools: []tenancy.Subnet{{ID: "pool", Prefix: netip.MustParsePrefix("10.90.1.0/24"), Gateway: netip.MustParseAddr("10.90.1.1"), MTU: 1280}}}}}
	managedDNSChange(t, f, "route-other-network", "create-tun-network", r.Networks.Revision(), definition, state.Applied)
	return f, RouteProposal{ID: "database", Source: RouteEndpoint{Tenant: "tenant", Network: "services", Node: "node-a", Pool: "pool"}, Destination: RouteEndpoint{Tenant: "other", Network: "dest", Node: "node-b", Pool: "pool"}, Protocol: 6, Ports: []tenancy.Ports{{First: 3306, Last: 3306}}}, map[[32]byte]ed25519.PrivateKey{[32]byte(f.node.Public().(ed25519.PublicKey)): f.node, [32]byte(second.Public().(ed25519.PublicKey)): second}
}

func TestRouteManagementUsesExplicitBilateralApprovalAndRetainsRevokingPolicy(t *testing.T) {
	f, proposal := routeControlFixture(t)
	before := f.s.Objects(tenancy.ManagedNetworkSourcePrefix)
	resources, _ := f.p.Resources(f.s)
	command, receipt := managedDNSChange(t, f, "route-proposal", "propose-route", resources.Networks.Revision(), proposal, state.Applied)
	resources, _ = f.p.Resources(f.s)
	route, found := resources.Networks.Route("tenant", "database")
	if !found || route.Phase != tenancy.Pending || len(route.Approvals) != 0 || route.Source.Tenant != "tenant" || route.Destination.Tenant != "other" || route.Source.Generation == 0 || route.Destination.Generation == 0 {
		t.Fatal("proposal self-approved or failed to bind original managed pools")
	}
	managedDNSChange(t, f, "route-approve-source", "approve-route", route.Revision, RouteSelection{Tenant: "tenant", SourceTenant: "tenant", ID: route.ID}, state.Applied)
	resources, _ = f.p.Resources(f.s)
	route, _ = resources.Networks.Route("tenant", route.ID)
	catalog, _ := f.p.Catalog(f.s)
	if route.Phase != tenancy.Pending || resources.Networks.RouteAuthorized(catalog, "tenant", route.ID) {
		t.Fatal("one tenant approval granted the other side")
	}
	managedDNSChange(t, f, "route-approve-destination", "approve-route", route.Revision, RouteSelection{Tenant: "other", SourceTenant: "tenant", ID: route.ID}, state.Applied)
	resources, _ = f.p.Resources(f.s)
	route, _ = resources.Networks.Route("tenant", route.ID)
	if route.Phase != tenancy.Active || !resources.Networks.RouteAuthorized(catalog, "tenant", route.ID) || !resources.Networks.AllowsNewFlow(catalog, "tenant", route.ID, netip.MustParseAddr("10.80.1.10"), netip.MustParseAddr("10.90.1.10"), 6, 3306) || resources.Networks.AllowsNewFlow(catalog, "tenant", route.ID, netip.MustParseAddr("10.90.1.10"), netip.MustParseAddr("10.80.1.10"), 6, 3306) || resources.Networks.AllowsNewFlow(catalog, "tenant", route.ID, netip.MustParseAddr("10.80.1.10"), netip.MustParseAddr("10.90.1.10"), 6, 3307) {
		t.Fatal("bilateral policy lost direction/port restrictions")
	}
	for _, tenant := range []string{"tenant", "other"} {
		found := false
		after := ""
		for {
			page, next, err := resources.Page(catalog, "admin", tenant, after)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range page {
				if entry.Route != nil && entry.Route.ID == route.ID {
					found = true
					entry.Route.Ports[0].Last++ // owned page, not the shared policy
					// a tenant sees the peer network by name, never its prefix
					own, peer := entry.Route.Source, entry.Route.Destination
					if tenant == "other" {
						own, peer = peer, own
					}
					names := resources.Networks.LogicalName(route.Source.Tenant, route.Source.Network) + ">" + resources.Networks.LogicalName(route.Destination.Tenant, route.Destination.Network)
					if !own.Prefix.IsValid() || peer.Prefix.IsValid() || entry.RouteNames == nil || entry.RouteNames.Source+">"+entry.RouteNames.Destination != names || entry.RouteNames.Source == "" || entry.RouteNames.Destination == "" {
						t.Fatal("route row prefixes or names", tenant, entry.Route, entry.RouteNames)
					}
				}
			}
			if next == "" {
				break
			}
			after = next
		}
		if !found {
			t.Fatal("related tenant could not query original route", tenant)
		}
	}
	f.apply("route-unrelated-tenant", "create-tenant", 0, TenantID{ID: "third"}, state.Applied)
	catalog, _ = f.p.Catalog(f.s)
	page, _, err := resources.Page(catalog, "admin", "third", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range page {
		if entry.Route != nil {
			t.Fatal("tenant filter exposed an unrelated route")
		}
	}
	managedDNSChange(t, f, "route-withdraw-destination", "withdraw-route", route.Revision, RouteSelection{Tenant: "other", SourceTenant: "tenant", ID: route.ID}, state.Applied)
	resources, _ = f.p.Resources(f.s)
	route, found = resources.Networks.Route("tenant", route.ID)
	if !found || route.Phase != tenancy.Revoking || len(route.Approvals) != 2 || route.Ports[0].Last != 3306 || resources.Networks.RouteAuthorized(catalog, "tenant", route.ID) {
		t.Fatal("withdraw erased original policy or allowed new flow")
	}
	managedDNSChange(t, f, "route-reapprove-withdrawn", "approve-route", route.Revision, RouteSelection{Tenant: "other", SourceTenant: "tenant", ID: route.ID}, state.ConditionFailed)
	for key, source := range before {
		if f.s.Object(key) != source {
			t.Fatal("route metadata rewrote borrowed native source", key)
		}
	}
	raw, err := state.Encode(f.s)
	restored, decodeErr := state.Decode(raw)
	if err != nil || decodeErr != nil {
		t.Fatal("bilateral policy snapshot", err, decodeErr)
	}
	next, replay, err := state.ApplyTransactional(restored, restored.Index()+1, command, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
	if err != nil || replay != receipt {
		t.Fatal("old proposal receipt replaced original intent", err)
	}
	resources, err = f.p.Resources(next)
	route, found = resources.Networks.Route("tenant", route.ID)
	if err != nil || !found || route.Phase != tenancy.Revoking {
		t.Fatal("replayed proposal reopened withdrawn policy", err)
	}
}

func TestRouteManagementRejectsForeignSessionStaleCASAndUnknownManagedPool(t *testing.T) {
	f, proposal := routeControlFixture(t)
	resources, _ := f.p.Resources(f.s)
	bad := proposal
	bad.Destination.Pool = "missing"
	managedDNSChange(t, f, "route-missing-pool", "propose-route", resources.Networks.Revision(), bad, state.ConditionFailed)
	managedDNSChange(t, f, "route-stale-proposal", "propose-route", resources.Networks.Revision()+1, proposal, state.ConditionFailed)
	managedDNSChange(t, f, "route-current-proposal", "propose-route", resources.Networks.Revision(), proposal, state.Applied)
	resources, _ = f.p.Resources(f.s)
	route, _ := resources.Networks.Route("tenant", proposal.ID)
	// A metadata reservation closes fresh approval without erasing the policy
	// or changing its original Binding. Cancellation restores that same CAS.
	member, _ := resources.Networks.NamedNetwork("tenant", "services", "node-a")
	target := member
	target.Generation, target.Revision, target.PendingChange = 0, 0, 0
	managedDNSChange(t, f, "route-reserve-source-change", "plan-network-change", member.Revision, NetworkChangePlan{Tenant: "tenant", ID: member.ID, Change: "route-source-change", Target: target}, state.Applied)
	managedDNSChange(t, f, "route-approval-during-source-change", "approve-route", route.Revision, RouteSelection{Tenant: "tenant", SourceTenant: "tenant", ID: proposal.ID}, state.ConditionFailed)
	resources, _ = f.p.Resources(f.s)
	candidate, _ := resources.Networks.Change("tenant", member.ID)
	managedDNSChange(t, f, "route-cancel-source-change", "cancel-network-change", candidate.Revision, NetworkChangeCancel{Tenant: "tenant", ID: member.ID, Generation: candidate.Generation}, state.Applied)
	f.session.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.ManageRoutes}}}
	f.session.Signature = ed25519.Sign(f.node, access.SessionBytes(f.session))
	managedDNSChange(t, f, "route-forged-destination-approval", "approve-route", route.Revision, RouteSelection{Tenant: "other", SourceTenant: "tenant", ID: proposal.ID}, state.Forbidden)
	managedDNSChange(t, f, "route-unrelated-side", "approve-route", route.Revision, RouteSelection{Tenant: "third", SourceTenant: "tenant", ID: proposal.ID}, state.Forbidden)
	managedDNSChange(t, f, "route-stale-approval", "approve-route", route.Revision+1, RouteSelection{Tenant: "tenant", SourceTenant: "tenant", ID: proposal.ID}, state.ConditionFailed)
	resources, _ = f.p.Resources(f.s)
	route, _ = resources.Networks.Route("tenant", proposal.ID)
	if route.Phase != tenancy.Pending || len(route.Approvals) != 0 {
		t.Fatal("rejected approval partly granted the route")
	}
}
