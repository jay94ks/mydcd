// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/tenancy"
)

func approveRouteControl(t *testing.T, f *backupCoreFixture, proposal RouteProposal) (state.Command, state.Result) {
	t.Helper()
	resources, _ := f.p.Resources(f.s)
	managedDNSChange(t, f, "native-route-proposal", "propose-route", resources.Networks.Revision(), proposal, state.Applied)
	resources, _ = f.p.Resources(f.s)
	route, _ := resources.Networks.Route(proposal.Source.Tenant, proposal.ID)
	managedDNSChange(t, f, "native-route-source", "approve-route", route.Revision, RouteSelection{Tenant: proposal.Source.Tenant, SourceTenant: proposal.Source.Tenant, ID: proposal.ID}, state.Applied)
	resources, _ = f.p.Resources(f.s)
	route, _ = resources.Networks.Route(proposal.Source.Tenant, proposal.ID)
	return managedDNSChange(t, f, "native-route-destination", "approve-route", route.Revision, RouteSelection{Tenant: proposal.Destination.Tenant, SourceTenant: proposal.Source.Tenant, ID: proposal.ID}, state.Applied)
}

func TestRouteTransportAdmissionRequiresCurrentBilateralOwners(t *testing.T) {
	f, proposal := routeControlFixture(t)
	resources, _ := f.p.Resources(f.s)
	managedDNSChange(t, f, "transport-propose", "propose-route", resources.Networks.Revision(), proposal, state.Applied)
	resources, _ = f.p.Resources(f.s)
	route, _ := resources.Networks.Route(proposal.Source.Tenant, proposal.ID)
	local, remote := route.Source.Owner, route.Destination.Owner
	allowed := func(s state.State) bool {
		return f.p.RouteTransportAllowed(s, local, remote) || f.p.RouteTransportAllowed(s, remote, local)
	}
	if allowed(f.s) {
		t.Fatal("proposal granted route transport before both approvals")
	}
	managedDNSChange(t, f, "transport-source", "approve-route", route.Revision, RouteSelection{Tenant: proposal.Source.Tenant, SourceTenant: proposal.Source.Tenant, ID: proposal.ID}, state.Applied)
	if allowed(f.s) {
		t.Fatal("one approval granted route transport")
	}
	resources, _ = f.p.Resources(f.s)
	route, _ = resources.Networks.Route(proposal.Source.Tenant, proposal.ID)
	managedDNSChange(t, f, "transport-destination", "approve-route", route.Revision, RouteSelection{Tenant: proposal.Destination.Tenant, SourceTenant: proposal.Source.Tenant, ID: proposal.ID}, state.Applied)
	if !f.p.RouteTransportAllowed(f.s, local, remote) || !f.p.RouteTransportAllowed(f.s, remote, local) {
		t.Fatal("approved distinct-network owners cannot establish the route path")
	}
	for _, pair := range [][2][32]byte{{local, local}, {local, {}}, {{99}, remote}} {
		if f.p.RouteTransportAllowed(f.s, pair[0], pair[1]) {
			t.Fatal("route transport admitted an unrelated or same owner")
		}
	}
	raw, _ := state.Encode(f.s)
	restored, err := state.Decode(raw)
	if err != nil || !f.p.RouteTransportAllowed(restored, local, remote) {
		t.Fatal("same committed snapshot changed route transport permission", err)
	}
	resources, _ = f.p.Resources(f.s)
	route, _ = resources.Networks.Route(proposal.Source.Tenant, proposal.ID)
	managedDNSChange(t, f, "transport-withdraw", "withdraw-route", route.Revision, RouteSelection{Tenant: proposal.Destination.Tenant, SourceTenant: proposal.Source.Tenant, ID: proposal.ID}, state.Applied)
	if allowed(f.s) {
		t.Fatal("withdrawn route kept transport permission")
	}
	projection, err := f.p.ProjectResources(f.s)
	if err != nil || len(projection.NetworkAuthority.RouteReferences()) != 2 {
		t.Fatal("transport denial erased original cleanup references", err)
	}
}

func TestRouteApprovalAtomicallyReservesBothOwnersAndFrozenPreparationWork(t *testing.T) {
	f, proposal := routeControlFixture(t)
	sources := f.s.Objects(tenancy.ManagedNetworkSourcePrefix)
	command, receipt := approveRouteControl(t, f, proposal)
	projection, err := f.p.ProjectResources(f.s)
	if err != nil || projection.NetworkAuthority == nil || len(projection.RouteConsumers) != 4 {
		t.Fatal("paired route demands did not join original Authority", err)
	}
	authority := *projection.NetworkAuthority
	references := authority.RouteReferences()
	if len(references) != 2 {
		t.Fatal("final approval did not reserve exactly two original lifetimes")
	}
	for _, ref := range references {
		if ref.Native == nil || !authority.CurrentRouteReference(ref.ID) || ref.Closed != nil {
			t.Fatal("missing live native dependency")
		}
		object := f.s.Object(ref.Native.Key)
		if !object.Present || object.Generation != ref.Native.Generation || object.Revision != ref.Native.Revision {
			t.Fatal("Bridge ordinals were replaced with logical/ref counters")
		}
		work, err := f.p.RouteWork(f.s, ref.Local.Owner, RouteWorkRequest{Reference: ref.ID, At: 10})
		if err != nil || !work.PrepareAllowed || work.Reference.ID != ref.ID || work.Peer.ID == ref.ID || work.Peer.Route == nil || work.Peer.Route.Side == ref.Route.Side || work.Tunnel.RoutePolicy == nil || work.Tunnel.RoutePolicy.LocalSource != (ref.Local.Tenant == proposal.Source.Tenant) || work.Tunnel.MTU != min(ref.Route.Source.MTU, ref.Route.Destination.MTU) {
			t.Fatal("owner preparation lost original binding/pair/native policy", err)
		}
		if _, err := f.p.RouteWork(f.s, work.Peer.Local.Owner, RouteWorkRequest{Reference: ref.ID, At: 10}); err == nil {
			t.Fatal("other owner queried a foreign original local instance")
		}
		catalog, _ := f.p.Catalog(f.s)
		core, err := services.NewRouteRuntime(catalog, projection.Resources.Networks, authority, ref.ID, [32]byte{77}, 2)
		if err != nil {
			t.Fatal("real route core cannot consume prepared native dependency", err)
		}
		raw, err := core.Encode()
		if err != nil {
			t.Fatal(err)
		}
		restored, err := services.DecodeRouteRuntime(raw)
		if err != nil || restored.Consumer().Native == nil || *restored.Consumer().Native != *ref.Native {
			t.Fatal("route core snapshot lost original Bridge dependency", err)
		}
		copy := restored.Consumer()
		copy.Native.Spec[0]++
		after, _ := restored.Encode()
		if !bytes.Equal(raw, after) {
			t.Fatal("returned consumer aliased immutable native dependency")
		}
		binding := *ref.Native
		binding.Revision++
		if _, _, err := authority.GrantRouteInstance(catalog, projection.Resources.Networks, "admin", proposal.Source.Tenant, proposal.ID, ref.Route.Side, ref.Generation, binding); err == nil {
			t.Fatal("same reference lifetime adopted a different native Bridge revision")
		}
	}
	for key, original := range sources {
		if f.s.Object(key) != original {
			t.Fatal("paired reservation changed managed Bridge/TUN source", key)
		}
	}
	resources, _ := f.p.Resources(f.s)
	route, _ := resources.Networks.Route(proposal.Source.Tenant, proposal.ID)
	managedDNSChange(t, f, "native-route-withdraw", "withdraw-route", route.Revision, RouteSelection{Tenant: proposal.Destination.Tenant, SourceTenant: proposal.Source.Tenant, ID: proposal.ID}, state.Applied)
	for _, ref := range references {
		work, err := f.p.RouteWork(f.s, ref.Local.Owner, RouteWorkRequest{Reference: ref.ID, At: 10})
		if err != nil || work.PrepareAllowed || work.Reference.Native == nil || *work.Reference.Native != *ref.Native || work.Reference.Closed != nil {
			t.Fatal("withdraw erased original cleanup work or invented closure", err)
		}
	}
	raw, err := state.Encode(f.s)
	restored, decodeErr := state.Decode(raw)
	if err != nil || decodeErr != nil {
		t.Fatal(err, decodeErr)
	}
	next, replay, err := state.ApplyTransactional(restored, restored.Index()+1, command, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
	if err != nil || replay != receipt {
		t.Fatal("paired grant lost original receipt", err)
	}
	projection, err = f.p.ProjectResources(next)
	if err != nil || len(projection.RouteConsumers) != 4 || len(projection.NetworkAuthority.RouteReferences()) != 2 {
		t.Fatal("replay duplicated or released original instance pins", err)
	}
}

func TestRouteFinalApprovalQuotaFailureCannotPublishOneOwnerOrApproval(t *testing.T) {
	f, proposal := routeControlFixture(t)
	resources, _ := f.p.Resources(f.s)
	managedDNSChange(t, f, "quota-route-propose", "propose-route", resources.Networks.Revision(), proposal, state.Applied)
	resources, _ = f.p.Resources(f.s)
	route, _ := resources.Networks.Route(proposal.Source.Tenant, proposal.ID)
	managedDNSChange(t, f, "quota-route-source", "approve-route", route.Revision, RouteSelection{Tenant: proposal.Source.Tenant, SourceTenant: proposal.Source.Tenant, ID: proposal.ID}, state.Applied)
	resources, _ = f.p.Resources(f.s)
	limit, _ := resources.Quotas.Limit(proposal.Destination.Tenant, proposal.Destination.Node)
	expected := limit.Revision
	limit.Revision, limit.MaxConsumers = 0, 1
	f.apply("quota-route-limit", "set-node-quota", expected, limit, state.Applied)
	beforeResources, beforeApps := f.s.Object(ResourcesKey), f.s.Object(AppsKey)
	resources, _ = f.p.Resources(f.s)
	route, _ = resources.Networks.Route(proposal.Source.Tenant, proposal.ID)
	managedDNSChange(t, f, "quota-route-destination", "approve-route", route.Revision, RouteSelection{Tenant: proposal.Destination.Tenant, SourceTenant: proposal.Source.Tenant, ID: proposal.ID}, state.ConditionFailed)
	if f.s.Object(ResourcesKey) != beforeResources || f.s.Object(AppsKey) != beforeApps {
		t.Fatal("quota failure partly committed approval/Authority")
	}
	projection, err := f.p.ProjectResources(f.s)
	if err != nil || len(projection.RouteConsumers) != 0 || projection.NetworkAuthority != nil && len(projection.NetworkAuthority.RouteReferences()) != 0 {
		t.Fatal("quota failure retained a one-sided shared grant", err)
	}
}

func TestRoutePreparationRevocationRetainsOriginalConsumerBudgetAndCleanup(t *testing.T) {
	f, proposal := routeControlFixture(t)
	approveRouteControl(t, f, proposal)
	projection, _ := f.p.ProjectResources(f.s)
	references := projection.NetworkAuthority.RouteReferences()
	local, remote := references[0].Local.Owner, references[1].Local.Owner
	if !f.p.RouteTransportAllowed(f.s, local, remote) {
		t.Fatal("active owner pair lacks transport permission before grant revocation")
	}
	catalog, _ := f.p.Catalog(f.s)
	tenant, _ := catalog.Tenant(proposal.Source.Tenant)
	f.apply("route-withdraw-node-grant", "set-nodes", tenant.Revision, NodeChangeTo(proposal.Source.Tenant, tenant.AllowedNodes, []string{"node-b"}), state.Applied)
	if f.p.RouteTransportAllowed(f.s, local, remote) || f.p.RouteTransportAllowed(f.s, remote, local) {
		t.Fatal("node grant revocation retained route transport admission")
	}
	for _, ref := range references {
		work, err := f.p.RouteWork(f.s, ref.Local.Owner, RouteWorkRequest{Reference: ref.ID, At: 10})
		if err != nil || work.PrepareAllowed || work.Reference.ID != ref.ID || work.Reference.Closed != nil || *work.Reference.Native != *ref.Native {
			t.Fatal("revocation discarded original work or widened current native scope", err)
		}
	}
	projection, err := f.p.ProjectResources(f.s)
	if err != nil || len(projection.RouteConsumers) != 4 {
		t.Fatal("revocation returned pins before positive native closure", err)
	}
}

// A preliminary committed read can remain valid as history while its permission
// has been withdrawn. The later request-local quorum must consume the NEW work
// and its matching projection; neither old permission nor mixed roots suffice.
func TestRouteWorkProjectionKeepsOldSnapshotSeparateFromCurrentRevocation(t *testing.T) {
	f, proposal := routeControlFixture(t)
	approveRouteControl(t, f, proposal)
	oldState := f.s
	projection, err := f.p.ProjectResources(oldState)
	if err != nil {
		t.Fatal(err)
	}
	refs := projection.NetworkAuthority.RouteReferences()
	if len(refs) != 2 {
		t.Fatal("missing original owner pair")
	}
	ref := refs[0]
	request := RouteWorkRequest{Reference: ref.ID, At: 10}
	before, work, err := f.p.ProjectRouteWork(oldState, ref.Local.Owner, request)
	if err != nil || !work.PrepareAllowed || before.NetworkAuthority == nil || work.ResourcesRevision != oldState.Object(ResourcesKey).Revision || work.AppsRevision != oldState.Object(AppsKey).Revision {
		t.Fatal("preliminary work is not bound to its own committed projection", err)
	}
	original, found := before.NetworkAuthority.ReferenceConsumer(ref.ID)
	if !found || original.Native == nil || *original.Native != *work.Reference.Native {
		t.Fatal("projection/work mixed original native references")
	}
	catalog, _ := f.p.Catalog(f.s)
	tenant, _ := catalog.Tenant(proposal.Source.Tenant)
	f.apply("readback-revoke-owner", "set-nodes", tenant.Revision, NodeChangeTo(proposal.Source.Tenant, tenant.AllowedNodes, []string{"node-b"}), state.Applied)
	after, current, err := f.p.ProjectRouteWork(f.s, ref.Local.Owner, request)
	if err != nil || current.PrepareAllowed || current.ResourcesRevision != f.s.Object(ResourcesKey).Revision || current.AppsRevision != f.s.Object(AppsKey).Revision || current.Reference.ID != work.Reference.ID || current.Reference.Closed != nil || *current.Reference.Native != *work.Reference.Native {
		t.Fatal("current readback reused old permission or erased its original cleanup pin", err)
	}
	if after.NetworkAuthority == nil || !work.PrepareAllowed || before.Resources.Networks.Revision() != projection.Resources.Networks.Revision() {
		t.Fatal("new readback mutated its preliminary immutable view")
	}
	_, stillOld, err := f.p.ProjectRouteWork(oldState, ref.Local.Owner, request)
	if err != nil || !stillOld.PrepareAllowed {
		t.Fatal("old snapshot no longer demonstrates why a fresh authority check is required", err)
	}
	if _, _, err := f.p.ProjectRouteWork(f.s, [32]byte{99}, request); err == nil {
		t.Fatal("projection reuse bypassed member authentication")
	}
}
