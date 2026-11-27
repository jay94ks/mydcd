// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/tenancy"
)

// These are committed FSM/core facts. No native grant or adapter exists for
// these lifetimes, and no physical absence is used to fabricate a closure.
func TestRouteCatalogRevocationIsAtomicAndUnpreparedOwnersCloseWithoutNativeGrant(t *testing.T) {
	f, proposal, keys := routeControlOwnersFixture(t)
	approveRouteControl(t, f, proposal)
	before, err := f.p.ProjectResources(f.s)
	if err != nil {
		t.Fatal(err)
	}
	catalog, _ := f.p.Catalog(f.s)
	refs := before.NetworkAuthority.RouteReferences()
	if len(refs) != 2 {
		t.Fatal("missing original route owners")
	}
	for _, ref := range refs {
		if _, err := services.NewUnstartedRouteRetirement(catalog, before.Resources.Networks, *before.NetworkAuthority, ref.ID, [32]byte{40}); err == nil {
			t.Fatal("active policy was treated as never dispatched")
		}
	}
	private, err := services.NewRouteRuntime(catalog, before.Resources.Networks, *before.NetworkAuthority, refs[0].ID, [32]byte{41}, 2)
	if err != nil {
		t.Fatal(err)
	}
	private, _, err = private.Plan()
	if err != nil {
		t.Fatal(err)
	}
	privateBytes, _ := private.Encode()
	tenant, _ := catalog.Tenant(proposal.Source.Tenant)
	sources := f.s.Objects(tenancy.ManagedNetworkSourcePrefix)
	beforeApps := f.s.Object(AppsKey)
	f.apply("route-revoke-node", "set-nodes", tenant.Revision, NodeChangeTo(proposal.Source.Tenant, tenant.AllowedNodes, []string{"node-b"}), state.Applied)
	if f.s.Object(CatalogKey).Revision != f.s.Object(ResourcesKey).Revision || f.s.Object(AppsKey) != beforeApps {
		t.Fatal("catalog and route revocation were split or original Authority was rewritten")
	}
	projection, err := f.p.ProjectResources(f.s)
	if err != nil || len(projection.RouteConsumers) != 4 {
		t.Fatal("revocation returned outstanding reservations", err)
	}
	route, exists := projection.Resources.Networks.Route(proposal.Source.Tenant, proposal.ID)
	if !exists || route.Phase != tenancy.Revoking || route.Generation != refs[0].Route.Policy.Generation || len(route.Approvals) != 2 || len(route.Closures) != 0 {
		t.Fatal("revocation erased accepted policy or invented closure")
	}
	catalog, _ = f.p.Catalog(f.s)
	retired, err := private.RetireNeverDispatched(catalog, projection.Resources.Networks, *projection.NetworkAuthority)
	if err != nil || retired.Journal().Pending != nil || retired.Journal().Desired.Present || retired.Journal().Applied.Present || retired.Journal().LastID != 1 || retired.FlowCount() != 0 {
		t.Fatal("private Prepared intent was replaced instead of retired", err)
	}
	afterPrivate, _ := private.Encode()
	if !bytes.Equal(privateBytes, afterPrivate) {
		t.Fatal("retirement mutated the original private core")
	}
	// Restoring a grant is not a new approval and cannot reopen Revoking.
	tenant, _ = catalog.Tenant(proposal.Source.Tenant)
	f.apply("route-restore-node", "set-nodes", tenant.Revision, NodeChangeTo(proposal.Source.Tenant, tenant.AllowedNodes, []string{"node-a", "node-b"}), state.Applied)
	for i, original := range refs {
		projection, err = f.p.ProjectResources(f.s)
		if err != nil {
			t.Fatal(err)
		}
		catalog, _ = f.p.Catalog(f.s)
		work, err := f.p.RouteWork(f.s, original.Local.Owner, RouteWorkRequest{Reference: original.ID})
		if err != nil || !work.Retiring || work.PrepareAllowed || work.Reference.Dispatch != nil {
			t.Fatal("grant restoration reopened native admission", err)
		}
		core, err := services.NewUnstartedRouteRetirement(catalog, projection.Resources.Networks, *projection.NetworkAuthority, original.ID, [32]byte{byte(50 + i)})
		if err != nil {
			t.Fatal(err)
		}
		closed, err := core.ReferenceFacts(*projection.NetworkAuthority, [32]byte{}, services.Clock{Boot: core.Boot(), Wall: int64(400 + i), Certain: true})
		if err != nil {
			t.Fatal(err)
		}
		policy, err := core.RouteClosureFacts(projection.Resources.Networks)
		if err != nil {
			t.Fatal(err)
		}
		closed.Settled = true
		closed.Signature = ed25519.Sign(keys[original.Local.Owner], services.ReferenceCloseBytes(closed))
		policy.NativeGone = true
		policy.Signature = ed25519.Sign(keys[original.Local.Owner], tenancy.RouteClosureBytes(policy))
		report := RouteRetirementReport{Schema: 1, Kind: "route-retirement", Cluster: f.p.Cluster, Reporter: original.Local.Owner, Epoch: work.Epoch, RootRevision: work.AppsRevision, ResourcesRevision: work.ResourcesRevision, Close: closed, Route: policy, NeverDispatched: true}
		report.Signature = ed25519.Sign(keys[report.Reporter], RouteRetirementReportBytes(report))
		applyRouteRetirement(t, f, report, state.Applied)
	}
	projection, err = f.p.ProjectResources(f.s)
	if err != nil || len(projection.RouteConsumers) != 0 {
		t.Fatal("unprepared lifetimes leaked reservations", err)
	}
	if _, exists := projection.Resources.Networks.Route(proposal.Source.Tenant, proposal.ID); exists {
		t.Fatal("both never-started closures retained policy")
	}
	for key, source := range sources {
		if f.s.Object(key) != source {
			t.Fatal("account change or unstarted retirement changed a native source", key)
		}
	}
	for _, ref := range projection.NetworkAuthority.RouteReferences() {
		if ref.Dispatch != nil || ref.Closed == nil || ref.RouteClosed == nil {
			t.Fatal("unprepared closure invented a grant or lost paired receipt")
		}
	}
}

func TestRouteSessionLogoutDoesNotRevokeAcceptedPersistentPolicy(t *testing.T) {
	f, proposal := routeControlFixture(t)
	approveRouteControl(t, f, proposal)
	catalog, _ := f.p.Catalog(f.s)
	user, _ := catalog.User("admin")
	before := f.s.Object(ResourcesKey)
	f.apply("route-session-only-logout", "revoke-session", user.Revision, SessionRevocation{User: "admin", Session: f.session.ID}, state.Applied)
	resources, err := f.p.Resources(f.s)
	route, exists := resources.Networks.Route(proposal.Source.Tenant, proposal.ID)
	if err != nil || !exists || route.Phase != tenancy.Active || f.s.Object(ResourcesKey) != before {
		t.Fatal("session expiry/logout was confused with persistent grant revocation", err)
	}
}

func TestRouteNeverDispatchedClaimCannotEraseAnOriginalNativeGrant(t *testing.T) {
	f, _, reports, keys := routeRetirementFixture(t)
	report := reports[0]
	report.NeverDispatched, report.Dispatch = true, services.RouteDispatch{}
	report.Signature = ed25519.Sign(keys[report.Reporter], RouteRetirementReportBytes(report))
	beforeApps, beforeResources := f.s.Object(AppsKey), f.s.Object(ResourcesKey)
	applyRouteRetirement(t, f, report, state.ConditionFailed)
	if f.s.Object(AppsKey) != beforeApps || f.s.Object(ResourcesKey) != beforeResources {
		t.Fatal("never-dispatched claim partly erased an actual original grant")
	}
	projection, _ := f.p.ProjectResources(f.s)
	catalog, _ := f.p.Catalog(f.s)
	if _, err := services.NewUnstartedRouteRetirement(catalog, projection.Resources.Networks, *projection.NetworkAuthority, report.Close.Consumer, [32]byte{70}); err == nil {
		t.Fatal("missing local journal with a grant got a replacement core")
	}
	// Signed metadata cannot widen the related checkpoint patch into native
	// or unrelated roots; the real reducer alone derives the consequence.
	// The patch admission runs the real reducer, so the change must carry the
	// tenant's current revision.
	tenant, _ := catalog.Tenant("tenant")
	change, _ := ChangeBytes("set-nodes", "admin", tenant.Revision, NodeChangeTo("tenant", tenant.AllowedNodes, []string{"node-b"}))
	var parsed Change
	_ = json.Unmarshal(change, &parsed)
	operation := UserOperation{Schema: 1, Session: f.session, At: 2, Epoch: f.s.ModuleEpoch(), RequestID: "patch-scope-only", RootRevision: f.s.Object(CatalogKey).Revision, Change: parsed}
	operation.Signature = ed25519.Sign(f.admin, OperationBytes(operation))
	command, _ := operation.Command()
	if !f.p.AdmitAppPatch(f.s, command, []string{ResourcesKey}) || f.p.AdmitAppPatch(f.s, command, []string{ResourcesKey, VaultKey}) || f.p.AdmitAppPatch(f.s, command, []string{tenancy.ManagedNetworkSourcePrefix + "bridge/tenant/services/node-a"}) {
		t.Fatal("catalog revocation patch escaped derived Resources")
	}
}
