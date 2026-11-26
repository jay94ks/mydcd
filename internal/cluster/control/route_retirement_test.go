// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/network/services"
	"github.com/jay94ks/mydcd/internal/tenancy"
	"github.com/jay94ks/mydcd/internal/workload"
)

// Installation and native closure are explicit signed model inputs. The real
// FSM, Authority and checkpoint codecs are used; no native or quorum runs.
func routeRetirementFixture(t *testing.T) (*backupCoreFixture, RouteProposal, []RouteRetirementReport, map[[32]byte]ed25519.PrivateKey) {
	t.Helper()
	f, proposal, keys := routeControlOwnersFixture(t)
	approveRouteControl(t, f, proposal)
	projection, err := f.p.ProjectResources(f.s)
	if err != nil {
		t.Fatal(err)
	}
	for i, ref := range projection.NetworkAuthority.RouteReferences() {
		spec, err := services.RouteTunnelDefinition(ref)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(spec)
		dispatch := services.RouteDispatch{Cluster: f.p.Cluster, Reference: services.ReferenceNeed{Consumer: ref.ID, Generation: ref.Generation, Lifetime: ref.Lifetime, Owner: ref.Local.Owner}, Boot: [32]byte{byte(111 + i)}, Journal: services.RouteJournalDigest(ref, [32]byte{byte(121 + i)}), Spec: ref.DesiredHash, NativeSpec: sha256.Sum256(raw), Operation: 1}
		dispatch.Signature = ed25519.Sign(keys[ref.Local.Owner], services.RouteDispatchBytes(dispatch))
		report := RouteDispatchReport{Schema: 1, Kind: "route-dispatch", Cluster: f.p.Cluster, Reporter: ref.Local.Owner, Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(AppsKey).Revision, Dispatch: dispatch}
		report.Signature = ed25519.Sign(keys[ref.Local.Owner], RouteDispatchReportBytes(report))
		applyRouteDispatch(t, f, report, state.Applied)
	}
	resources, _ := f.p.Resources(f.s)
	route, _ := resources.Networks.Route(proposal.Source.Tenant, proposal.ID)
	managedDNSChange(t, f, "retirement-withdraw", "withdraw-route", route.Revision, RouteSelection{Tenant: proposal.Source.Tenant, SourceTenant: proposal.Source.Tenant, ID: proposal.ID}, state.Applied)
	projection, err = f.p.ProjectResources(f.s)
	if err != nil {
		t.Fatal(err)
	}
	route, _ = projection.Resources.Networks.Route(proposal.Source.Tenant, proposal.ID)
	var reports []RouteRetirementReport
	for i, ref := range projection.NetworkAuthority.RouteReferences() {
		closed := services.ReferenceClose{Cluster: f.p.Cluster, Consumer: ref.ID, Generation: ref.Generation, Lifetime: ref.Lifetime, Owner: ref.Local.Owner, Boot: ref.Dispatch.Boot, At: int64(200 + i), Native: ref.RouteNativeKey(), Fenced: true, Settled: true, TTLExpired: true}
		closed.Signature = ed25519.Sign(keys[ref.Local.Owner], services.ReferenceCloseBytes(closed))
		policy := tenancy.RouteClosure{Cluster: f.p.Cluster, SourceTenant: route.Source.Tenant, Route: route.ID, Tenant: ref.Route.Side, Node: ref.Local.Node, Owner: ref.Local.Owner, Generation: route.Generation, Revision: route.Revision, NativeGone: true}
		policy.Signature = ed25519.Sign(keys[ref.Local.Owner], tenancy.RouteClosureBytes(policy))
		report := RouteRetirementReport{Schema: 1, Kind: "route-retirement", Cluster: f.p.Cluster, Reporter: ref.Local.Owner, Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(AppsKey).Revision, ResourcesRevision: f.s.Object(ResourcesKey).Revision, Dispatch: *ref.Dispatch, Close: closed, Route: policy}
		report.Signature = ed25519.Sign(keys[ref.Local.Owner], RouteRetirementReportBytes(report))
		reports = append(reports, report)
	}
	return f, proposal, reports, keys
}

func applyRouteRetirement(t *testing.T, f *backupCoreFixture, report RouteRetirementReport, want state.Code) (state.Command, state.Result) {
	t.Helper()
	command, err := report.Command()
	if err != nil {
		t.Fatal(err)
	}
	next, result, err := state.ApplyTransactional(f.s, f.s.Index()+1, command, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
	if err != nil || result.Code != want {
		t.Fatal("route retirement result", result, want, err)
	}
	f.s = next
	return command, result
}

func TestRouteRetirementPreservesAppProjectionWithoutPersistingItsQuota(t *testing.T) {
	f, _, reports, keys := routeRetirementFixture(t)
	f.session.Scopes[0].Actions = append(f.session.Scopes[0].Actions, access.Deploy)
	f.session.Signature = ed25519.Sign(f.node, access.SessionBytes(f.session))
	for _, scope := range []string{"", "tenant"} {
		resources, _ := f.p.Resources(f.s)
		limit, _ := resources.Quotas.Limit(scope, "node-a")
		expected := limit.Revision
		limit.Revision = 0
		limit.Capacity = workload.Resources{CPU: 4e9, Memory: 256 << 20}
		f.apply("retirement-live-app-quota-"+scope, "set-node-quota", expected, limit, state.Applied)
	}
	task := managedDNSTaskCoreBegin(t, f, "busy", "10.80.1.12", "busy", func(input *deployment.Compose, _ *deployment.PlanningContext) {
		service := input.Services["web"]
		service.DNS = nil // This fixture's managed DNS is explicitly disabled.
		attachment := service.Networks["lan"]
		attachment.Aliases = nil
		service.Networks["lan"] = attachment
		input.Services["web"] = service
	})
	managedDNSTaskCoreSubmit(t, f, "busy", deployment.ResourceKey("network-ref", "tenant", "busy", "lan/node-a"), true, state.Applied)
	managedDNSTaskCoreSubmit(t, f, "busy", task, false, state.Applied)
	originalTask := f.s.Object(task)
	base, err := f.p.Resources(f.s)
	if err != nil {
		t.Fatal(err)
	}
	originalQuota, _ := base.Quotas.Encode()
	projection, err := f.p.ProjectResources(f.s)
	if err != nil || projection.Resources.Quotas.Revision() <= base.Revision+1 {
		t.Fatal("fixture did not expose a newer app-owned reservation", err)
	}
	used, _ := projection.Resources.Quotas.Usage("", "node-a")
	for _, report := range reports {
		report.RootRevision = f.s.Object(AppsKey).Revision
		report.ResourcesRevision = f.s.Object(ResourcesKey).Revision
		report.Signature = ed25519.Sign(keys[report.Reporter], RouteRetirementReportBytes(report))
		applyRouteRetirement(t, f, report, state.Applied)
		current, err := f.p.Resources(f.s)
		if err != nil {
			t.Fatal("authoritative resource decode", err)
		}
		quota, _ := current.Quotas.Encode()
		projection, err = f.p.ProjectResources(f.s)
		usage, _ := projection.Resources.Quotas.Usage("", "node-a")
		if err != nil || !bytes.Equal(quota, originalQuota) || usage != used || f.s.Object(task) != originalTask {
			t.Fatal("retirement copied app reservations or changed the original Task", err)
		}
	}
	raw, _ := state.Encode(f.s)
	restored, err := state.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.p.ProjectResources(restored); err != nil {
		t.Fatal("snapshot projection", err)
	}
}

func TestRouteRetirementAtomicallyClosesOneSideThenBothAndPreservesOriginalReplay(t *testing.T) {
	f, proposal, reports, keys := routeRetirementFixture(t)
	if len(reports) != 2 {
		t.Fatal("fixture did not prepare both original owners")
	}
	sources := f.s.Objects(tenancy.ManagedNetworkSourcePrefix)
	command, receipt := applyRouteRetirement(t, f, reports[0], state.Applied)
	if f.s.Object(AppsKey).Revision != receipt.Index || f.s.Object(ResourcesKey).Revision != receipt.Index {
		t.Fatal("Authority and policy were not published in the same FSM patch")
	}
	projection, err := f.p.ProjectResources(f.s)
	if err != nil || len(projection.RouteConsumers) != 2 {
		t.Fatal("one side returned the peer's consumer reservation", err)
	}
	route, exists := projection.Resources.Networks.Route(proposal.Source.Tenant, proposal.ID)
	if !exists || route.Phase != tenancy.Revoking || len(route.Closures) != 1 {
		t.Fatal("one owner deleted bilateral policy")
	}
	closed, _ := projection.NetworkAuthority.ReferenceConsumer(reports[0].Close.Consumer)
	peer, _ := projection.NetworkAuthority.ReferenceConsumer(reports[1].Close.Consumer)
	if closed.Closed == nil || closed.RouteClosed == nil || peer.Closed != nil || peer.RouteClosed != nil {
		t.Fatal("instance/policy closure was split or the peer was closed")
	}
	beforeApps, beforeResources := f.s.Object(AppsKey), f.s.Object(ResourcesKey)
	applyRouteRetirement(t, f, reports[1], state.ConditionFailed)
	if f.s.Object(AppsKey) != beforeApps || f.s.Object(ResourcesKey) != beforeResources {
		t.Fatal("stale-root loser partly published closure")
	}
	second := reports[1]
	second.RootRevision, second.ResourcesRevision = beforeApps.Revision, beforeResources.Revision
	second.Signature = ed25519.Sign(keys[second.Reporter], RouteRetirementReportBytes(second))
	applyRouteRetirement(t, f, second, state.Applied)
	projection, err = f.p.ProjectResources(f.s)
	if err != nil || len(projection.RouteConsumers) != 0 {
		t.Fatal("both closed owners retained route reservations", err)
	}
	if _, exists := projection.Resources.Networks.Route(proposal.Source.Tenant, proposal.ID); exists {
		t.Fatal("both original closures retained the retired policy")
	}
	for _, ref := range projection.NetworkAuthority.RouteReferences() {
		if ref.Closed == nil || ref.RouteClosed == nil || services.ValidateRouteRetirement(ref, *ref.Closed, *ref.RouteClosed) != nil {
			t.Fatal("policy deletion lost original paired closure receipt")
		}
	}
	for key, source := range sources {
		if f.s.Object(key) != source {
			t.Fatal("route closure removed a managed network source", key)
		}
	}
	raw, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	f.s, err = state.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	beforeApps, beforeResources = f.s.Object(AppsKey), f.s.Object(ResourcesKey)
	_, replay := applyRouteRetirement(t, f, reports[0], state.Applied)
	if replay != receipt || f.s.Object(AppsKey) != beforeApps || f.s.Object(ResourcesKey) != beforeResources {
		t.Fatal("deleted policy lost original immutable report result")
	}
	if original, found := f.s.LookupResult(command); !found || original != receipt {
		t.Fatal("original retirement result missing after snapshot")
	}
	// Reuse the name with explicit new approvals. The old consumer receipts
	// must never resolve to those new policy/reference generations.
	resources, _ := f.p.Resources(f.s)
	managedDNSChange(t, f, "reused-route-propose", "propose-route", resources.Networks.Revision(), proposal, state.Applied)
	for _, side := range []string{proposal.Source.Tenant, proposal.Destination.Tenant} {
		resources, _ = f.p.Resources(f.s)
		current, _ := resources.Networks.Route(proposal.Source.Tenant, proposal.ID)
		managedDNSChange(t, f, "reused-route-approve-"+side, "approve-route", current.Revision, RouteSelection{Tenant: side, SourceTenant: proposal.Source.Tenant, ID: proposal.ID}, state.Applied)
	}
	old := reports[0]
	old.RootRevision, old.ResourcesRevision = f.s.Object(AppsKey).Revision, f.s.Object(ResourcesKey).Revision
	old.Signature = ed25519.Sign(keys[old.Reporter], RouteRetirementReportBytes(old))
	beforeResources = f.s.Object(ResourcesKey)
	applyRouteRetirement(t, f, old, state.Applied)
	projection, err = f.p.ProjectResources(f.s)
	current, exists := projection.Resources.Networks.Route(proposal.Source.Tenant, proposal.ID)
	if err != nil || !exists || current.Generation == old.Route.Generation || current.Phase != tenancy.Active || len(projection.RouteConsumers) != 4 || f.s.Object(ResourcesKey) != beforeResources {
		t.Fatal("old receipt closed a new route with the same name", err)
	}
	closed, _ = projection.NetworkAuthority.ReferenceConsumer(old.Close.Consumer)
	authorityBytes, _ := projection.NetworkAuthority.Encode()
	closed.RouteClosed.Signature[0]++
	afterBytes, _ := projection.NetworkAuthority.Encode()
	if !bytes.Equal(authorityBytes, afterBytes) {
		t.Fatal("returned receipt signature aliased the shared checkpoint")
	}
}

func TestRouteRetirementRejectsPartialProofCASAndUnrelatedPatchButAllowsRevokedSessionCleanup(t *testing.T) {
	f, _, reports, keys := routeRetirementFixture(t)
	report := reports[0]
	command, _ := report.Command()
	if !f.p.AdmitAppPatch(f.s, command, []string{ResourcesKey, ResourcesKey + "/part/0"}) || f.p.AdmitAppPatch(f.s, command, []string{ResourcesKey, VaultKey}) || f.p.AdmitAppPatch(f.s, command, []string{tenancy.ManagedNetworkSourcePrefix + "bridge/other/lan/node-b"}) {
		t.Fatal("retirement patch scope escaped Resources checkpoint")
	}
	for _, mutate := range []func(*RouteRetirementReport){
		func(r *RouteRetirementReport) { r.ResourcesRevision++ },
		func(r *RouteRetirementReport) { r.Dispatch.Journal[0]++ },
		func(r *RouteRetirementReport) { r.Close.Lifetime.Token++ },
		func(r *RouteRetirementReport) { r.Close.Native = "route/foreign-original" },
		func(r *RouteRetirementReport) { r.Route.Generation++ },
		func(r *RouteRetirementReport) { r.Route.PendingPins++ },
		func(r *RouteRetirementReport) { r.Route.NativeGone = false },
	} {
		var bad RouteRetirementReport
		raw, _ := json.Marshal(report)
		if err := json.Unmarshal(raw, &bad); err != nil {
			t.Fatal(err)
		}
		mutate(&bad)
		bad.Dispatch.Signature = ed25519.Sign(keys[bad.Reporter], services.RouteDispatchBytes(bad.Dispatch))
		bad.Close.Signature = ed25519.Sign(keys[bad.Reporter], services.ReferenceCloseBytes(bad.Close))
		bad.Route.Signature = ed25519.Sign(keys[bad.Reporter], tenancy.RouteClosureBytes(bad.Route))
		bad.Signature = ed25519.Sign(keys[bad.Reporter], RouteRetirementReportBytes(bad))
		beforeApps, beforeResources := f.s.Object(AppsKey), f.s.Object(ResourcesKey)
		applyRouteRetirement(t, f, bad, state.ConditionFailed)
		if f.s.Object(AppsKey) != beforeApps || f.s.Object(ResourcesKey) != beforeResources {
			t.Fatal("failed proof or CAS published half the closure")
		}
	}
	catalog, _ := f.p.Catalog(f.s)
	user, _ := catalog.User("admin")
	f.apply("retirement-revoke-session", "revoke-session", user.Revision, SessionRevocation{User: "admin", Session: f.session.ID}, state.Applied)
	applyRouteRetirement(t, f, report, state.Applied)
}
