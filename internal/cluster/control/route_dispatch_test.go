// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/network/services"
)

func originalRouteDispatch(t *testing.T, f *backupCoreFixture) (services.ReferenceConsumer, [32]byte, RouteDispatchReport) {
	t.Helper()
	projection, err := f.p.ProjectResources(f.s)
	if err != nil || projection.NetworkAuthority == nil {
		t.Fatal(err)
	}
	owner := [32]byte(f.node.Public().(ed25519.PublicKey))
	for _, ref := range projection.NetworkAuthority.RouteReferences() {
		if ref.Local.Owner != owner {
			continue
		}
		spec, err := services.RouteTunnelDefinition(ref)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(spec)
		nonce := [32]byte{97}
		dispatch := services.RouteDispatch{Cluster: f.p.Cluster, Reference: services.ReferenceNeed{Consumer: ref.ID, Generation: ref.Generation, Lifetime: ref.Lifetime, Owner: owner}, Boot: [32]byte{98}, Journal: services.RouteJournalDigest(ref, nonce), Spec: ref.DesiredHash, NativeSpec: sha256.Sum256(raw), Operation: 1}
		dispatch.Signature = ed25519.Sign(f.node, services.RouteDispatchBytes(dispatch))
		report := RouteDispatchReport{Schema: 1, Kind: "route-dispatch", Cluster: f.p.Cluster, Reporter: owner, Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(AppsKey).Revision, Dispatch: dispatch}
		report.Signature = ed25519.Sign(f.node, RouteDispatchReportBytes(report))
		return ref, nonce, report
	}
	t.Fatal("no original local route reference")
	return services.ReferenceConsumer{}, [32]byte{}, RouteDispatchReport{}
}

func applyRouteDispatch(t *testing.T, f *backupCoreFixture, report RouteDispatchReport, want state.Code) (state.Command, state.Result) {
	t.Helper()
	cmd, err := report.Command()
	if err != nil {
		t.Fatal(err)
	}
	next, result, err := state.ApplyTransactional(f.s, f.s.Index()+1, cmd, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
	if err != nil || result.Code != want {
		t.Fatal("route dispatch result", result, want, err)
	}
	f.s = next
	return cmd, result
}

// Explicit installation facts feed the real FSM; no native execution, RPC,
// quorum or physical owner journal is claimed by these model inputs.
func TestRouteOriginalDispatchSnapshotReplayAndNonceBoundNativePermit(t *testing.T) {
	f, proposal := routeControlFixture(t)
	approveRouteControl(t, f, proposal)
	ref, nonce, report := originalRouteDispatch(t, f)
	request := RouteNativeRequest{Reference: ref.ID, Nonce: nonce, Operation: 1, At: 10}
	if _, err := f.p.RouteNativePermit(f.s, ref.Local.Owner, request); err == nil {
		t.Fatal("preparation alone granted native permission")
	}
	command, receipt := applyRouteDispatch(t, f, report, state.Applied)
	before := f.s.Object(AppsKey)
	permit, err := f.p.RouteNativePermit(f.s, ref.Local.Owner, request)
	if err != nil || permit.Journal != report.Dispatch.Journal || permit.NativeSpec != report.Dispatch.NativeSpec || permit.Operation != 1 || permit.Reference != report.Dispatch.Reference {
		t.Fatal("original nonce did not select original dispatch", err)
	}
	for _, mutate := range []func(*RouteNativeRequest){
		func(q *RouteNativeRequest) { q.Nonce = [32]byte{} },
		func(q *RouteNativeRequest) { q.Nonce[0]++ },
		func(q *RouteNativeRequest) { q.Operation++ },
		func(q *RouteNativeRequest) { q.Reference[0]++ },
	} {
		other := request
		mutate(&other)
		if _, err := f.p.RouteNativePermit(f.s, ref.Local.Owner, other); err == nil {
			t.Fatal("changed journal identity granted native permission")
		}
	}
	if _, err := f.p.RouteNativePermit(f.s, [32]byte{67}, request); err == nil {
		t.Fatal("foreign owner borrowed original journal permission")
	}
	raw, err := state.Encode(f.s)
	restored, decodeErr := state.Decode(raw)
	if err != nil || decodeErr != nil {
		t.Fatal(err, decodeErr)
	}
	f.s = restored
	_, replay := applyRouteDispatch(t, f, report, state.Applied)
	if replay != receipt || f.s.Object(AppsKey) != before {
		t.Fatal("same original report did not return its stored result")
	}
	if _, found := f.s.LookupResult(command); !found {
		t.Fatal("original dispatch result missing after snapshot")
	}
	work, err := f.p.RouteWork(f.s, ref.Local.Owner, RouteWorkRequest{Reference: ref.ID})
	if err != nil || work.Reference.Dispatch == nil || work.Reference.Dispatch.Journal != report.Dispatch.Journal {
		t.Fatal("latest work lost original dispatch after ACK loss", err)
	}
	// Returned signatures cannot mutate the shared Authority checkpoint.
	work.Reference.Dispatch.Signature[0]++
	if _, err := f.p.RouteNativePermit(f.s, ref.Local.Owner, request); err != nil {
		t.Fatal("work response aliased shared dispatch signature", err)
	}
	resources, _ := f.p.Resources(f.s)
	route, _ := resources.Networks.Route(proposal.Source.Tenant, proposal.ID)
	managedDNSChange(t, f, "dispatch-withdraw", "withdraw-route", route.Revision, RouteSelection{Tenant: proposal.Source.Tenant, SourceTenant: proposal.Source.Tenant, ID: proposal.ID}, state.Applied)
	if _, err := f.p.RouteNativePermit(f.s, ref.Local.Owner, request); err == nil {
		t.Fatal("withdraw allowed a fresh native Apply")
	}
	work, err = f.p.RouteWork(f.s, ref.Local.Owner, RouteWorkRequest{Reference: ref.ID})
	if err != nil || work.PrepareAllowed || work.Reference.Dispatch == nil || work.Reference.Closed != nil {
		t.Fatal("withdraw invented native closure or erased provenance", err)
	}
}

func TestRouteDispatchImmutableSignedIdentity(t *testing.T) {
	f, proposal := routeControlFixture(t)
	approveRouteControl(t, f, proposal)
	ref, _, report := originalRouteDispatch(t, f)
	before := f.s.Object(AppsKey)
	bad := report
	bad.Dispatch.NativeSpec[0]++
	bad.Dispatch.Signature = ed25519.Sign(f.node, services.RouteDispatchBytes(bad.Dispatch))
	bad.Signature = ed25519.Sign(f.node, RouteDispatchReportBytes(bad))
	applyRouteDispatch(t, f, bad, state.ConditionFailed)
	if f.s.Object(AppsKey) != before {
		t.Fatal("foreign native policy partially published dispatch")
	}
	applyRouteDispatch(t, f, report, state.Applied)
	before = f.s.Object(AppsKey)
	bad = report
	bad.RootRevision = before.Revision
	bad.Dispatch.Journal[0]++
	bad.Dispatch.Signature = ed25519.Sign(f.node, services.RouteDispatchBytes(bad.Dispatch))
	bad.Signature = ed25519.Sign(f.node, RouteDispatchReportBytes(bad))
	applyRouteDispatch(t, f, bad, state.ConditionFailed)
	if f.s.Object(AppsKey) != before {
		t.Fatal("owner replaced the original native dispatch identity")
	}
	projection, _ := f.p.ProjectResources(f.s)
	original, _ := projection.NetworkAuthority.ReferenceConsumer(ref.ID)
	if original.Dispatch == nil || original.Dispatch.Journal != report.Dispatch.Journal {
		t.Fatal("failed replacement discarded original record")
	}
}
