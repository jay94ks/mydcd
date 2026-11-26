// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/network/services"
	"github.com/jay94ks/mydcd/internal/tenancy"
)

// Core and DB are real. The never-started native/dependency closure is an
// explicit model fact, not a substitute for actual Manager/native validation.
func retiredRouteOwnerFixture(t *testing.T, owner *Runtime) (services.ReferenceConsumer, routeOwnerRecord, control.ResourceProjection, control.RouteWork) {
	t.Helper()
	ref, record, catalog, networks, authority := routeOwnerCoreFixture(t)
	authority, err := authority.RecordRouteDispatch(record.Dispatch)
	if err != nil {
		t.Fatal(err)
	}
	ref, _ = authority.ReferenceConsumer(ref.ID)
	policy, _ := networks.Route("first", "database")
	networks, err = networks.Withdraw(catalog, "admin", "first", "database", "first", policy.Revision)
	if err != nil {
		t.Fatal(err)
	}
	core, err := services.DecodeRouteRuntime(record.Core)
	if err != nil {
		t.Fatal(err)
	}
	core, err = core.Sync(catalog, networks, authority)
	if err != nil {
		t.Fatal(err)
	}
	record.Core, err = core.Encode()
	if err != nil {
		t.Fatal(err)
	}
	record.Report, record.BridgeReturned = nil, true
	if err := owner.saveRouteOwner(record, ref); err != nil {
		t.Fatal(err)
	}
	projection := control.ResourceProjection{NetworkAuthority: &authority, Resources: control.Resources{Networks: networks}}
	work := control.RouteWork{Schema: 1, Reference: ref, Epoch: 1, AppsRevision: 20, ResourcesRevision: 21}
	return ref, record, projection, work
}

func TestRouteRetirementPendingOriginalPairSurvivesDBAndResolvesSharedACKLoss(t *testing.T) {
	path := filepath.Join(t.TempDir(), "observations.db")
	owner := routeNativeTestOwner(t, path)
	ref, record, projection, work := retiredRouteOwnerFixture(t, owner)
	report, err := owner.newRouteRetirement(projection, work, record, 300)
	if err != nil || report == nil || report.Close.At != 300 || report.Close.Boot != record.Dispatch.Boot || report.Dispatch.Journal != record.Dispatch.Journal || !report.Close.Settled || !report.Route.NativeGone {
		t.Fatal("retirement did not preserve original completed facts", err)
	}
	record.Retirement = report
	if err := owner.saveRouteOwner(record, ref); err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(record.Retirement)
	if err := owner.reports.Close(); err != nil {
		t.Fatal(err)
	}
	owner = routeNativeTestOwner(t, path)
	defer owner.reports.Close()
	restored, found, err := owner.loadRouteOwner(ref)
	if err != nil || !found || restored.Retirement == nil {
		t.Fatal("restart lost original retirement submission", err)
	}
	after, _ := json.Marshal(restored.Retirement)
	if !bytes.Equal(before, after) || restored.Nonce != record.Nonce {
		t.Fatal("restart regenerated original time, signatures, nonce or CAS")
	}
	authority, _, err := projection.NetworkAuthority.ObserveRouteRetired(projection.Resources.Networks, report.Close, report.Route, 301)
	if err != nil {
		t.Fatal(err)
	}
	shared, _ := authority.ReferenceConsumer(ref.ID)
	changed, _ := authority.ReferenceConsumer(ref.ID)
	changed.RouteClosed.Revision++
	changed.RouteClosed.Signature = ed25519.Sign(owner.Identity.Private, tenancy.RouteClosureBytes(*changed.RouteClosed))
	if err := owner.resolveRouteRetirement(changed, &restored); err == nil {
		t.Fatal("different signed policy receipt resolved the original pending report")
	}
	after, _ = json.Marshal(restored.Retirement)
	if !bytes.Equal(before, after) {
		t.Fatal("failed receipt comparison changed original submission")
	}
	if err := owner.resolveRouteRetirement(shared, &restored); err != nil {
		t.Fatal(err)
	}
	resolved, found, err := owner.loadRouteOwner(shared)
	if err != nil || !found || resolved.Retirement != nil || resolved.RetirementRejected || !resolved.BridgeReturned || !bytes.Equal(resolved.Core, record.Core) || resolved.Nonce != record.Nonce {
		t.Fatal("shared ACK resolution lost original local terminal record", err)
	}
}

func TestRouteRetirementRequiresDependencyClosureAndRejectsChangedStoredFacts(t *testing.T) {
	owner := routeNativeTestOwner(t, filepath.Join(t.TempDir(), "observations.db"))
	defer owner.reports.Close()
	ref, record, projection, work := retiredRouteOwnerFixture(t, owner)
	record.BridgeReturned = false
	if report, err := owner.newRouteRetirement(projection, work, record, 300); err != nil || report != nil {
		t.Fatal("unsettled Bridge produced a shared closure", err)
	}
	record.BridgeReturned = true
	report, err := owner.newRouteRetirement(projection, work, record, 300)
	if err != nil || report == nil {
		t.Fatal(err)
	}
	record.Retirement = report
	original, _ := json.Marshal(record)
	for _, mutate := range []func(*routeOwnerRecord){
		func(r *routeOwnerRecord) { r.BridgeReturned = false },
		func(r *routeOwnerRecord) { r.Retirement.Close.At++ },
		func(r *routeOwnerRecord) { r.Retirement.Route.PendingFlows++ },
		func(r *routeOwnerRecord) { r.Retirement.Dispatch.Journal[0]++ },
	} {
		var changed routeOwnerRecord
		if err := json.Unmarshal(original, &changed); err != nil {
			t.Fatal(err)
		}
		mutate(&changed)
		raw, _ := json.Marshal(changed)
		if _, err := decodeRouteOwner(raw, ref); err == nil {
			t.Fatal("stored original retirement facts were changed")
		}
	}
	missing := record
	missing.Retirement, missing.RetirementRejected = nil, true
	raw, _ := json.Marshal(missing)
	if _, err := decodeRouteOwner(raw, ref); err == nil {
		t.Fatal("known rejection lost its exact original submission")
	}
}

func TestRouteRetirementExpiredEnvelopePreservesFactsAcrossDBAndCurrentRoots(t *testing.T) {
	path := filepath.Join(t.TempDir(), "observations.db")
	owner := routeNativeTestOwner(t, path)
	ref, record, projection, work := retiredRouteOwnerFixture(t, owner)
	report, err := owner.newRouteRetirement(projection, work, record, 300)
	if err != nil || report == nil {
		t.Fatal(err)
	}
	record.Retirement = report
	if err = owner.saveRouteOwner(record, ref); err != nil {
		t.Fatal(err)
	}
	facts := func(r routeOwnerRecord) []byte {
		b, _ := json.Marshal([]any{r.Nonce, r.Core, r.Dispatch, r.Bridge, r.BridgeReturned, r.Retirement.Close, r.Retirement.Route})
		return b
	}
	original := facts(record)
	oldCommand, err := report.Command()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = owner.recordRouteRetirementResult(ref, record, state.Expired); err != nil {
		t.Fatal("expired report envelope cannot progress", err)
	}
	if err = owner.reports.Close(); err != nil {
		t.Fatal(err)
	}
	owner = routeNativeTestOwner(t, path)
	defer owner.reports.Close()
	record, found, err := owner.loadRouteOwner(ref)
	if err != nil || !found || !record.RetirementRejected || !bytes.Equal(original, facts(record)) {
		t.Fatal("DB lost original closed envelope/facts", err)
	}
	before, _ := json.Marshal(record)
	if err = owner.rebaseRouteRetirementReport(work, &record); err == nil {
		t.Fatal("same coordinates retried expired report")
	}
	after, _ := json.Marshal(record)
	if !bytes.Equal(before, after) {
		t.Fatal("failed rebase changed original record")
	}
	work.AppsRevision, work.ResourcesRevision = 40, 41
	if err = owner.rebaseRouteRetirementReport(work, &record); err != nil {
		t.Fatal(err)
	}
	current, err := record.Retirement.Command()
	if err != nil {
		t.Fatal(err)
	}
	if record.RetirementRejected || current.RequestID == oldCommand.RequestID || record.Retirement.Epoch != report.Epoch || record.Retirement.RootRevision != 40 || !bytes.Equal(original, facts(record)) || !ed25519.Verify(owner.Identity.Public[:], control.RouteRetirementReportBytes(*record.Retirement), record.Retirement.Signature) {
		t.Fatal("rebase changed permanent facts or did not bind current coordinates")
	}
	stored, found, err := owner.loadRouteOwner(ref)
	if err != nil || !found || stored.Retirement.RootRevision != 40 || !bytes.Equal(original, facts(stored)) {
		t.Fatal("current wrapper not durable", err)
	}
	unchanged, _ := json.Marshal(stored)
	for _, code := range []state.Code{state.Invalid, state.Forbidden, state.RequestConflict, state.LedgerFull} {
		if _, err = owner.recordRouteRetirementResult(ref, stored, code); err == nil {
			t.Fatal("unrelated rejection authorized renewal", code)
		}
		got, found, err := owner.loadRouteOwner(ref)
		raw, _ := json.Marshal(got)
		if err != nil || !found || !bytes.Equal(unchanged, raw) {
			t.Fatal("rejected result changed durable original", code, err)
		}
	}
}

func TestRouteRetirementEnvelopeWriteFailurePreservesOriginal(t *testing.T) {
	owner := routeNativeTestOwner(t, filepath.Join(t.TempDir(), "observations.db"))
	ref, record, projection, work := retiredRouteOwnerFixture(t, owner)
	report, err := owner.newRouteRetirement(projection, work, record, 300)
	if err != nil || report == nil {
		t.Fatal(err)
	}
	record.Retirement, record.RetirementRejected = report, true
	if err = owner.saveRouteOwner(record, ref); err != nil {
		t.Fatal(err)
	}
	if err = owner.reports.Close(); err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(record)
	work.AppsRevision, work.ResourcesRevision = 40, 41
	if err = owner.rebaseRouteRetirementReport(work, &record); err == nil {
		t.Fatal("closed DB published renewed wrapper")
	}
	after, _ := json.Marshal(record)
	if !bytes.Equal(before, after) {
		t.Fatal("write failure replaced original pending facts/envelope")
	}
}
