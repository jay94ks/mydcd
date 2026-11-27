// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/network/services"
)

func TestRouteDispatchWindowFencesOldEnvelopeAndKeepsOriginalDispatch(t *testing.T) {
	f, proposal := routeControlFixture(t)
	approveRouteControl(t, f, proposal)
	ref, _, report := originalRouteDispatch(t, f)
	original, _ := report.Command()
	f.apply("route-dispatch-window", "rotate-ledger", 1, LedgerWindow{NextEpoch: 2}, state.Applied)
	beforeApps, beforeResources := f.s.Object(AppsKey), f.s.Object(ResourcesKey)
	applyRouteDispatch(t, f, report, state.Expired)
	if f.s.Object(AppsKey) != beforeApps || f.s.Object(ResourcesKey) != beforeResources {
		t.Fatal("closed report epoch mutated route authority")
	}
	work, err := f.p.RouteWork(f.s, ref.Local.Owner, RouteWorkRequest{Reference: ref.ID})
	if err != nil || work.Epoch != 2 || work.Reference.Dispatch != nil || work.Reference.Closed != nil {
		t.Fatal("quorum model did not preserve original unadmitted reference", err)
	}
	oldDispatch, _ := json.Marshal(report.Dispatch)
	report.Epoch, report.RootRevision = work.Epoch, work.AppsRevision
	report.Signature = ed25519.Sign(f.node, RouteDispatchReportBytes(report))
	applyRouteDispatch(t, f, report, state.Applied)
	work, err = f.p.RouteWork(f.s, ref.Local.Owner, RouteWorkRequest{Reference: ref.ID})
	got, _ := json.Marshal(work.Reference.Dispatch)
	if err != nil || !bytes.Equal(oldDispatch, got) || work.Reference.ID != ref.ID || work.Reference.Generation != ref.Generation || work.Reference.Lifetime != ref.Lifetime {
		t.Fatal("new envelope replaced the original immutable dispatch/grant", err)
	}
	if _, found := f.s.LookupResult(original); found || !f.s.ModuleExpired(original) {
		t.Fatal("closed epoch was presented as an original effect receipt")
	}
}

func TestRouteRetirementWindowPreservesSharedPairAndAllowsOnlyOriginalRemainingFact(t *testing.T) {
	f, _, reports, keys := routeRetirementFixture(t)
	first, _ := applyRouteRetirement(t, f, reports[0], state.Applied)
	f.apply("route-retirement-window", "rotate-ledger", 1, LedgerWindow{NextEpoch: 2}, state.Applied)
	projection, err := f.p.ProjectResources(f.s)
	if err != nil || projection.NetworkAuthority == nil {
		t.Fatal(err)
	}
	closed, found := projection.NetworkAuthority.ReferenceConsumer(reports[0].Close.Consumer)
	if !found || closed.Closed == nil || closed.RouteClosed == nil || services.ValidateRouteRetirement(closed, *closed.Closed, *closed.RouteClosed) != nil {
		t.Fatal("window reclaimed permanent paired closure")
	}
	if _, found := f.s.LookupResult(first); found {
		t.Fatal("old report ledger receipt was not reclaimed")
	}
	beforeApps, beforeResources := f.s.Object(AppsKey), f.s.Object(ResourcesKey)
	applyRouteRetirement(t, f, reports[1], state.Expired)
	if f.s.Object(AppsKey) != beforeApps || f.s.Object(ResourcesKey) != beforeResources {
		t.Fatal("old epoch partly closed peer")
	}
	work, err := f.p.RouteWork(f.s, reports[1].Reporter, RouteWorkRequest{Reference: reports[1].Close.Consumer})
	if err != nil || work.Reference.Closed != nil || work.Epoch != 2 || !work.Retiring {
		t.Fatal("remaining original peer not positively unclosed", err)
	}
	report := reports[1]
	facts, _ := json.Marshal([]any{report.Dispatch, report.Close, report.Route})
	report.Epoch, report.RootRevision, report.ResourcesRevision = work.Epoch, work.AppsRevision, work.ResourcesRevision
	report.Signature = ed25519.Sign(keys[report.Reporter], RouteRetirementReportBytes(report))
	applyRouteRetirement(t, f, report, state.Applied)
	projection, err = f.p.ProjectResources(f.s)
	if err != nil {
		t.Fatal(err)
	}
	peer, found := projection.NetworkAuthority.ReferenceConsumer(report.Close.Consumer)
	after, _ := json.Marshal([]any{peer.Dispatch, peer.Closed, peer.RouteClosed})
	if !found || !bytes.Equal(facts, after) || peer.Generation != work.Reference.Generation || peer.Lifetime != work.Reference.Lifetime {
		t.Fatal("epoch recovery replaced original closure/dispatch facts")
	}
}
