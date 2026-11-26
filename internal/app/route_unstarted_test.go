// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/network/services"
)

// A committed withdrawal/no-grant barrier is a product-core fact. No physical
// absence or mock native success is used to establish these terminal journals.
func TestNeverDispatchedRetirementKeepsPrivateProposalNonceAndUnknownSubmission(t *testing.T) {
	ref, record, catalog, networks, authority := routeOwnerCoreFixture(t)
	policy, _ := networks.Route("first", "database")
	var err error
	networks, err = networks.Withdraw(catalog, "admin", "first", "database", "first", policy.Revision)
	if err != nil {
		t.Fatal(err)
	}
	core, err := services.DecodeRouteRuntime(record.Core)
	if err != nil {
		t.Fatal(err)
	}
	core, err = core.RetireNeverDispatched(catalog, networks, authority)
	if err != nil {
		t.Fatal(err)
	}
	originalProposal, _ := json.Marshal(record.Dispatch)
	originalSubmission, _ := json.Marshal(record.Report)
	originalNonce := record.Nonce
	record.Core, err = core.Encode()
	if err != nil {
		t.Fatal(err)
	}
	record.NeverDispatched, record.BridgeReturned = true, true
	path := filepath.Join(t.TempDir(), "observations.db")
	owner := routeNativeTestOwner(t, path)
	if err := owner.saveRouteOwner(record, ref); err != nil {
		t.Fatal(err)
	}
	projection := control.ResourceProjection{NetworkAuthority: &authority, Resources: control.Resources{Networks: networks}}
	work := control.RouteWork{Schema: 1, Reference: ref, Retiring: true, Epoch: 1, AppsRevision: 20, ResourcesRevision: 21}
	report, err := owner.newRouteRetirement(projection, work, record, 500)
	if err != nil || report == nil || !report.NeverDispatched || !sameRouteDispatch(report.Dispatch, services.RouteDispatch{}) {
		t.Fatal("no-grant barrier was not distinguished from a native grant", err)
	}
	record.Retirement = report
	if err := owner.saveRouteOwner(record, ref); err != nil {
		t.Fatal(err)
	}
	if err := owner.reports.Close(); err != nil {
		t.Fatal(err)
	}
	owner = routeNativeTestOwner(t, path)
	defer owner.reports.Close()
	restored, found, err := owner.loadRouteOwner(ref)
	if err != nil || !found || !restored.NeverDispatched || restored.Report == nil || restored.Retirement == nil || restored.Nonce != originalNonce {
		t.Fatal("restart erased original proposal or unresolved submission", err)
	}
	proposal, _ := json.Marshal(restored.Dispatch)
	submission, _ := json.Marshal(restored.Report)
	if !bytes.Equal(originalProposal, proposal) || !bytes.Equal(originalSubmission, submission) {
		t.Fatal("never-dispatched transition rewrote original private identity")
	}
	// A real committed grant, even with the same consumer and proposal, makes
	// this recovery mode inadmissible. It cannot hide a lost original journal.
	ref.Dispatch = &record.Dispatch
	raw, _ := json.Marshal(restored)
	if _, err := decodeRouteOwner(raw, ref); err == nil {
		t.Fatal("never-dispatched record adopted an actual native grant")
	}
}

func TestFreshNeverDispatchedCoreCreatesNoNonceGrantOrNativeWork(t *testing.T) {
	ref, _, catalog, networks, authority := routeOwnerCoreFixture(t)
	policy, _ := networks.Route("first", "database")
	var err error
	networks, err = networks.Withdraw(catalog, "admin", "first", "database", "first", policy.Revision)
	if err != nil {
		t.Fatal(err)
	}
	core, err := services.NewUnstartedRouteRetirement(catalog, networks, authority, ref.ID, [32]byte{71})
	if err != nil {
		t.Fatal(err)
	}
	if core.Journal().Pending != nil || core.Journal().Applied.Present || core.Journal().Desired.Present || core.FlowCount() != 0 {
		t.Fatal("never-dispatched core could execute native work")
	}
	rawCore, err := core.Encode()
	if err != nil {
		t.Fatal(err)
	}
	record := routeOwnerRecord{Schema: 1, Core: rawCore, NeverDispatched: true, BridgeReturned: true}
	owner := routeNativeTestOwner(t, filepath.Join(t.TempDir(), "observations.db"))
	defer owner.reports.Close()
	if err := owner.saveRouteOwner(record, ref); err != nil {
		t.Fatal(err)
	}
	restored, found, err := owner.loadRouteOwner(ref)
	if err != nil || !found || restored.Nonce != ([32]byte{}) || restored.NativeStarted || restored.Report != nil || !sameRouteDispatch(restored.Dispatch, services.RouteDispatch{}) {
		t.Fatal("fresh terminal core invented a private/native grant", err)
	}
}
