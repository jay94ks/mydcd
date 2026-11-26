// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/network/services"
)

// Epoch/work/native closure are explicit model facts here. The real DB and
// product envelope transition are reused, without claiming actual quorum I/O.
func TestRouteDispatchClosedEpochRenewsEnvelopeAndRetainsOriginalDBCore(t *testing.T) {
	ref, original := routeOwnerRecordFixture(t)
	path := filepath.Join(t.TempDir(), "observations.db")
	owner := routeNativeTestOwner(t, path)
	if err := owner.saveRouteOwner(original, ref); err != nil {
		t.Fatal(err)
	}
	work := control.RouteWork{Schema: 1, Reference: ref, Epoch: 1, AppsRevision: 30, ResourcesRevision: 31}
	record := original
	before, _ := json.Marshal(record)
	if err := owner.renewRouteReportEpoch(work, &record); err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(record)
	if !bytes.Equal(before, after) {
		t.Fatal("same epoch root movement replaced an unknown original report")
	}
	work.Epoch = 2
	if err := owner.renewRouteReportEpoch(work, &record); err != nil {
		t.Fatal(err)
	}
	if record.Report == nil || record.Report.Epoch != 2 || record.Report.RootRevision != 30 || record.Nonce != original.Nonce || !sameRouteDispatch(record.Dispatch, original.Dispatch) || !sameRouteDispatch(record.Report.Dispatch, original.Report.Dispatch) || !bytes.Equal(record.Core, original.Core) || record.NativeStarted || record.Bridge != original.Bridge || !ed25519.Verify(owner.Identity.Public[:], control.RouteDispatchReportBytes(*record.Report), record.Report.Signature) {
		t.Fatal("epoch renewal replaced original dispatch/native work or lost the signed envelope")
	}
	renewed, _ := json.Marshal(record)
	if err := owner.reports.Close(); err != nil {
		t.Fatal(err)
	}
	owner = routeNativeTestOwner(t, path)
	defer owner.reports.Close()
	record, found, err := owner.loadRouteOwner(ref)
	after, _ = json.Marshal(record)
	if err != nil || !found || !bytes.Equal(after, renewed) {
		t.Fatal("same DB did not preserve original core and renewed envelope", err)
	}
}

func TestRouteRetirementClosedEpochPreservesPermanentSignedFacts(t *testing.T) {
	owner := routeNativeTestOwner(t, filepath.Join(t.TempDir(), "observations.db"))
	defer owner.reports.Close()
	ref, record, projection, work := retiredRouteOwnerFixture(t, owner)
	report, err := owner.newRouteRetirement(projection, work, record, 300)
	if err != nil || report == nil {
		t.Fatal(err)
	}
	record.Retirement = report
	if err := owner.saveRouteOwner(record, ref); err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal([]any{record.Nonce, record.Core, record.Dispatch, record.Bridge, record.Retirement.Close, record.Retirement.Route})
	work.Epoch, work.AppsRevision, work.ResourcesRevision, work.Retiring = 2, 40, 41, true
	if err := owner.renewRouteReportEpoch(work, &record); err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal([]any{record.Nonce, record.Core, record.Dispatch, record.Bridge, record.Retirement.Close, record.Retirement.Route})
	if !bytes.Equal(before, after) || record.Retirement.Epoch != 2 || record.Retirement.RootRevision != 40 || record.Retirement.ResourcesRevision != 41 || record.RetirementRejected || !record.BridgeReturned || !ed25519.Verify(owner.Identity.Public[:], control.RouteRetirementReportBytes(*record.Retirement), record.Retirement.Signature) {
		t.Fatal("renewal changed original completed facts instead of only the report envelope")
	}
	stored, found, err := owner.loadRouteOwner(ref)
	raw, _ := json.Marshal(stored)
	want, _ := json.Marshal(record)
	if err != nil || !found || !bytes.Equal(raw, want) {
		t.Fatal("renewed retirement not durable", err)
	}
}

func TestRouteEpochFutureHalfClosureAndWriteFailureDoNotReplaceOriginal(t *testing.T) {
	ref, record := routeOwnerRecordFixture(t)
	owner := routeNativeTestOwner(t, filepath.Join(t.TempDir(), "observations.db"))
	if err := owner.saveRouteOwner(record, ref); err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(record)
	for _, work := range []control.RouteWork{
		{Reference: ref},           // No committed epoch.
		{Reference: ref, Epoch: 1}, // Future report relative to this work below.
		{Reference: ref, Epoch: 2}, // A partial pair is never absence of closure.
	} {
		candidate := record
		if work.Epoch == 1 {
			report := *record.Report
			report.Epoch = 2
			report.Signature = ed25519.Sign(owner.Identity.Private, control.RouteDispatchReportBytes(report))
			candidate.Report = &report
		}
		if work.Epoch == 2 {
			work.Reference.Closed = &services.ReferenceClose{}
		}
		input, _ := json.Marshal(candidate)
		if err := owner.renewRouteReportEpoch(work, &candidate); err == nil {
			t.Fatal("unproven epoch/closure admitted report renewal")
		}
		after, _ := json.Marshal(candidate)
		if !bytes.Equal(input, after) {
			t.Fatal("rejected renewal changed original input")
		}
	}
	if err := owner.reports.Close(); err != nil {
		t.Fatal(err)
	}
	if err := owner.renewRouteReportEpoch(control.RouteWork{Reference: ref, Epoch: 2, AppsRevision: 30}, &record); err == nil || !owner.routeStoreFailed {
		t.Fatal("closed DB claimed durable renewal or remained usable", err)
	}
	after, _ := json.Marshal(record)
	if !bytes.Equal(before, after) {
		t.Fatal("uncertain write reset original in-memory report/core")
	}
}

func TestRouteWorkComparisonRejectsMixedPermissionReferenceAndEpoch(t *testing.T) {
	ref, _ := routeOwnerRecordFixture(t)
	original := control.RouteWork{Schema: 1, Reference: ref, Epoch: 1, AppsRevision: 10, ResourcesRevision: 11, PrepareAllowed: true, MaxConsumers: 8}
	if !sameRouteWorkPermission(original, original) {
		t.Fatal("same work differs")
	}
	for _, mutate := range []func(*control.RouteWork){
		func(w *control.RouteWork) { w.Epoch++ },
		func(w *control.RouteWork) { w.AppsRevision-- },
		func(w *control.RouteWork) { w.ResourcesRevision-- },
		func(w *control.RouteWork) { w.PrepareAllowed = false },
		func(w *control.RouteWork) { w.Reference.Lifetime.Token++ },
		func(w *control.RouteWork) { w.Reference.Native.Spec[0]++ },
		func(w *control.RouteWork) { w.MaxConsumers-- },
		func(w *control.RouteWork) { w.Retiring = true },
		func(w *control.RouteWork) { w.Reference.DesiredSource++ },
		func(w *control.RouteWork) { w.Reference.Local.Owner[0]++ },
		func(w *control.RouteWork) { w.Peer.ID[0]++ },
		func(w *control.RouteWork) { w.Packets.QueueBytes++ },
	} {
		raw, _ := json.Marshal(original)
		var current control.RouteWork
		if err := json.Unmarshal(raw, &current); err != nil {
			t.Fatal(err)
		}
		mutate(&current)
		if sameRouteWorkPermission(original, current) {
			t.Fatal("mixed work retained authority")
		}
	}
	current := original
	current.AppsRevision++
	current.ResourcesRevision++
	if !sameRouteWorkPermission(original, current) {
		t.Fatal("unrelated root advance rejected identical recomputed permission")
	}
	if original.AppsRevision != 10 || original.ResourcesRevision != 11 {
		t.Fatal("comparison changed the original quorum response")
	}
}
