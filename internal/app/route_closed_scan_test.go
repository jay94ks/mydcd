// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/network/services"
	"path/filepath"
	"testing"
)

func closedRouteScanFixture(t *testing.T, owner *Runtime) (services.ReferenceConsumer, routeOwnerRecord, control.ResourceProjection) {
	t.Helper()
	ref, record, projection, work := retiredRouteOwnerFixture(t, owner)
	report, err := owner.newRouteRetirement(projection, work, record, 300)
	if err != nil || report == nil {
		t.Fatal(err)
	}
	record.Retirement = report
	if err := owner.saveRouteOwner(record, ref); err != nil {
		t.Fatal(err)
	}
	authority, _, err := projection.NetworkAuthority.ObserveRouteRetired(projection.Resources.Networks, report.Close, report.Route, 301)
	if err != nil {
		t.Fatal(err)
	}
	projection.NetworkAuthority = &authority
	ref, _ = authority.ReferenceConsumer(ref.ID)
	return ref, record, projection
}

func TestCommittedClosedRouteScanSettlesOriginalPairWithoutEngineOrNative(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owner.db")
	owner := routeNativeTestOwner(t, path)
	ref, original, projection := closedRouteScanFixture(t, owner)
	// No Engine/Mesh/native adapter exists: a fresh quorum call here would panic.
	for range 2 {
		if err := owner.prepareRouteOwners(context.Background(), cluster.View{}, projection); err != nil {
			t.Fatal(err)
		}
	}
	stored, found, err := owner.loadRouteOwner(ref)
	if err != nil || !found || stored.Retirement != nil || !stored.BridgeReturned || stored.NativeStarted != original.NativeStarted || stored.Nonce != original.Nonce || !sameRouteDispatch(stored.Dispatch, original.Dispatch) || !bytes.Equal(stored.Core, original.Core) {
		t.Fatal("closed scan changed original terminal work", err)
	}
	if err := owner.reports.Close(); err != nil {
		t.Fatal(err)
	}
	owner = routeNativeTestOwner(t, path)
	defer owner.reports.Close()
	if closed, err := owner.settleCommittedRouteClosure(ref); err != nil || !closed {
		t.Fatal("same DB lost permanent closure", err)
	}
}

func TestCommittedClosedRouteScanRejectsMissingJournalAndChangedReceipt(t *testing.T) {
	owner := routeNativeTestOwner(t, filepath.Join(t.TempDir(), "owner.db"))
	defer owner.reports.Close()
	ref, original, _ := closedRouteScanFixture(t, owner)
	before, _ := json.Marshal(original)
	changed := ref
	receipt := *ref.RouteClosed
	receipt.Signature = append([]byte(nil), receipt.Signature...)
	receipt.Signature[0] ^= 1
	changed.RouteClosed = &receipt
	if closed, err := owner.settleCommittedRouteClosure(changed); err == nil || closed {
		t.Fatal("changed receipt bypassed original closure")
	}
	stored, _, err := owner.loadRouteOwner(ref)
	after, _ := json.Marshal(stored)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed closure changed original pending report", err)
	}
	missing := routeNativeTestOwner(t, filepath.Join(t.TempDir(), "missing.db"))
	defer missing.reports.Close()
	if closed, err := missing.settleCommittedRouteClosure(ref); err == nil || closed {
		t.Fatal("permanent dispatch journal loss was ignored")
	}
	open := ref
	open.Closed = nil
	open.RouteClosed = nil
	if closed, err := owner.settleCommittedRouteClosure(open); err != nil || closed {
		t.Fatal("open lifetime skipped latest-work authority", err)
	}
}
