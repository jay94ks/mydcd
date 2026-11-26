// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"encoding/json"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"path/filepath"
	"testing"
)

func TestRouteDispatchExpiredEnvelopePreservesOriginalCoreAndNativeIdentity(t *testing.T) {
	ref, original := routeOwnerRecordFixture(t)
	path := filepath.Join(t.TempDir(), "owner.db")
	owner := routeNativeTestOwner(t, path)
	if err := owner.saveRouteOwner(original, ref); err != nil {
		t.Fatal(err)
	}
	if err := owner.recordRouteDispatchResult(ref, original, state.Expired); err != nil {
		t.Fatal("positively fenced report remained stuck", err)
	}
	record, found, err := owner.loadRouteOwner(ref)
	if err != nil || !found || record.Report != nil || record.NativeStarted || record.Bridge != original.Bridge || record.Nonce != original.Nonce || !sameRouteDispatch(record.Dispatch, original.Dispatch) || !bytes.Equal(record.Core, original.Core) {
		t.Fatal("expired envelope replaced original work or authorized native", err)
	}
	if original.Report == nil {
		t.Fatal("result handling mutated the caller's unknown original")
	}
	if err := owner.reports.Close(); err != nil {
		t.Fatal(err)
	}
	owner = routeNativeTestOwner(t, path)
	defer owner.reports.Close()
	stored, found, err := owner.loadRouteOwner(ref)
	a, _ := json.Marshal(record)
	b, _ := json.Marshal(stored)
	if err != nil || !found || !bytes.Equal(a, b) {
		t.Fatal("same DB lost envelope closure or original identity", err)
	}
}

func TestRouteDispatchForbiddenOrInvalidResultRetainsOriginalReport(t *testing.T) {
	for _, code := range []state.Code{state.Forbidden, state.Invalid} {
		ref, original := routeOwnerRecordFixture(t)
		owner := routeNativeTestOwner(t, filepath.Join(t.TempDir(), "owner.db"))
		if err := owner.saveRouteOwner(original, ref); err != nil {
			t.Fatal(err)
		}
		before, _ := json.Marshal(original)
		if err := owner.recordRouteDispatchResult(ref, original, code); err == nil {
			t.Fatal("unproven rejection closed original envelope", code)
		}
		stored, found, err := owner.loadRouteOwner(ref)
		after, _ := json.Marshal(stored)
		if err != nil || !found || !bytes.Equal(before, after) {
			t.Fatal("rejection changed original pending report", err)
		}
		if err := owner.reports.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRouteDispatchExpiredStoreFailureKeepsOriginalEnvelope(t *testing.T) {
	ref, original := routeOwnerRecordFixture(t)
	path := filepath.Join(t.TempDir(), "owner.db")
	owner := routeNativeTestOwner(t, path)
	if err := owner.saveRouteOwner(original, ref); err != nil {
		t.Fatal(err)
	}
	if err := owner.reports.Close(); err != nil {
		t.Fatal(err)
	}
	if err := owner.recordRouteDispatchResult(ref, original, state.Expired); err == nil {
		t.Fatal("failed store acknowledged envelope closure")
	}
	owner = routeNativeTestOwner(t, path)
	defer owner.reports.Close()
	stored, found, err := owner.loadRouteOwner(ref)
	a, _ := json.Marshal(original)
	b, _ := json.Marshal(stored)
	if err != nil || !found || !bytes.Equal(a, b) {
		t.Fatal("failed envelope closure lost original identity", err)
	}
}
