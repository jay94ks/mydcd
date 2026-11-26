// SPDX-License-Identifier: Apache-2.0

package state

import (
	"fmt"
	"testing"
)

func TestRouteDispatchTargetPreservesEpochFloorSnapshotAndNarrowFraming(t *testing.T) {
	checkScopedReportEpochAndFloor(t, RouteDispatchTarget)
}
func TestAppDeliveryTargetPreservesEpochFloorSnapshotAndNarrowFraming(t *testing.T) {
	checkScopedReportEpochAndFloor(t, AppDeliveryTarget)
}
func TestAppInventoryTargetPreservesEpochFloorSnapshotAndNarrowFraming(t *testing.T) {
	checkScopedReportEpochAndFloor(t, AppInventoryTarget)
}
func checkScopedReportEpochAndFloor(t *testing.T, target string) {
	t.Helper()
	s, reduce, admit := reportFixture()
	original := checkpoint(s, "control/apps", "original")
	original.Target = target
	original.RequestID = ReportRequestID(original)
	// Replay collection is triggered only at the bounded ledger budget.
	// Fill it with accepted current reports instead of assuming eager floors.
	var err error
	var result Result
	for i := 0; i < LedgerLimit+2; i++ {
		newer := checkpoint(s, "control/apps", fmt.Sprint(i))
		newer.Target = target
		newer.RequestID = ReportRequestID(newer)
		s, result, err = ApplyAdmitted(s, s.Index()+1, newer, nil, reduce, admit)
		if err != nil || result.Code != Applied {
			t.Fatal(result, err)
		}
	}
	before := s.Object(original.Key)
	next, result, err := ApplyAdmitted(s, s.Index()+1, original, nil, reduce, admit)
	if err != nil || result.Code != Expired || next.Object(original.Key) != before {
		t.Fatal("reference target bypassed original report floor", result, err)
	}
	raw, err := Encode(s)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := Decode(raw)
	if err != nil || !restored.ModuleExpired(original) {
		t.Fatal("snapshot lost scoped replay floor", err)
	}
	future := checkpoint(restored, "control/apps", "future")
	future.Target = target
	future.Epoch++
	future.RequestID = ReportRequestID(future)
	_, result, err = ApplyAdmitted(restored, restored.Index()+1, future, nil, reduce, admit)
	if err != nil || result.Code != Expired {
		t.Fatal("scoped target bypassed epoch", result, err)
	}
	for _, c := range []Command{
		{Kind: ModuleReport, Actor: "node/reporter", Epoch: 1, Key: "control/other", Target: target, Value: "bad"},
		{Kind: ModuleReport, Actor: "user/reporter", Epoch: 1, Key: "control/apps", Target: target, Value: "bad"},
		{Kind: ModuleReport, Actor: "node/reporter", Epoch: 1, Key: "control/apps", Target: target + "-other", Value: "bad"},
	} {
		c.RequestID = ReportRequestID(c)
		n, r, e := ApplyAdmitted(restored, restored.Index()+1, c, nil, reduce, admit)
		if e != nil || r.Code == Applied || n.Object(c.Key) != restored.Object(c.Key) {
			t.Fatal("target broadened report framing", r, e)
		}
	}
}
