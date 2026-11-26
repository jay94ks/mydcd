// SPDX-License-Identifier: Apache-2.0

package mydc

import "testing"

// node-summary rows carry the observe limit behind "unreachable".
func TestNodeSummaryObserveLimit(t *testing.T) {
	f, _ := newTestFake(t)
	alice := passwordLogin(t, f, "alice", "alice")
	rows, err := alice.NodeSummary(ctx, "shop", "", "")
	if err != nil || len(rows.Nodes) == 0 {
		t.Fatalf("summary %v %v", rows, err)
	}
	for _, r := range rows.Nodes {
		if r.ObserveLimitSeconds != DefaultObserveLimitSeconds {
			t.Fatalf("row %+v", r)
		}
	}
	admin := passwordLogin(t, f, "admin", "admin")
	all, _ := admin.NodeSummary(ctx, "", "", "")
	for _, r := range all.Nodes {
		age := uint64(fixtureNow)*1000 - r.ObservedAt
		if r.State != "pending" && (r.State == "unreachable") != (age > r.ObserveLimitSeconds*1000) {
			t.Fatalf("fixture %s state %s age %d limit %d", r.Node, r.State, age, r.ObserveLimitSeconds)
		}
	}
	f.SetObserveLimit(30)
	if rows, _ = alice.NodeSummary(ctx, "shop", "", ""); rows.Nodes[0].ObserveLimitSeconds != 30 {
		t.Fatalf("set %+v", rows.Nodes[0])
	}
}
