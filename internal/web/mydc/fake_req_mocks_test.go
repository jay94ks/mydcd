// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"slices"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/userauth"
)

func TestTenantStorageAndAllowedNodes(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	admin := passwordLogin(t, f, "admin", "admin")
	alice := passwordLogin(t, f, "alice", "alice")
	bob, _ := keyLogin(t, f, "bob", FixtureKey("bob"))

	p, err := alice.TenantStoragePage(ctx, "shop", "", "")
	if err != nil || len(p.Items) != 1 || p.Items[0].Node != "node-b" || p.Items[0].ID != "ssd" || p.Items[0].Generation != 1 {
		t.Fatalf("shop storage %+v %v", p, err)
	}
	_, err = bob.TenantStoragePage(ctx, "payments", "", "")
	wantCode(t, err, CodeDenied)

	// The tenant's allowed servers and the revision set-nodes expects are
	// select-tenant's AllowedNodes and Revision.
	n, err := bob.SelectTenant(ctx, "shop")
	if err != nil || strings.Join(n.AllowedNodes, ",") != "node-a,node-b" {
		t.Fatalf("allowed %+v %v", n, err)
	}
	// set-nodes is CAS on the tenant revision and raises it.
	if _, res := submit(t, admin, ActionSetNodes, n.Revision-1, control.NodeAssignment{Tenant: "shop", Nodes: []string{"node-a"}}, rootFor(t, admin, ActionSetNodes)); res.Code != ResultConditionFailed {
		t.Fatalf("stale set-nodes %+v", res)
	}
	if _, res := submit(t, admin, ActionSetNodes, n.Revision, control.NodeAssignment{Tenant: "shop", Nodes: []string{"node-a", "node-b", "node-c"}}, rootFor(t, admin, ActionSetNodes)); res.Code != ResultApplied {
		t.Fatalf("set-nodes %+v", res)
	}
	m, _ := bob.SelectTenant(ctx, "shop")
	if len(m.AllowedNodes) != 3 || m.Revision <= n.Revision {
		t.Fatalf("after set-nodes %+v", m)
	}
	ts, _ := bob.Tenants(ctx)
	if len(ts) == 0 || ts[0].AllowedNodes == nil {
		t.Fatalf("tenants %+v", ts)
	}
	_, err = bob.SelectTenant(ctx, "payments")
	wantCode(t, err, CodeDenied)
}

func TestRaftCompact(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	admin := passwordLogin(t, f, "admin", "admin")
	alice := passwordLogin(t, f, "alice", "alice")
	change := func(op string, sel CompactSelection) CompactChange {
		p, err := admin.RaftCompactPlan(ctx, sel, "")
		if err != nil {
			t.Fatalf("plan %+v: %v", sel, err)
		}
		return CompactChange{Operation: op, Selection: sel, Target: p.Target}
	}
	keep := CompactSelection{Mode: "keep"}
	if _, err := alice.RaftCompactPlan(ctx, keep, ""); err == nil {
		t.Fatal("plan by a non-admin")
	}
	if _, res := submit(t, alice, ActionRaftCompact, 0, change("compact-x", keep), rootFor(t, alice, ActionRaftCompact)); res.Code != ResultForbidden {
		t.Fatalf("non-admin %+v", res)
	}
	minimal := CompactSelection{Mode: "minimal", Retain: 500}
	p, err := admin.RaftCompactPlan(ctx, minimal, "")
	if err != nil || p.Total != 3 || len(p.Nodes) != 3 || p.Nodes[2].Node != "node-a" || p.Next != "" {
		t.Fatalf("plan %+v %v", p, err)
	}
	// A Target from another selection is a changed roster.
	if _, res := submit(t, admin, ActionRaftCompact, 0, CompactChange{Operation: "compact-0", Selection: minimal, Target: change("compact-0", keep).Target}, rootFor(t, admin, ActionRaftCompact)); res.Code != ResultConditionFailed {
		t.Fatalf("other target %+v", res)
	}
	f.HoldCompaction(true)
	f.FailCompaction("node-c", "disk full")
	if _, res := submit(t, admin, ActionRaftCompact, 0, change("compact-1", minimal), rootFor(t, admin, ActionRaftCompact)); res.Code != ResultApplied {
		t.Fatalf("compact %+v", res)
	}
	st, _ := admin.RaftStatus(ctx)
	lc := st.LastManualCompact
	runs := raftCompactNodes(st)
	if lc == nil || lc.Operation != "compact-1" || lc.Total != 3 || lc.Complete || lc.Options.Mode != "minimal" || runs["node-c"].State != "queued" || runs["node-a"].State != "queued" || runs["node-b"].State != "running" {
		t.Fatalf("running %+v %+v", lc, runs)
	}
	// One at a time on the same servers.
	if _, res := submit(t, admin, ActionRaftCompact, 0, change("compact-2", keep), rootFor(t, admin, ActionRaftCompact)); res.Code != ResultInvalid {
		t.Fatalf("busy %+v", res)
	}
	f.HoldCompaction(false)
	st, _ = admin.RaftStatus(ctx)
	if lc := st.LastManualCompact; lc == nil || !lc.Complete || lc.Failed != 1 || lc.Done != 2 {
		t.Fatalf("summary %+v", lc)
	}
	for node, r := range raftCompactNodes(st) {
		switch node {
		case "node-c":
			if r.State != "failed" || r.Code != "disk full" {
				t.Fatalf("node-c %+v", r)
			}
		default:
			if r.State != "done" || r.LogEntriesAfter != 500 || r.LogEntriesBefore <= 500 || r.LogUsedBytesAfter >= r.LogUsedBytesBefore || r.LogFileBytesAfter != r.LogUsedBytesBefore {
				t.Fatalf("%s %+v", node, r)
			}
		}
	}
	if st.Local.SnapshotIndex < 48209 || st.Local.SnapshotAt == 0 {
		t.Fatalf("snapshot index %d", st.Local.SnapshotIndex)
	}
	// raft-compact-status: 4 nodes a page, the summary on each.
	sp, err := admin.RaftCompactStatus(ctx, "compact-1", "")
	if err != nil || !sp.Summary.Complete || sp.Summary.Failed != 1 || len(sp.Nodes) != 3 || sp.Next != "" || sp.Target != p.Target {
		t.Fatalf("status %+v %v", sp, err)
	}
	if _, err := admin.RaftCompactStatus(ctx, "compact-none", ""); err == nil {
		t.Fatal("status of an unknown job")
	}
	if _, res := submit(t, admin, ActionRaftCompact, 0, change("compact-1", keep), rootFor(t, admin, ActionRaftCompact)); res.Code != ResultConditionFailed {
		t.Fatalf("reused operation %+v", res)
	}
	if _, err := admin.RaftCompactPlan(ctx, CompactSelection{Mode: "keep", Nodes: []string{"node-z"}}, ""); err == nil {
		t.Fatal("plan for an unknown server")
	}
}

// REQ-58 in mydcd's real shape: TenantStoragePage rows carry the whole Root.
func TestTenantStoragePageReal(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	alice := passwordLogin(t, f, "alice", "alice")
	bob, _ := keyLogin(t, f, "bob", FixtureKey("bob"))
	p, err := alice.TenantStoragePage(ctx, "shop", "", "")
	if err != nil || len(p.Items) == 0 || p.Next != "" {
		t.Fatalf("page %+v %v", p, err)
	}
	for _, r := range p.Items {
		if !r.Allowed || r.Root.Validate() != nil || r.Root.Node != r.Node || r.Root.ID != r.ID || r.Root.Path == "" {
			t.Fatalf("row %+v", r)
		}
	}
	if one, _ := alice.TenantStoragePage(ctx, "shop", "node-b", ""); len(one.Items) == 0 || slices.ContainsFunc(one.Items, func(r control.TenantStorageRoot) bool { return r.Node != "node-b" }) {
		t.Fatalf("node filter %+v", one.Items)
	}
	if _, err := bob.TenantStoragePage(ctx, "shop", "", ""); err == nil {
		t.Fatal("reader sees tenant storage")
	}
	if _, err := alice.TenantStoragePage(ctx, "shop", "", "bad:node-b/ssd"); err == nil {
		t.Fatal("foreign cursor")
	}
}

func raftCompactNodes(st RaftStatus) map[string]userauth.RaftCompactNode {
	out := map[string]userauth.RaftCompactNode{}
	for _, n := range st.Nodes {
		if n.LastManualCompact != nil {
			out[n.Node] = *n.LastManualCompact
		}
	}
	return out
}
