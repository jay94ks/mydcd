// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/control"
)

// RQ4 node-pair reconnect in mydcd's real shape: plan → signed
// reconnect-tunnel TunnelChange → status; the down pair also gives one
// tenant-scoped tunnel-down/-up per TUN network.
func TestTunnelReconnectReal(t *testing.T) {
	f, clk := newTestFake(t)
	f.SetIdleTimeout(0)
	admin := passwordLogin(t, f, "admin", "admin")
	alice := passwordLogin(t, f, "alice", "alice")
	events := func(kind string) []FixtureEvent {
		t.Helper()
		p, err := seedEvents(admin, "payments", "")
		if err != nil {
			t.Fatal(err)
		}
		var out []FixtureEvent
		for _, e := range p.Items {
			if e.Kind == kind {
				out = append(out, e)
			}
		}
		return out
	}

	// An up (degraded) link has no plan; a manager is not a system admin.
	if _, err := admin.PlanTunnelReconnect(ctx, "node-a", "node-c"); err == nil {
		t.Fatal("plan for a link that is not down")
	}
	if _, err := admin.PlanTunnelReconnect(ctx, "node-a", "node-a"); err == nil {
		t.Fatal("plan for the same node")
	}
	f.SetMeshLinkDown("node-c", "node-a", true)
	if _, err := alice.PlanTunnelReconnect(ctx, "node-a", "node-c"); err == nil {
		t.Fatal("plan by a tenant manager")
	}
	down := events("tunnel-down")
	if len(down) != 2 || down[1].PairID != "node-a/node-c" || down[1].Network != "payments-net" || down[1].Scope != "tenant" || down[1].Detail != "AUTHENTICATED_LINK_DOWN" {
		t.Fatalf("tunnel-down %+v", down)
	}

	p, err := admin.PlanTunnelReconnect(ctx, "node-a", "node-c")
	if err != nil || !p.Valid() || p.PairID != "node-a/node-c" || p.Node != "node-a" || p.Peer != "node-c" || p.Endpoint != "10.0.0.13:7443" || p.Observation.Link.State != "down" {
		t.Fatalf("plan %+v %v", p, err)
	}
	root := rootFor(t, admin, ActionReconnectTunnel)
	ch := control.TunnelChange{Operation: "link-1", Plan: p}
	if _, res := submit(t, alice, ActionReconnectTunnel, 0, ch, root); res.Code != ResultForbidden {
		t.Fatalf("manager reconnect %+v", res)
	}
	if _, res := submit(t, admin, ActionReconnectTunnel, 0, ch, root); res.Code != ResultApplied {
		t.Fatalf("reconnect %+v", res)
	}
	if _, res := submit(t, admin, ActionReconnectTunnel, 0, control.TunnelChange{Operation: "link-2", Plan: p}, rootFor(t, admin, ActionReconnectTunnel)); res.Code != ResultConditionFailed {
		t.Fatalf("second job for the same pair %+v", res)
	}
	s, err := admin.TunnelReconnectStatus(ctx, "link-1")
	if err != nil || s.State != "queued" || s.Result != nil || s.User != "u-admin" || s.Plan.Target != p.Target {
		t.Fatalf("status %+v %v", s, err)
	}
	if _, err := alice.TunnelReconnectStatus(ctx, "link-1"); err == nil {
		t.Fatal("status by a tenant manager")
	}
	if _, err := admin.TunnelReconnectStatus(ctx, "link-9"); err == nil {
		t.Fatal("status of an unknown operation")
	}
	clk.add(time.Second)
	if s, _ = admin.TunnelReconnectStatus(ctx, "link-1"); s.State != "running" {
		t.Fatalf("running %+v", s)
	}
	clk.add(2 * time.Second)
	s, _ = admin.TunnelReconnectStatus(ctx, "link-1")
	if s.State != "done" || s.Result == nil || s.Result.State != "reconnected" || !s.Result.Valid(s.Plan) || s.RootRevision != rootFor(t, admin, ActionReconnectTunnel) {
		t.Fatalf("done %+v", s)
	}
	if up := events("tunnel-up"); len(up) != 1 || up[0].PairID != "node-a/node-c" || up[0].Network != "payments-net" {
		t.Fatalf("tunnel-up %+v", up)
	}
	p2, _ := seedEvents(admin, "", "")
	found := false
	for _, e := range p2.Items {
		found = found || e.Kind == "tunnel-reconnected" && e.Scope == "node" && e.Node == "node-a" && e.PairID == "node-a/node-c"
	}
	if !found {
		t.Fatalf("no tunnel-reconnected in %+v", p2.Items)
	}

	// Recovered before the run: already-connected. Failure injection.
	f.SetMeshLinkDown("node-a", "node-b", true)
	p, _ = admin.PlanTunnelReconnect(ctx, "node-b", "node-a")
	if _, res := submit(t, admin, ActionReconnectTunnel, 0, control.TunnelChange{Operation: "link-3", Plan: p}, rootFor(t, admin, ActionReconnectTunnel)); res.Code != ResultApplied {
		t.Fatalf("reconnect a-b %+v", res)
	}
	f.SetMeshLinkDown("node-a", "node-b", false)
	f.FinishTunnelReconnects()
	if s, _ = admin.TunnelReconnectStatus(ctx, "link-3"); s.State != "done" || s.Result.State != "already-connected" || !s.Result.KeptExisting || !s.Result.Valid(s.Plan) {
		t.Fatalf("already-connected %+v", s)
	}
	f.SetMeshLinkDown("node-a", "node-b", true)
	f.FailTunnelReconnect("node-a", "node-b", "dial-failed")
	p, _ = admin.PlanTunnelReconnect(ctx, "node-a", "node-b")
	if _, res := submit(t, admin, ActionReconnectTunnel, 0, control.TunnelChange{Operation: "link-4", Plan: p}, rootFor(t, admin, ActionReconnectTunnel)); res.Code != ResultApplied {
		t.Fatalf("reconnect fail %+v", res)
	}
	f.FinishTunnelReconnects()
	if s, _ = admin.TunnelReconnectStatus(ctx, "link-4"); s.State != "failed" || s.Result.Code != "dial-failed" || !s.Result.Valid(s.Plan) {
		t.Fatalf("failed %+v", s)
	}

	// A stale plan (observation older than 120 s) is refused.
	p, _ = admin.PlanTunnelReconnect(ctx, "node-a", "node-b")
	clk.add(3 * time.Minute)
	if _, res := submit(t, admin, ActionReconnectTunnel, 0, control.TunnelChange{Operation: "link-5", Plan: p}, rootFor(t, admin, ActionReconnectTunnel)); res.Code != ResultConditionFailed {
		t.Fatalf("stale plan %+v", res)
	}
}
