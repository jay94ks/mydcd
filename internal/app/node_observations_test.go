// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/observability"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
)

// Real authenticated two-voter Raft/DB/QUIC, actual host statfs/CPU and current
// user queries. Native Task effects are tested separately, never synthesized.
func TestRQ3TwoNodeSignedObservationsSnapshotAndQuorumLoss(t *testing.T) {
	testRealManagedJoin(t, false, "observations")
}

func verifyTwoNodeObservations(t *testing.T, ctx context.Context, a, b *Runtime, client userauth.Client, session access.Session, ap, bp sfcp.Peer, p control.Policy, submit func(string, string, uint64, any), wait func(string, func() bool)) {
	t.Helper()
	// No native adapters are enabled. These tenants exercise scope without
	// creating Docker, routing, firewall or TUN resources.
	for _, tenant := range []string{"first", "second"} {
		submit("observation-tenant-"+tenant, "create-tenant", 0, control.TenantID{ID: tenant})
		view, e := a.Engine().Read(ctx, true)
		if e != nil {
			t.Fatal(e)
		}
		catalog, e := p.Catalog(view.State)
		if e != nil {
			t.Fatal(e)
		}
		tenantView, _ := catalog.Tenant(tenant)
		nodes := []string{"node-a"}
		if tenant == "second" {
			nodes = []string{"node-b"}
		}
		submit("observation-nodes-"+tenant, "set-nodes", tenantView.Revision, control.NodeChangeTo(tenant, tenantView.AllowedNodes, nodes))
	}
	// Use the same key for two accounts only inside this fixture. The account
	// identity and signed session scopes, not key equality, must isolate them.
	submit("observation-reader", "put-user", 0, access.User{ID: "reader", Username: "reader", Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: client.Self.Public, Enabled: true}}})
	submit("observation-membership", "set-membership", 0, access.Membership{Tenant: "first", User: "reader", Role: access.Viewer, Enabled: true})
	reader, e := client.Login(ctx, ap, "reader", client.Self.Private)
	if e != nil {
		t.Fatal(e)
	}
	floor, e := a.Engine().Read(ctx, true)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = b.Engine().ReadAtLeast(ctx, floor.State.Index()); e != nil {
		t.Fatal(e)
	}
	// Measure twice for an actual CPU delta, and send exact signed bytes through
	// Session.Report. No test-only write bypass is used at the receiving node.
	collect := func(r *Runtime, target sfcp.Peer) {
		t.Helper()
		view, e := r.Engine().Read(ctx, false)
		if e != nil {
			t.Fatal(e)
		}
		reports, e := r.collectNodeObservations(ctx, view)
		if e != nil {
			t.Fatal(e)
		}
		link, e := r.Mesh.Dial(ctx, target)
		if e != nil {
			t.Fatal(e)
		}
		for _, raw := range reports {
			if e = r.storeNodeObservation(sfcp.Identity(r.Identity.Public), raw); e != nil {
				t.Fatal("local report", e)
			}
			if e = link.Report(ctx, sfcp.KindNodeObservation, raw); e != nil {
				t.Fatal("authenticated remote report", e)
			}
		}
	}
	collect(a, bp)
	collect(b, ap)
	timer := time.NewTimer(20 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	collect(a, bp)
	collect(b, ap)
	summary, e := client.NodeSummary(ctx, ap, session, userauth.NodeObservationQuery{})
	if e != nil || len(summary.Nodes) != 2 {
		t.Fatal("admin two nodes", e, summary)
	}
	for _, node := range summary.Nodes {
		if node.Admin == nil || node.Stale || node.ObserveLimitSeconds != observability.MaxAge/1000 || node.ObservationMaxAge != observability.MaxAge || node.State == "unreachable" {
			t.Fatalf("real node observation unavailable: %+v", node)
		}
	}
	scoped, e := client.NodeSummary(ctx, ap, reader, userauth.NodeObservationQuery{Tenant: "first"})
	if e != nil || len(scoped.Nodes) != 1 || scoped.Nodes[0].Node != "node-a" || scoped.Nodes[0].Admin != nil {
		t.Fatal("tenant node visibility", e, scoped)
	}
	raw, _ := json.Marshal(scoped)
	for _, forbidden := range []string{"node-b", "second", ap.Endpoint, bp.Endpoint} {
		if forbidden != "" && bytes.Contains(raw, []byte(forbidden)) {
			t.Fatal("hidden node/tenant/address in tenant response", forbidden)
		}
	}
	if _, e = client.NodeSummary(ctx, ap, reader, userauth.NodeObservationQuery{Tenant: "first", Node: "node-b"}); e == nil {
		t.Fatal("explicit hidden node selector accepted")
	}
	disks, e := client.NodeDisks(ctx, ap, session, userauth.NodeObservationQuery{Node: "node-a"})
	if e != nil || len(disks.Disks) == 0 {
		t.Fatal("actual system statfs", e)
	}
	for _, disk := range disks.Disks {
		if disk.Total == nil || *disk.Total == 0 || disk.Stale {
			t.Fatal("unknown/fake disk", disk)
		}
	}
	mesh, e := client.MeshLinks(ctx, ap, session, userauth.NodeObservationQuery{})
	if e != nil || len(mesh.Links) != 1 || mesh.Links[0].ID != observability.PairID("node-a", "node-b") || len(mesh.Links[0].Ends) != 2 {
		t.Fatal("actual two-ended Mesh pair", e, mesh)
	}
	wait("actual leader replication match", func() bool {
		reply, e := client.RaftStatus(ctx, ap, session)
		if e != nil || reply.RaftStatus == nil || reply.RaftStatus.Stale || reply.RaftStatus.Voters != 2 || reply.RaftStatus.RespondingVoters != 2 {
			return false
		}
		for _, node := range reply.RaftStatus.Nodes {
			if node.Node == "node-b" {
				return node.MatchIndex != nil && *node.MatchIndex > 0
			}
		}
		return false
	})
	if e = a.Engine().Snapshot(ctx); e != nil {
		t.Fatal("actual snapshot", e)
	}
	status, e := client.RaftStatus(ctx, ap, session)
	if e != nil || status.RaftStatus == nil || !status.RaftStatus.Local.SnapshotKnown || status.RaftStatus.Local.SnapshotIndex == 0 || status.RaftStatus.Local.SnapshotBytes == 0 {
		t.Fatal("actual snapshot metrics", e)
	}
	if _, e = client.RaftStatus(ctx, ap, reader); e == nil {
		t.Fatal("tenant reader received cluster consensus data")
	}
	// Positive shutdown of the second voter loses quorum. A new proof challenge
	// on the remaining node must still return locally authorized stale state.
	if e = b.Close(); e != nil {
		t.Fatal(e)
	}
	wait("stale consensus after actual quorum loss", func() bool {
		call, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		reply, e := client.RaftStatus(call, ap, session)
		return e == nil && reply.RaftStatus != nil && reply.RaftStatus.Stale && reply.RaftStatus.LocalLastAppliedAuthorization && reply.RaftStatus.ObservedBy == "node-a" && reply.RaftStatus.Voters == 2
	})
	t.Log("two actual voters: signed OS observations over SFCP, tenant filtering, statfs, both Mesh ends, acknowledged Raft prefix, actual snapshot, and quorum-loss local authenticated stale query")
}
