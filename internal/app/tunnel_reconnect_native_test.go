// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/observability"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
)

// The existing fixture owns three voters, CLI credentials, original DBs and
// rollback. It closes only its third voter, preserves quorum and reopens the
// same DB/identity before the accepted owner job is allowed to run.
func verifyTunnelReconnectUserNative(t *testing.T, ctx context.Context, source, second *Runtime, third **Runtime, root string, c userauth.Client, peer sfcp.Peer, session access.Session, reopen func() error, read func() cluster.View) {
	t.Helper()
	target := *third
	member, known := source.Mesh.Peer(sfcp.Identity(target.Identity.Public))
	if !known {
		t.Fatal("installed third peer missing")
	}
	if _, err := source.Mesh.Dial(ctx, member); err != nil {
		t.Fatal("original healthy link baseline", err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	*third = nil
	for {
		link, known := source.Mesh.LinkObservation(peer.ID, member)
		if known && link.State == "down" {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("last owned member path did not close", ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	read() // latest quorum barrier; measurements still name the owner's prefix
	v, err := source.Engine().Read(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := source.collectNodeObservations(ctx, v)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, raw := range rows {
		report, err := observability.Decode(raw)
		if err != nil {
			t.Fatal(err)
		}
		if report.Link == nil || report.Link.Peer != member.ID || report.Link.State != "down" {
			continue
		}
		found = true
		if err := source.storeNodeObservation(sfcp.Identity(source.Identity.Public), raw); err != nil {
			t.Fatal(err)
		}
		other, known := source.Mesh.Peer(sfcp.Identity(second.Identity.Public))
		if !known {
			t.Fatal("other control missing")
		}
		conn, err := source.Mesh.Dial(ctx, other)
		if err != nil {
			t.Fatal(err)
		}
		if err = conn.Report(ctx, sfcp.KindNodeObservation, raw); err != nil {
			t.Fatal("actual signed down observation relay", err)
		}
	}
	if !found {
		t.Fatal("actual down PairID not captured")
	}
	run := func(args ...string) []byte {
		t.Helper()
		out, diag, err := runManagedCLICommand(ctx, os.Getenv("SFC_TEST_CLI"), filepath.Join(root, "cli-home"), filepath.Join(root, "cli.yaml"), args, nil)
		if err != nil {
			t.Fatal("real tunnel CLI", args, err, string(diag))
		}
		return out
	}
	var plan control.TunnelPlan
	if json.Unmarshal(run("mesh", "reconnect", "--node", peer.ID, "--peer", member.ID, "--preview"), &plan) != nil || !plan.Valid() || plan.PairID != observability.PairID(peer.ID, member.ID) {
		t.Fatal("actual broken-link plan")
	}
	// Hold only this fixture's scheduler slot. No result/handshake/Ready state
	// is injected, and no production-only test hook or retry executor is added.
	source.tunnelJob.mu.Lock()
	if source.tunnelJob.busy {
		source.tunnelJob.mu.Unlock()
		t.Fatal("unexpected pending tunnel job")
	}
	source.tunnelJob.busy = true
	source.tunnelJob.mu.Unlock()
	held := true
	release := func() {
		if held {
			source.tunnelJob.mu.Lock()
			source.tunnelJob.busy = false
			source.tunnelJob.mu.Unlock()
			held = false
		}
	}
	defer release()
	args := []string{"mesh", "reconnect", "--node", peer.ID, "--peer", member.ID, "--operation", "rq4-native-link", "--request-id", "rq4-native-link-request"}
	run(args...)
	queued, err := c.TunnelReconnectStatus(ctx, peer, session, "rq4-native-link")
	if err != nil || queued.State != "queued" {
		t.Fatal("accepted original not durably queued", err)
	}
	accepted := queued.Plan
	if accepted.Node != plan.Node || accepted.Peer != plan.Peer || accepted.Owner != plan.Owner || accepted.PeerKey != plan.PeerKey || accepted.Endpoint != plan.Endpoint {
		t.Fatal("accepted reconnect changed preview node identities")
	}
	plan = accepted // incidental signed observation timestamps may advance
	if err := reopen(); err != nil {
		t.Fatal("reopen original peer before owner action", err)
	}
	release()
	var status *control.TunnelStatus
	for {
		reply, e := c.TunnelReconnectStatus(ctx, peer, session, "rq4-native-link")
		if e == nil && (reply.State == "done" || reply.State == "failed") {
			status = &reply
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("accepted tunnel action not settled", e, ctx.Err())
		case <-time.After(40 * time.Millisecond):
		}
	}
	if status.State != "done" || status.Result == nil || !status.Result.Valid(plan) || status.Plan.Target != plan.Target {
		t.Fatal("actual original reconnect did not produce positive handshake", status)
	}
	actual, known := source.Mesh.LinkObservation(peer.ID, member)
	if !known || actual.State == "down" || actual.ID != status.Result.PairID || actual.LastHandshakeAt < status.Result.HandshakeAt {
		t.Fatal("owner report differs from actual transport")
	}
	run(args...) // old down plan is intentionally stale/up now; journal wins
	jobs, err := source.controlPolicy.TunnelReconnections(read().State)
	if err != nil || len(jobs.Records) != 1 {
		t.Fatal("original replay created a new reconnect", err)
	}
	run("mesh", "reconnect-status", "rq4-native-link")
	t.Log("scope: actual three-voter User/CLI, signed down report through SFCP Report, original peer DB reopen, queued owner scheduling, authenticated recovery/already-connected result and original replay; raw transport branch separately proves surviving path preservation")
}
