// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/userauth"
)

// Reuses the owned Docker/CLI fixture. Only its private cluster is changed:
// two added control voters, original DB close/reopen and original leadership
// restoration. No foreign process, host configuration or disk capacity changes.
func verifyManualCompactUserNative(t *testing.T, ctx context.Context, source, second *Runtime, root string, client userauth.Client, peer mydcp.Peer, session access.Session, policy control.Policy, change func(string, string, uint64, any)) []*Runtime {
	t.Helper()
	var third *Runtime
	read := func() cluster.View {
		t.Helper()
		for {
			for _, node := range []*Runtime{source, second, third} {
				if node != nil && node.Engine().IsLeader() {
					if v, err := node.Engine().Read(ctx, true); err == nil {
						return v
					}
				}
			}
			select {
			case <-ctx.Done():
				t.Fatal("original compact cluster quorum", ctx.Err())
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	third = prepareManagedHandoffControl(t, ctx, root, source, client, peer, session, policy, read, change, "node-d")
	secondConfig, thirdConfig := second.installation.config, third.installation.config
	// Always reopen the exact same databases before fixture retirement/cleanup.
	// Open creates no new cluster, node identity, membership or accepted job.
	reopen := func() error {
		if second == nil {
			r, err := Open(secondConfig)
			if err != nil {
				return err
			}
			second = r
			t.Cleanup(func() {
				if err := r.Close(); err != nil {
					t.Error(err)
				}
			})
		}
		if third == nil {
			r, err := Open(thirdConfig)
			if err != nil {
				return err
			}
			third = r
			t.Cleanup(func() {
				if err := r.Close(); err != nil {
					t.Error(err)
				}
			})
		}
		return nil
	}
	defer func() {
		if err := reopen(); err != nil {
			t.Error("restore original control databases", err)
			return
		}
		clean, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		for {
			if source.Engine().IsLeader() {
				if _, err := source.Engine().Read(clean, true); err == nil {
					return
				}
			}
			for _, node := range []*Runtime{second, third} {
				if node.Engine().IsLeader() {
					_ = node.Engine().TransferLeadership(clean, peer.ID, peer.Endpoint)
					break
				}
			}
			select {
			case <-clean.Done():
				t.Error("restore fixture control leadership", clean.Err())
				return
			case <-time.After(20 * time.Millisecond):
			}
		}
	}()
	if os.Getenv("MYDC_TEST_RQ4_TUNNEL_USER") == "1" {
		verifyTunnelReconnectUserNative(t, ctx, source, second, &third, root, client, peer, session, reopen, read)
		return []*Runtime{second, third}
	}
	run := func(args ...string) []byte {
		t.Helper()
		out, diag, err := runManagedCLICommand(ctx, os.Getenv("MYDC_TEST_CLI"), filepath.Join(root, "cli-home"), filepath.Join(root, "cli.yaml"), args, nil)
		if err != nil {
			t.Fatal("real compact CLI", args, err, string(diag))
		}
		return out
	}
	waitJob := func(operation string) control.CompactStatusPage {
		t.Helper()
		for {
			reply, err := client.CompactStatus(ctx, peer, session, control.CompactQuery{Operation: operation})
			if err == nil && reply.CompactStatus != nil && reply.CompactStatus.Summary.Complete {
				return *reply.CompactStatus
			}
			select {
			case <-ctx.Done():
				t.Fatal("original compact job did not settle", operation, err, ctx.Err())
			case <-time.After(40 * time.Millisecond):
			}
		}
	}
	var plan control.CompactPlan
	if json.Unmarshal(run("raft", "compact", "--preview", "--mode", "minimal", "--retain", "1000"), &plan) != nil || !plan.Valid() || len(plan.Nodes) != 3 {
		t.Fatal("actual three-voter default plan")
	}
	before := map[string]uint64{}
	for _, node := range []*Runtime{source, second, third} {
		obs, err := node.Engine().ConsensusObservation(ctx)
		if err != nil {
			t.Fatal(err)
		}
		before[node.Engine().ObservedNodeID()] = obs.TrailingLogs
	}
	args := []string{"raft", "compact", "--operation", "rq4-user-compact", "--request-id", "rq4-user-compact-request", "--mode", "minimal", "--retain", "1000"}
	run(args...)
	// Normal management traffic remains usable while the original job advances.
	change("rq4-compact-live-tenant", "create-tenant", 0, control.TenantID{ID: "compact-live"})
	job := waitJob("rq4-user-compact")
	if job.Next != "" || len(job.Nodes) != 3 || job.Summary.Done != 3 || job.Summary.User != session.User {
		t.Fatal("shared actual three-voter completion", job.Summary)
	}
	for _, node := range job.Nodes {
		if node.State != "done" || node.Result == nil || !node.Result.ConfigRestored || !node.Result.TargetMet || node.Result.After.SnapshotIndex < node.Result.Dispatch.MinimumIndex || node.Result.After.LogEntries > node.Result.Dispatch.EffectiveTrailing {
			t.Fatal("actual SDK result missing from original owner", node.Node)
		}
	}
	for _, node := range []*Runtime{source, second, third} {
		obs, err := node.Engine().ConsensusObservation(ctx)
		if err != nil || obs.TrailingLogs != before[node.Engine().ObservedNodeID()] {
			t.Fatal("retention not restored", err)
		}
	}
	run(args...) // original durable CLI journal/result, no new SDK snapshot
	jobs, err := policy.Compactions(read().State)
	if err != nil || len(jobs.Records) != 1 {
		t.Fatal("original compact replay created another job", err)
	}
	status, err := client.RaftStatus(ctx, peer, session)
	if err != nil || status.RaftStatus == nil || status.RaftStatus.LastManualCompact == nil || status.RaftStatus.LastManualCompact.Operation != job.Summary.Operation {
		t.Fatal("last manual compact diagnostics", err)
	}
	for _, node := range status.RaftStatus.Nodes {
		if node.LastManualCompact == nil || node.LastManualCompact.State != "done" {
			t.Fatal("per-node last original result missing", node.Node)
		}
	}
	// A genuine non-administrator login cannot plan or directly sign this action.
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	viewer, err := (access.User{ID: "compact-viewer", Username: "compact-viewer", Enabled: true}).WithPrivateKey("reader-key", [32]byte(pub))
	if err != nil {
		t.Fatal(err)
	}
	change("rq4-compact-viewer", "put-user", 0, viewer)
	viewerSession, err := client.Login(ctx, peer, viewer.Username, private)
	if err != nil {
		t.Fatal(err)
	}
	assertDenied := func(err error) {
		t.Helper()
		var denied *userauth.Error
		if !errors.As(err, &denied) || denied.Code != "denied" {
			t.Fatal("expected explicit non-admin denial", err)
		}
	}
	_, err = client.CompactPlan(ctx, peer, viewerSession, plan.Selection)
	assertDenied(err)
	payload, _ := json.Marshal(control.CompactChange{Operation: "rq4-viewer-denied", Selection: plan.Selection, Target: plan.Target})
	op, err := client.Prepare(ctx, peer, viewerSession, "rq4-viewer-request", control.Change{Schema: 1, Principal: viewer.ID, Action: "raft-compact", Payload: payload})
	if err == nil {
		reply, operationErr := client.Operation(ctx, peer, op, false)
		if reply.Result == nil || reply.Result.Code != state.Forbidden {
			assertDenied(operationErr)
		}
	} else {
		assertDenied(err)
	}
	// Close only this fixture's third voter, preserving its DB/keys/configuration.
	if err := third.Close(); err != nil {
		t.Fatal(err)
	}
	third = nil
	run("raft", "compact", "--operation", "rq4-unreachable-compact", "--request-id", "rq4-unreachable-request", "--mode", "minimal", "--retain", "1000")
	skipped := waitJob("rq4-unreachable-compact")
	if skipped.Summary.Skipped != 1 || skipped.Summary.Done != 2 {
		t.Fatal("unreachable target blocked remaining voters", skipped.Summary)
	}
	// Prepare once while quorum exists, then attempt that exact signed intent
	// without quorum. It is not automatically re-submitted after recovery.
	selection := control.CompactSelection{Mode: "keep"}
	current, err := client.CompactPlan(ctx, peer, session, selection)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ = json.Marshal(control.CompactChange{Operation: "rq4-quorum-unknown", Selection: selection, Target: current.Target})
	op, err = client.Prepare(ctx, peer, session, "rq4-quorum-unknown-request", control.Change{Schema: 1, Principal: session.User, Action: "raft-compact", Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = userauth.StageOperation(filepath.Join(root, "cli-home"), client, op); err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	second = nil
	for source.Engine().IsLeader() {
		select {
		case <-ctx.Done():
			t.Fatal("isolated leader did not step down", ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	isolated, cancel := context.WithTimeout(ctx, 3*time.Second)
	reply, callErr := client.Operation(isolated, peer, op, false)
	cancel()
	if reply.Result != nil && reply.Result.Code == state.Applied || callErr == nil && reply.Code == "ok" {
		t.Fatal("isolated voter accepted maintenance")
	}
	if err := reopen(); err != nil {
		t.Fatal(err)
	}
	read() // actual SDK election/read barrier, not just Open success
	jobs, err = policy.Compactions(read().State)
	if err != nil {
		t.Fatal(err)
	}
	if _, accepted := jobs.Record("rq4-quorum-unknown"); accepted {
		t.Fatal("quorum-less original unexpectedly committed")
	}
	t.Log("scope: actual MYDCP User/CLI, shared three-voter SDK results, continuing management, non-admin denial, queued unreachable skip, quorum denial, original DB reopen and leadership rollback; lagging snapshot recovery is the separate SDK branch")
	return []*Runtime{second, third}
}
