// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/maintenance"
	"github.com/jay94ks/mydcd/internal/mydcp"
)

// This branch uses the real SDK/QUIC/Bolt fixture's installed three voters and
// retained fourth non-voter. It is adapter evidence, not user authorization or
// the future shared-job/CLI path. Existing fixture shutdown removes owned DBs,
// loopback sockets and snapshot directories; retention restores in the product.
func verifyManualCompactSDK(t *testing.T, ctx context.Context, nodes []realNode, leader int, wait func(string, func() bool), lookup func(mydcp.Identity) (mydcp.Peer, bool)) {
	t.Helper()
	lagger := &nodes[3]
	if err := lagger.engine.Close(); err != nil {
		t.Fatal(err)
	}
	lagger.engine = nil
	if err := lagger.mesh.Close(); err != nil {
		t.Fatal(err)
	}
	lagger.mesh = nil
	var last Committed
	for i := 0; i < 8; i++ {
		cmd := state.Command{Actor: nodes[0].identity.Actor(), Epoch: 1, RequestID: fmt.Sprintf("compact-source-%d", i), Key: fmt.Sprintf("workload/compact/source/%d", i), Value: "original-prefix"}
		committed, err := nodes[leader].engine.Submit(ctx, cmd)
		if err != nil || committed.Result.Code != state.Applied {
			t.Fatal("original source mutation", committed.Result, err)
		}
		last = committed
	}
	targets := make([]maintenance.CompactNode, 3)
	for i := range targets {
		targets[i] = maintenance.CompactNode{Node: fmt.Sprintf("node-%d", i+1), Key: nodes[i].identity.Public}
	}
	options := maintenance.CompactOptions{Mode: "minimal", Retain: 1}
	job, err := maintenance.NewCompactJob("sdk-compact-1", options, true, targets)
	if err != nil {
		t.Fatal("product maintenance target identifiers", err)
	}
	seen := map[string]bool{}
	for !job.Terminal() {
		_, currentLeader := nodes[leader].engine.Leader()
		id := "node-" + string(currentLeader)
		next := -1
		for i := 0; i < 3; i++ {
			if job.CanBegin(fmt.Sprintf("node-%d", i+1), id) {
				next = i
				break
			}
		}
		if next < 0 {
			t.Fatal("no original SDK target can advance")
		}
		node := nodes[next]
		nodeID := fmt.Sprintf("node-%d", next+1)
		if nodeID == id && len(seen) != 2 {
			t.Fatal("leader did not run last")
		}
		row, _ := job.Node(nodeID)
		job, err = job.Begin(nodeID, id, row.Revision)
		if err != nil {
			t.Fatal(err)
		}
		wait("target owns accepted source prefix", func() bool {
			v, err := node.engine.Read(ctx, false)
			return err == nil && v.RaftIndex >= last.RaftIndex && v.State.Object("workload/compact/source/7").Value == "original-prefix"
		})
		original := node.engine.raft.ReloadableConfig()
		saved := false
		result, err := node.engine.ManualCompact(ctx, job.Operation, last.RaftIndex, options, func(d maintenance.CompactDispatch) error {
			if d.Validate() != nil {
				return maintenance.ErrCompact
			}
			raw, _ := json.Marshal(d)
			if err := node.engine.db.Write(map[string][]byte{"maintenance/compact/original": raw}); err != nil {
				return err
			}
			saved = true
			return nil
		})
		if err != nil || !saved || result.Validate() != nil || !result.ConfigRestored || !result.TargetMet || result.After.SnapshotIndex < last.RaftIndex || node.engine.raft.ReloadableConfig() != original {
			t.Fatal("real SDK compaction/retention restore", result, err)
		}
		row, _ = job.Node(nodeID)
		job, err = job.Finish(nodeID, row.Revision, &result, "")
		if err != nil {
			t.Fatal(err)
		}
		seen[nodeID] = true
		// A private sync failure is observed before any next SDK call/config change.
		sentinel := errors.New("private-dispatch-sync-failed")
		_, err = node.engine.ManualCompact(ctx, "sync-rejected", last.RaftIndex, options, func(maintenance.CompactDispatch) error { return sentinel })
		if !errors.Is(err, sentinel) || node.engine.raft.ReloadableConfig() != original {
			t.Fatal("failed private sync dispatched or changed retention", err)
		}
	}
	failureSource, err := nodes[leader].engine.Submit(ctx, state.Command{Actor: nodes[0].identity.Actor(), Epoch: 1, RequestID: "compact-failure-source", Key: "workload/compact/failure-source", Value: "original-failure-prefix"})
	if err != nil || failureSource.Result.Code != state.Applied {
		t.Fatal("original new prefix before snapshot failure", failureSource.Result, err)
	}
	verifyCompactSnapshotFailure(t, ctx, nodes[leader].engine, failureSource.RaftIndex)
	// The retained, lagging node resumes its original DB. It must install the SDK
	// snapshot because its missing logs were compacted, not get a fabricated FSM.
	lagger.mesh, err = mydcp.NewTransport(lagger.identity, lagger.options.Cluster, lookup)
	if err != nil {
		t.Fatal("reopen original non-voter transport", err)
	}
	if err = lagger.mesh.Listen(lagger.address); err != nil {
		t.Fatal("bind original non-voter address", err)
	}
	lagger.options.Mesh = lagger.mesh
	lagger.engine, err = Open(lagger.options)
	if err != nil {
		t.Fatal(err)
	}
	if err = lagger.engine.ServeManagement(); err != nil {
		t.Fatal(err)
	}
	wait("lagging original node installs snapshot and catches up", func() bool {
		v, err := lagger.engine.Read(ctx, false)
		if err != nil || v.State.Object("workload/compact/source/7").Value != "original-prefix" {
			return false
		}
		m, err := lagger.engine.CompactMetrics()
		return err == nil && m.SnapshotKnown && m.SnapshotIndex >= last.RaftIndex
	})
	t.Log("scope: real three-voter SDK/QUIC/Bolt compaction, original lagging non-voter snapshot recovery, retention restoration; no user/shared-job claim")
}

func verifyCompactSnapshotFailure(t *testing.T, ctx context.Context, engine *Engine, minimum uint64) {
	t.Helper()
	before, err := engine.CompactMetrics()
	if err != nil {
		t.Fatal(err)
	}
	original := engine.raft.ReloadableConfig()
	path := filepath.Join(engine.root, "control", "snapshots")
	backup := path + ".owned-failure-baseline"
	// Inject only after ManualCompact's preflight metrics and original dispatch
	// sync. Otherwise ENOTDIR blocks preflight and never exercises SDK Create.
	backedUp := false
	defer func() {
		if !backedUp {
			return
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			t.Error(err)
		}
		if err := os.Rename(backup, path); err != nil {
			t.Error(err)
		}
	}()
	result, runErr := engine.ManualCompact(ctx, "sdk-snapshot-store-failure", minimum, maintenance.CompactOptions{Mode: "minimal", Retain: 1}, func(d maintenance.CompactDispatch) error {
		raw, err := json.Marshal(d)
		if err != nil {
			return err
		}
		if err = engine.db.Write(map[string][]byte{"maintenance/compact/original-failure": raw}); err != nil {
			return err
		}
		if err = os.Rename(path, backup); err != nil {
			return err
		}
		backedUp = true
		return os.WriteFile(path, []byte("owned snapshot write failure"), 0600)
	})
	if runErr == nil || !backedUp || !errors.Is(runErr, syscall.ENOTDIR) || result.Validate() != nil || result.Dispatch.MinimumIndex != minimum || result.ErrorCode != "snapshot-failed" || !result.ConfigRestored || engine.raft.ReloadableConfig() != original {
		t.Fatal("SDK snapshot-store failure not preserved", result, runErr)
	}
	first, firstErr := engine.log.FirstIndex()
	last, lastErr := engine.log.LastIndex()
	if firstErr != nil || lastErr != nil || first != before.FirstIndex || last != before.LastIndex {
		t.Fatal("snapshot creation failure deleted original logs", firstErr, lastErr)
	}
}

func TestCompactClassifiesDiskFullWithoutDroppingOriginalFailure(t *testing.T) {
	err := fmt.Errorf("create original snapshot: %w", syscall.ENOSPC)
	if compactErrorCode(err) != "disk-full" || compactErrorText(err) == "" {
		t.Fatal("disk-full diagnosis lost")
	}
}
