// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/identity"
)

// Leader no-ops and the one read barrier per term commit entries the FSM
// never sees. The applied position must follow them instead of staying at
// the last state command, before and after a voter restarts (KVM: APPLIED
// 305 vs commit 711). Latest reads no longer write (R14), so an idle cluster's
// commit index must then stay where it is.
func TestTwoVoterAppliedFollowsIdleCommitsAcrossRestart(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	root := t.TempDir()
	admin, err := identity.Create(filepath.Join(root, "admin"))
	if err != nil {
		t.Fatal(err)
	}
	m := newManagedVoters(t, ctx, filepath.Join(root, "cluster"), admin, 2)
	put := func(i int, id string) {
		m.Change(i, "put-"+id, "put-user", 0, access.User{ID: id, Username: id, Enabled: true})
	}
	put(0, "u-before")
	check := func(label string) {
		t.Helper()
		durable := map[int]uint64{}
		for i, n := range m.Nodes {
			v, err := n.Engine().Read(ctx, false)
			if err != nil {
				t.Fatal(label, err)
			}
			durable[i] = v.RaftIndex
		}
		// Applied reaches the commit index, which covers the durable state
		// position, even when the newest entries are no-ops or barriers.
		m.wait(label, func() bool {
			for i, n := range m.Nodes {
				c, err := n.Engine().ConsensusObservation(ctx)
				if err != nil || c.CommitIndex < durable[i] || c.AppliedIndex+1 < c.CommitIndex {
					return false
				}
			}
			return true
		})
		// Asked through either voter, a healthy cluster is not reported as
		// stale: a follower counts itself and the leader it hears from.
		m.wait(label+": status through every voter", func() bool {
			for i := range m.Nodes {
				reply, err := m.client.RaftStatusPage(ctx, m.Peer(i), m.session, "")
				if err != nil || reply.RaftStatus == nil || reply.RaftStatus.Stale || reply.RaftStatus.RespondingVoters != 2 {
					return false
				}
			}
			return true
		})
		// A follower learns the commit index on the next heartbeat, so the
		// newest commit is the highest one any voter has seen.
		var commit uint64
		for i, n := range m.Nodes {
			c, _ := n.Engine().ConsensusObservation(ctx)
			if c.SnapshotKnown && c.SnapshotIndex > c.AppliedIndex {
				t.Fatal(label, "applied below snapshot", i, c.AppliedIndex, c.SnapshotIndex)
			}
			commit = max(commit, c.CommitIndex)
		}
		// Status pages and managed passes above used latest reads; none of
		// them may have written. Give the passes time to run again.
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(3 * time.Second):
		}
		for i, n := range m.Nodes {
			c, err := n.Engine().ConsensusObservation(ctx)
			if err != nil || c.CommitIndex != commit {
				t.Fatal(label, "idle cluster committed", i, commit, c.CommitIndex, err)
			}
		}
	}
	check("idle before restart")
	for round, restart := range []int{0, 1} {
		if err = m.Nodes[restart].Close(); err != nil {
			t.Fatal(err)
		}
		if m.Nodes[restart], err = Open(m.Configs[restart]); err != nil {
			t.Fatal(err)
		}
		m.wait("leader after restart", func() bool {
			for _, n := range m.Nodes {
				if n.Engine().IsLeader() {
					if _, err := n.Engine().Read(ctx, true); err == nil {
						return true
					}
				}
			}
			return false
		})
		put(restart, fmt.Sprintf("u-after-%d", round))
		check(fmt.Sprintf("idle after restart %d", round))
	}
}
