// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"context"
	"crypto/ed25519"
	"slices"

	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/config"
)

// Node join in the fake: only node-invitation for a fixture member still
// joining, signed with the leader's fixture key. Invite, join and promote
// are tested on real sfcd (real_node_join_test.go).

func fakePeer(m FixtureMember) config.Peer {
	return config.Peer{ID: m.ID, Key: m.Key, Endpoint: m.Endpoint, Voter: m.Voter}
}

func (w *world) member(id string) int {
	return slices.IndexFunc(w.members, func(m FixtureMember) bool { return m.ID == id })
}

func (c *fakeConn) NodeInvitation(ctx context.Context, node string) (NodeInvitation, error) {
	const m = "node-invitation"
	if !lifecycle.ValidID(node) {
		return NodeInvitation{}, fail(m, CodeInvalid, "node")
	}
	if err := c.adminOnly(ctx, m); err != nil {
		return NodeInvitation{}, err
	}
	defer c.unlock()
	w := c.f.w
	i, src := w.member(node), w.member(w.raft.Leader)
	if i < 0 || src < 0 || !slices.Contains([]string{JoinInvited, JoinLearner, JoinReady}, w.members[i].Join) {
		return NodeInvitation{}, fail(m, CodeDenied, "")
	}
	inv := NodeInvitation{Schema: 1, Cluster: w.cluster, Admin: [32]byte(FixtureKey("bootstrap").Public().(ed25519.PublicKey)),
		Genesis: fakePeer(w.members[0]), Source: fakePeer(w.members[src]), Target: fakePeer(w.members[i]),
		JoinID: w.members[i].JoinID, ApprovalRevision: w.members[i].Revision, MinimumIndex: max(1, w.raft.CommitIndex)}
	inv.Signature = ed25519.Sign(FixtureKey(w.members[src].ID), membership.InvitationBytes(inv))
	return inv, nil
}

// loadMembers gives the fixture members a join phase: pending non-voters
// are invited, the rest full members.
func (w *world) loadMembers() {
	w.members = slices.Clone(w.members)
	for i := range w.members {
		switch m := &w.members[i]; {
		case m.Join != "":
		case m.Phase == NodePhasePending && !m.Voter:
			m.Join = JoinInvited // an invitation not yet joined
		default:
			m.Join = JoinActive
		}
	}
}
