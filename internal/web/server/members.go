// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"

	"github.com/jay94ks/mydcd/internal/cluster/membership"
	"github.com/jay94ks/mydcd/internal/web/mydc"
)

// memberView: one /nodes row, the screen's merge of a `members` entry
// (membership.Entry) and its lifecycle row (membership.NodeView, same ID).
// A server that is still joining (invited, learner, ready, promoting) has
// no lifecycle row yet: phase "pending", no scheduling or admitsWork.
//
// Revisions, each the Expected of its own change: revision is the
// lifecycle row's (isolate / restore / remove / rotate-identity; the
// entry's while joining), joinRevision the entry's (promote-node), and
// scheduling.revision the cordon's (cordon / uncordon).
type memberView struct {
	ID           string
	Key          string
	Endpoint     string
	JoinID       string
	Revision     uint64
	JoinRevision uint64
	Phase        string
	Voter        bool
	AdmitsWork   bool
	Cordoned     bool
	CordonedBy   string                 `json:",omitempty"`
	CordonedAt   string                 `json:",omitempty"`
	CordonReason string                 `json:",omitempty"` // the cordon-node original's note
	Scheduling   *membership.CordonView `json:",omitempty"`
	// PendingOperation: the lifecycle row's unfinished node operation.
	PendingOperation string `json:",omitempty"`
	// Identity: the latest identity rotation (operation, phase: Preparing
	// → Prepared → Activated → Installed, failure?).
	// IdentityRotatedAt repeats identity.requestedAt.
	Identity          *memberIdentity `json:",omitempty"`
	IdentityRotatedAt string          `json:",omitempty"`
	// Join: the membership phase (invited → learner → ready → promoting →
	// active).
	Join string
}

type memberIdentity struct {
	Operation string
	Phase     string
	Failure   string `json:",omitempty"`
	// RequestedAt: when the rotation was asked for (UTC RFC 3339).
	RequestedAt string `json:",omitempty"`
}

func newMemberView(e membership.Entry, v *membership.NodeView) memberView {
	m := memberView{ID: e.Peer.ID, Key: e.Peer.Key, Endpoint: e.Peer.Endpoint, JoinID: e.JoinID, Revision: e.Revision, JoinRevision: e.Revision,
		Phase: mydc.NodePhasePending, Voter: e.Peer.Voter, Join: string(e.Phase)}
	if v != nil {
		sch := v.Scheduling
		m.Revision, m.Phase, m.Voter, m.AdmitsWork, m.Scheduling = v.Node.Revision, string(v.Node.Phase), v.Node.Member.Voter, v.AdmitsWork, &sch
		m.Cordoned, m.CordonedBy, m.CordonedAt, m.CordonReason = sch.Enabled, sch.CordonedBy, sch.CordonedAt, sch.Reason
		if r := v.Identity; r != nil {
			m.Identity = &memberIdentity{Operation: r.Operation, Phase: r.Phase, Failure: r.Failure, RequestedAt: r.RequestedAt}
			m.IdentityRotatedAt = r.RequestedAt
		}
		if v.Node.Pending != nil {
			m.PendingOperation = v.Node.Pending.ID
		}
	}
	return m
}

// memberViews: the page's entries in order, each with its lifecycle row.
func memberViews(p mydc.MembersPage) []memberView {
	nodes := make(map[string]*membership.NodeView, len(p.Nodes))
	for i := range p.Nodes {
		nodes[p.Nodes[i].Node.Member.ID] = &p.Nodes[i]
	}
	out := make([]memberView, 0, len(p.Entries))
	for _, e := range p.Entries {
		out = append(out, newMemberView(e, nodes[e.Peer.ID]))
	}
	return out
}

// membersMaxPages bounds one walk of `members` (8 servers a page).
const membersMaxPages = 256

// eachMember walks every members page until fn says stop. It reads at most
// membersMaxPages pages and stops early if mydcd hands back a cursor that
// does not move forward (a backend fault, not an endless loop).
func eachMember(ctx context.Context, c mydc.Conn, fn func(memberView, mydc.MembersPage) bool) error {
	after := ""
	for range membersMaxPages {
		p, err := c.Members(ctx, after)
		if err != nil {
			return err
		}
		for _, m := range memberViews(p) {
			if !fn(m, p) {
				return nil
			}
		}
		if p.Next == "" || p.Next <= after {
			return nil
		}
		after = p.Next
	}
	return nil
}

// findMemberEpoch: the server's row (nil when there is none) and the node
// operation epoch of the members page it came from (remove-node's Epoch).
func findMemberEpoch(ctx context.Context, c mydc.Conn, id string) (*memberView, uint64, error) {
	var found *memberView
	var epoch uint64
	err := eachMember(ctx, c, func(m memberView, p mydc.MembersPage) bool {
		if m.ID == id {
			found, epoch = &m, p.NodeOperationEpoch
			return false
		}
		return true
	})
	return found, epoch, err
}

func findMember(ctx context.Context, c mydc.Conn, id string) (*memberView, error) {
	m, _, err := findMemberEpoch(ctx, c, id)
	return m, err
}

// cordonRevision: cordon / uncordon's Expected (the scheduling row's).
func (m memberView) cordonRevision() uint64 {
	if m.Scheduling != nil {
		return m.Scheduling.Revision
	}
	return m.Revision
}
