// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"crypto/ed25519"
	"errors"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// MembersQuery selects one page of the member directory: the entries after
// the node ID After.
type MembersQuery struct {
	After string `json:",omitempty"`
}

func (q MembersQuery) Valid() bool { return q.After == "" || lifecycle.ValidID(q.After) }

// MembersReply is one page of at most eight member entries, all read at the
// same committed members root revision. A caller joining pages must reject a
// changed RootRevision.
type MembersReply struct {
	RootRevision       uint64
	RuntimeRevision    uint64 `json:",omitempty"`
	OperationEpoch     uint64 `json:",omitempty"`
	ConfigurationIndex uint64 `json:",omitempty"`
	Voters             int    `json:",omitempty"`
	Quorum             int    `json:",omitempty"`
	Members            []membership.Entry
	// Nodes are the runtime views of the page's members that have one.
	Nodes []membership.NodeView `json:",omitempty"`
	Next  string                `json:",omitempty"`
}

// NodeInvitationQuery names the registered server whose invitation to sign.
type NodeInvitationQuery struct{ Node string }

func (q NodeInvitationQuery) Valid() bool { return lifecycle.ValidID(q.Node) }

// MemberPage returns at most eight entries with the same committed root CAS.
func (c Client) MemberPage(ctx context.Context, target sfcp.Peer, session access.Session, after string) (MembersReply, error) {
	r, err := call(ctx, c, target, session, MembersMethod, MembersQuery{After: after})
	if err == nil && (len(r.Members) > 8 || r.Next != "" && (len(r.Members) != 8 || r.Next != r.Members[7].Peer.ID)) {
		return MembersReply{}, sfcp.ErrFrame
	}
	return r, err
}

func (c Client) NodeInvitation(ctx context.Context, target sfcp.Peer, session access.Session, node string) (membership.Invitation, error) {
	inv, err := call(ctx, c, target, session, NodeInvitationMethod, NodeInvitationQuery{Node: node})
	if err != nil {
		return membership.Invitation{}, err
	}
	err = c.verifyNodeInvitation(inv, node, nil)
	var untrusted *UntrustedSourceError
	if errors.As(err, &untrusted) {
		// The node the CLI talks to relays the request to the leader, which
		// signs as itself. That leader need not be pinned: the pinned node's
		// own member list vouches for it.
		var members []membership.Entry
		if members, err = c.memberEntry(ctx, target, session, inv.Source.ID); err == nil {
			err = c.verifyNodeInvitation(inv, node, members)
		}
	}
	if err != nil {
		return membership.Invitation{}, err
	}
	return inv, nil
}

// memberEntry pages the member list of target (a pinned node) up to the
// entry for id. It returns that one entry, or none.
func (c Client) memberEntry(ctx context.Context, target sfcp.Peer, session access.Session, id string) ([]membership.Entry, error) {
	after := ""
	for range 512 {
		page, err := c.MemberPage(ctx, target, session, after)
		if err != nil {
			return nil, err
		}
		for _, e := range page.Members {
			if e.Peer.ID == id {
				return []membership.Entry{e}, nil
			}
		}
		if page.Next == "" || page.Next <= after {
			return nil, nil
		}
		after = page.Next
	}
	return nil, nil
}

var (
	MembersMethod = define(Method[MembersQuery, MembersReply]{Name: "members"}, true, func(_ context.Context, s Service, view cluster.View, session access.Session, q MembersQuery) (MembersReply, string) {
		if !s.manageCluster(view, session) {
			return MembersReply{}, "denied"
		}
		d, err := s.Policy.Members(view.State)
		if err != nil {
			return MembersReply{}, "unavailable"
		}
		out := MembersReply{RootRevision: view.State.Object(control.MembersKey).Revision, Members: []membership.Entry{}}
		if topology, err := d.Topology(); err == nil {
			configuration := topology.Configuration()
			out.RuntimeRevision, out.OperationEpoch = topology.Revision(), topology.Epoch()
			out.ConfigurationIndex, out.Voters, out.Quorum = configuration.Index, configuration.Voters(), configuration.Quorum()
		}
		for _, entry := range d.Entries {
			if entry.Peer.ID <= q.After {
				continue
			}
			if len(out.Members) == 8 {
				out.Next = out.Members[len(out.Members)-1].Peer.ID
				break
			}
			out.Members = append(out.Members, entry)
			node, found := s.Policy.PublicNodeView(view.State, entry.Peer.ID)
			if !found {
				continue
			}
			if d.MemberKey(node.Node.Member.Key) {
				activity, err := s.Policy.NodeActivity(view.State, node.Node.Member.Key)
				if err != nil {
					return MembersReply{}, "unavailable"
				}
				node.SharedActivity = &activity
			}
			out.Nodes = append(out.Nodes, node)
		}
		return out, "ok"
	})
	// NodeInvitationMethod signs, as this voter, the invitation of a server
	// that is registered and has not finished joining.
	NodeInvitationMethod = define(Method[NodeInvitationQuery, membership.Invitation]{Name: "node-invitation"}, false, func(_ context.Context, s Service, view cluster.View, session access.Session, q NodeInvitationQuery) (membership.Invitation, string) {
		if !s.manageCluster(view, session) {
			return membership.Invitation{}, "denied"
		}
		d, err := s.Policy.Members(view.State)
		target, found := d.Entry(q.Node)
		var source config.Peer
		for _, entry := range d.Entries {
			if entry.CurrentPeer().Key == s.Self.Actor() && membership.FullMember(entry) {
				source = entry.Peer
			}
		}
		if err != nil || !found || target.Phase != membership.Invited && target.Phase != membership.Learner && target.Phase != membership.Ready || !source.Voter {
			return membership.Invitation{}, "denied"
		}
		inv := membership.Invitation{Schema: 1, Cluster: s.Policy.Cluster, Admin: s.Policy.BootstrapKey, Genesis: d.Genesis, Source: source, Target: target.Peer, JoinID: target.JoinID, ApprovalRevision: target.Job.Desired.Revision, MinimumIndex: view.RaftIndex}
		inv.Signature = ed25519.Sign(s.Self.Private, membership.InvitationBytes(inv))
		return inv, "ok"
	})
)
