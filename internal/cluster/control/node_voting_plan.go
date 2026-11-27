// SPDX-License-Identifier: Apache-2.0

package control

import (
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/state"
)

type NodeVotingPlan struct {
	Schema                                                      uint8
	Node                                                        string
	Epoch, Expected, RootRevision, Index, ConfigurationIndex    uint64
	Demotable                                                   bool
	Blockers                                                    []NodeBlocker
	VotersBefore, VotersAfter, QuorumAfter, FaultToleranceAfter int
	PendingOperation                                            string `json:",omitempty"`
}

func nodeBlockerCode(blockers []NodeBlocker) state.Code {
	// Use one stable priority for read projections and retained rejections.
	for code := state.NodeLastVoter; code <= state.NodeStillResponding; code++ {
		for _, blocker := range blockers {
			if state.RejectionReason(code) == blocker.Code {
				return code
			}
		}
	}
	return state.Applied
}
func (p NodeVotingPlan) Rejection() state.Code { return nodeBlockerCode(p.Blockers) }

func (p Policy) PlanNodeDemotion(s state.State, session access.Session, at int64, node string) (NodeVotingPlan, error) {
	current, err := p.Current(s)
	if err != nil {
		return NodeVotingPlan{}, err
	}
	catalog, err := current.Catalog(s)
	if err != nil {
		return NodeVotingPlan{}, err
	}
	if !lifecycle.ValidID(node) || catalog.AuthorizeSession(session, p.Cluster, current.Issuer(session.Issuer), at, "", access.ManageCluster, "") != nil {
		return NodeVotingPlan{}, access.ErrDenied
	}
	return current.nodeVotingPlan(s, node)
}
func (p Policy) nodeVotingPlan(s state.State, node string) (NodeVotingPlan, error) {
	out := NodeVotingPlan{Schema: 1, Node: node, RootRevision: s.Object(MembersKey).Revision, Index: s.Index(), Blockers: []NodeBlocker{}}
	d, err := p.Members(s)
	if err != nil {
		return out, err
	}
	entry, found := d.Entry(node)
	if !found || !entry.Peer.Voter {
		return out, access.ErrInvalid
	}
	plan, err := d.PlanNodeChange(node, false)
	if err != nil {
		return out, err
	}
	out.Epoch, out.Expected, out.ConfigurationIndex = plan.Epoch, plan.Expected, plan.ConfigurationIndex
	out.VotersBefore, out.VotersAfter, out.QuorumAfter, out.FaultToleranceAfter = plan.VotersBefore, plan.VotersAfter, plan.QuorumAfter, plan.FaultToleranceAfter
	out.PendingOperation = plan.PendingOperation
	for _, code := range plan.Blockers {
		out.Blockers = append(out.Blockers, NodeBlocker{Code: code})
	}
	out.Demotable = len(out.Blockers) == 0
	return out, nil
}

// Voting effects keep the current account/role check next to the dispatch.
// Original signatures remain historical proof, not a fresh grant after revoke.
func (p Policy) CheckVotingEffect(s state.State, node string) error {
	d, err := p.Members(s)
	if err != nil {
		return err
	}
	entry, found := d.Entry(node)
	if !found || entry.Voting == nil {
		return ErrCatalog
	}
	var origin UserOperation
	if canonical(entry.Voting.Origin, &origin) != nil {
		return ErrCatalog
	}
	catalog, err := p.Catalog(s)
	if err != nil {
		return err
	}
	return catalog.AuthorizeAccepted(origin.Session, p.Cluster, origin.At, "", access.ManageCluster, "")
}
