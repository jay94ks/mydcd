// SPDX-License-Identifier: Apache-2.0

package membership

import "github.com/jay94ks/mydcd/internal/cluster/lifecycle"

// NodeChangePlan describes only committed membership/lifecycle facts. It is
// shared by admission and public plans; network silence is not a committed fact
// and never stands in for closure or an SDK configuration change.
type NodeChangePlan struct {
	Epoch, Expected, ConfigurationIndex                         uint64
	VotersBefore, VotersAfter, QuorumAfter, FaultToleranceAfter int
	PendingOperation                                            string
	Blockers                                                    []string
}

func (p *NodeChangePlan) block(code string) {
	for _, old := range p.Blockers {
		if old == code {
			return
		}
	}
	p.Blockers = append(p.Blockers, code)
}

// PlanNodeChange is the common installed-voter calculator for removal and
// demotion. Expected names the lifecycle node for removal and the installed
// directory entry for a suffrage change. A current leader may transfer to a
// remaining voter before dispatch; this core does not invent a self ban.
func (d Directory) PlanNodeChange(id string, remove bool) (NodeChangePlan, error) {
	e, exists := d.Entry(id)
	out := NodeChangePlan{Epoch: 1, Expected: e.Revision, Blockers: []string{}}
	if !exists || !FullMember(e) {
		return out, ErrMember
	}
	for _, row := range d.Rotations {
		if row.Phase != "Installed" && (row.Node == id || !remove) {
			out.PendingOperation = row.Operation
			out.block("NODE_OPERATION_PENDING")
		}
	}
	for _, row := range d.Drains {
		if row.Node == id && row.Pending > 0 {
			out.PendingOperation = row.Operation
			out.block("NODE_OPERATION_PENDING")
		}
	}
	targetVoter := e.Peer.Voter
	if d.Runtime == nil {
		for _, member := range d.Entries {
			if FullMember(member) && member.Peer.Voter {
				out.VotersBefore++
			}
		}
		out.block("CONFIGURATION_NOT_INSTALLED")
	} else {
		t, err := d.Topology()
		if err != nil {
			return out, err
		}
		c := t.Configuration()
		n, found := t.Node(id)
		installed, present := c.Member(id)
		if !found || !present || (n.Phase == lifecycle.Removed || n.Phase == lifecycle.Retired) {
			return out, ErrMember
		}
		out.Epoch, out.ConfigurationIndex, out.VotersBefore = t.Epoch(), c.Index, c.Voters()
		targetVoter = installed.Voter
		if installed.Voter != e.Peer.Voter || e.NativeIndex > c.Index {
			out.block("CONFIGURATION_NOT_INSTALLED")
		}
		if remove {
			out.Expected = n.Revision
		}
		if n.Pending != nil {
			out.PendingOperation = n.Pending.ID
			out.block("NODE_OPERATION_PENDING")
		}
		if !remove && (n.Phase != lifecycle.Active || installed.Voter != e.Peer.Voter) {
			out.block("NODE_OPERATION_PENDING")
		}
		// Reservations exclude only committed removals. Isolated members still
		// replicate/vote, and no clock/liveness estimate enters the reducer.
		remaining := 0
		for _, member := range c.Members {
			if !member.Voter || member.ID == id {
				continue
			}
			other, _ := t.Node(member.ID)
			if other.Phase != lifecycle.Removing && other.Phase != lifecycle.Retiring {
				remaining++
			}
		}
		if remaining == 0 && (!installed.Voter || c.Voters() > 1) {
			out.block("QUORUM_LOSS")
		}
		for _, operation := range d.Runtime.Operations {
			if operation.Node == id && operation.Job.Pending != nil {
				out.PendingOperation = operation.ID
				out.block("NODE_OPERATION_PENDING")
			}
		}
	}
	out.VotersAfter = out.VotersBefore
	if targetVoter {
		out.VotersAfter--
	}
	if out.VotersAfter == 0 {
		out.block("LAST_VOTER")
	} else {
		out.QuorumAfter = out.VotersAfter/2 + 1
		out.FaultToleranceAfter = (out.VotersAfter - 1) / 2
	}
	for _, member := range d.Entries {
		if member.Job.Pending != nil && (member.Peer.ID == id || !remove) {
			out.block("NODE_OPERATION_PENDING")
		}
	}
	return out, nil
}
