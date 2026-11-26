// SPDX-License-Identifier: Apache-2.0

package membership

import (
	"encoding/json"

	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/reconcile"
)

// VotingChange retains the original signed administrator request and the
// already installed identity. Only suffrage changes: this is not a new join,
// installation ACK, member key, or native identity.
type VotingChange struct {
	Origin                                       json.RawMessage
	Before                                       config.Peer
	AcceptedRevision, PreviousNativeIndex, JobID uint64
}

func (d Directory) ChangeVote(id string, expected uint64, voter bool, origin json.RawMessage) (Directory, error) {
	e, ok := d.Entry(id)
	if !ok || !d.writable() || e.Revision != expected || !FullMember(e) || e.Job.Pending != nil || e.Peer.Voter == voter || len(origin) == 0 || len(origin) > 64<<10 || !json.Valid(origin) {
		return d, ErrMember
	}
	topology, err := d.Topology()
	if err != nil {
		return d, err
	}
	node, exists := topology.Node(id)
	installed, present := topology.Configuration().Member(id)
	key, _ := identity.ParseKey(e.CurrentPeer().Key)
	if !exists || !present || node.Phase != lifecycle.Active || node.Pending != nil || installed.Key != key || installed.Voter != e.Peer.Voter {
		return d, ErrMember
	}
	plan, err := d.PlanNodeChange(id, false)
	if err != nil {
		return d, err
	}
	for _, code := range plan.Blockers {
		if !voter || code != "LAST_VOTER" && code != "QUORUM_LOSS" {
			return d, ErrMember
		}
	}
	before := e.Peer
	// Genesis/adopted members already have positive installed configuration
	// evidence; seed the existing journal from that fact, never from silence.
	job := e.Job
	if job == (reconcile.State{}) {
		job = reconcile.State{Desired: reconcile.Desired{Revision: e.Revision, Resource: peerResource(before)}, Applied: peerResource(before), GenerationFloor: 1}
	}
	target := before
	target.Voter = voter
	job, err = reconcile.SetDesired(job, reconcile.Desired{Revision: d.Revision + 1, Resource: peerResource(target)})
	if err != nil {
		return d, err
	}
	job, _, err = reconcile.Plan(job)
	if err != nil || job.Pending == nil {
		return d, ErrMember
	}
	e.Voting = &VotingChange{Origin: append(json.RawMessage(nil), origin...), Before: before, AcceptedRevision: expected, PreviousNativeIndex: e.NativeIndex, JobID: job.Pending.ID}
	e.Job, e.Source, e.BaseIndex = job, [32]byte{}, 0
	e.Phase = Demoting
	if voter {
		e.Phase = Promoting
	}
	return d.replace(e), nil
}

func (d Directory) validateVotingEntry(e Entry) (bool, error) {
	v := e.Voting
	if v == nil || len(v.Origin) == 0 || len(v.Origin) > 64<<10 || !json.Valid(v.Origin) || v.AcceptedRevision == 0 || v.AcceptedRevision >= e.Revision || !validPeer(v.Before) || v.Before.ID != e.Peer.ID || v.Before.Key != e.Peer.Key || v.Before.Endpoint != e.Peer.Endpoint || v.JobID == 0 || e.Job.LastID != v.JobID || e.Job.GenerationFloor != 1 || e.Job.Stopped || e.Job.Desired.Retiring != 0 || e.Job.Desired.Revision <= v.AcceptedRevision || e.Job.Desired.Revision > e.Revision {
		return false, ErrMember
	}
	target := v.Before
	target.Voter = !target.Voter
	if e.Job.Desired.Resource != peerResource(target) {
		return false, ErrMember
	}
	if e.Ack != nil && (!validAck(*e.Ack, d.Cluster, e) || e.Ack.ConfigurationIndex > e.NativeIndex) {
		return false, ErrMember
	}
	if pending := e.Job.Pending; pending != nil {
		phase := Demoting
		if target.Voter {
			phase = Promoting
		}
		if e.Phase != phase || e.Peer != v.Before || e.NativeIndex != v.PreviousNativeIndex || pending.Kind != reconcile.Apply || pending.Target != peerResource(target) || e.Job.Applied != peerResource(v.Before) {
			return false, ErrMember
		}
		if pending.Phase == reconcile.Prepared {
			if e.Source != ([32]byte{}) || e.BaseIndex != 0 {
				return false, ErrMember
			}
			return false, nil
		}
		if !d.HistoricalMemberKey(e.Source) || e.BaseIndex == 0 || e.BaseIndex < e.NativeIndex {
			return false, ErrMember
		}
		return true, nil
	}
	phase := Ready
	if target.Voter {
		phase = Active
	}
	if e.Phase != phase || e.Peer != target || e.Job.Applied != peerResource(target) || !d.HistoricalMemberKey(e.Source) || e.BaseIndex == 0 || e.NativeIndex <= e.BaseIndex {
		return false, ErrMember
	}
	return false, nil
}
