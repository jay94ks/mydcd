// SPDX-License-Identifier: Apache-2.0

package membership

import (
	"encoding/json"

	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/reconcile"
)

// VotingChange retains the original signed administrator request and the
// already installed identity. Only suffrage, or only the endpoint, changes:
// this is not a new join, installation ACK, member key, or native identity.
type VotingChange struct {
	Origin                                       json.RawMessage
	Before                                       config.Peer
	AcceptedRevision, PreviousNativeIndex, JobID uint64
	// Endpoint is set when the change moves the server to a new endpoint
	// (set-node-endpoint); its vote stays. Empty: the vote flips.
	Endpoint string `json:",omitempty"`
}

// Target is the peer the change installs.
func (v VotingChange) Target() config.Peer {
	t := v.Before
	if v.Endpoint != "" {
		t.Endpoint = v.Endpoint
	} else {
		t.Voter = !t.Voter
	}
	return t
}

// pendingPhase is the entry's phase while the change is not yet settled.
func (v VotingChange) pendingPhase() Phase {
	switch {
	case v.Endpoint != "":
		return Moving
	case v.Before.Voter:
		return Demoting
	}
	return Promoting
}

func (d Directory) ChangeVote(id string, expected uint64, voter bool, origin json.RawMessage) (Directory, error) {
	e, ok := d.Entry(id)
	if !ok || e.Peer.Voter == voter {
		return d, ErrMember
	}
	return d.changeInstalled(id, expected, "", origin)
}

// ChangeEndpoint moves a joined server's recorded endpoint (and with it the
// address Raft and the mesh use to reach it) to endpoint, keeping its vote.
// The leader installs the new address in Raft like a vote change; the entry
// keeps the old endpoint until the installed configuration is observed.
func (d Directory) ChangeEndpoint(id string, expected uint64, endpoint string, origin json.RawMessage) (Directory, error) {
	e, ok := d.Entry(id)
	if !ok || endpoint == "" || endpoint == e.Peer.Endpoint || config.ValidateCanonicalEndpoint(endpoint) != nil || e.Restore != nil {
		return d, ErrMember
	}
	for _, other := range d.Entries {
		if other.Peer.ID != id && !d.gone(other.Peer.ID) && (other.Peer.Endpoint == endpoint || other.Voting != nil && other.Voting.Target().Endpoint == endpoint) {
			return d, ErrMember
		}
	}
	return d.changeInstalled(id, expected, endpoint, origin)
}

// changeInstalled starts a vote flip (endpoint "") or an endpoint move of an
// installed, settled full member.
func (d Directory) changeInstalled(id string, expected uint64, endpoint string, origin json.RawMessage) (Directory, error) {
	e, ok := d.Entry(id)
	if !ok || !d.writable() || e.Revision != expected || !FullMember(e) || e.Job.Pending != nil || len(origin) == 0 || len(origin) > 64<<10 || !json.Valid(origin) {
		return d, ErrMember
	}
	voter := e.Peer.Voter != (endpoint == "")
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
	if endpoint == "" {
		plan, err := d.PlanNodeChange(id, false)
		if err != nil {
			return d, err
		}
		for _, code := range plan.Blockers {
			if !voter || code != "LAST_VOTER" && code != "QUORUM_LOSS" {
				return d, ErrMember
			}
		}
	}
	before := e.Peer
	// Genesis/adopted members already have positive installed configuration
	// evidence; seed the existing journal from that fact, never from silence.
	job := e.Job
	if job == (reconcile.State{}) {
		job = reconcile.State{Desired: reconcile.Desired{Revision: e.Revision, Resource: peerResource(before)}, Applied: peerResource(before), GenerationFloor: 1}
	}
	change := VotingChange{Origin: append(json.RawMessage(nil), origin...), Before: before, AcceptedRevision: expected, PreviousNativeIndex: e.NativeIndex, Endpoint: endpoint}
	target := change.Target()
	job, err = reconcile.SetDesired(job, reconcile.Desired{Revision: d.Revision + 1, Resource: peerResource(target)})
	if err != nil {
		return d, err
	}
	job, _, err = reconcile.Plan(job)
	if err != nil || job.Pending == nil {
		return d, ErrMember
	}
	change.JobID = job.Pending.ID
	e.Voting = &change
	e.Job, e.Source, e.BaseIndex = job, [32]byte{}, 0
	e.Phase = change.pendingPhase()
	return d.replace(e), nil
}

func (d Directory) validateVotingEntry(e Entry) (bool, error) {
	v := e.Voting
	if v == nil || len(v.Origin) == 0 || len(v.Origin) > 64<<10 || !json.Valid(v.Origin) || v.AcceptedRevision == 0 || v.AcceptedRevision >= e.Revision || !validPeer(v.Before) || v.Before.ID != e.Peer.ID || v.Before.Key != e.Peer.Key || v.Endpoint != "" && (v.Endpoint == v.Before.Endpoint || config.ValidateCanonicalEndpoint(v.Endpoint) != nil) || v.JobID == 0 || e.Job.LastID != v.JobID || e.Job.GenerationFloor != 1 || e.Job.Stopped || e.Job.Desired.Retiring != 0 || e.Job.Desired.Revision <= v.AcceptedRevision || e.Job.Desired.Revision > e.Revision {
		return false, ErrMember
	}
	target := v.Target()
	if e.Job.Desired.Resource != peerResource(target) {
		return false, ErrMember
	}
	if e.Ack != nil && (!validAck(*e.Ack, d.Cluster, e) || e.Ack.ConfigurationIndex > e.NativeIndex) {
		return false, ErrMember
	}
	if pending := e.Job.Pending; pending != nil {
		if e.Phase != v.pendingPhase() || e.Peer != v.Before || e.NativeIndex != v.PreviousNativeIndex || pending.Kind != reconcile.Apply || pending.Target != peerResource(target) || e.Job.Applied != peerResource(v.Before) {
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
