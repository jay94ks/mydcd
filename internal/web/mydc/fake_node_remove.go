// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"errors"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/control"
)

// REQ-52 in the fake, plus isolate-node / restore-node / remove-node with
// the real payload control.NodeLifecycleChange{ID, Operation, Epoch} and
// Expected = the member Revision. The fake finishes a lifecycle operation at
// once (no PendingOperation is left). "Self" is the node mydcd answers from:
// the fixture leader.

// fakeNodeEpoch is the fake's node operation epoch (MembersPage
// NodeOperationEpoch); a lifecycle change with another Epoch is refused.
const fakeNodeEpoch = 1

var removeResultCodes = map[string]ResultCode{
	NodeLastVoter:                 ResultLastVoter,
	NodeQuorumLoss:                ResultQuorumLoss,
	NodeOperationPending:          ResultNodeOperationPending,
	NodeFixedVolumeStays:          ResultFixedVolumePresent,
	NodeStorageNotDrained:         ResultNodeStorageNotDrained,
	NodeSelfRemoval:               ResultSelfRemoval,
	NodeNativeUnsettled:           ResultNativeUnsettled,
	NodeTasksPresent:              ResultTasksPresent,
	NodeConfigurationPending:      ResultConfigurationPending,
	NodeResponding:                ResultNodeResponding,
	string(CodeNodeShellDisabled): ResultNodeShellDisabled,
	string(CodeNodeShellNotReady): ResultNodeShellNotReady,
	string(CodeLimit):             ResultNodeShellLimit,
	string(CodeNodeUnreachable):   ResultNodeShellUnreachable,
}

type nodeRemoveRefused struct{ code string }

func (e nodeRemoveRefused) Error() string { return "remove-node: " + e.code }

func (w *world) removePlan(node string) removePlanView {
	m := w.members[w.memberIndex(node)]
	vp := w.voterPlan(node, false)
	p := removePlanView{Node: node, Epoch: fakeNodeEpoch, Expected: m.Revision, Blockers: []removeBlocker{},
		Tasks: []removeTask{}, Storage: []removeStorage{}, PendingOperation: m.PendingOperation}
	p.VotersBefore = vp.VotersAfter
	if m.Voter {
		p.VotersBefore++
		p.VotersAfter = vp.VotersAfter
	} else {
		p.VotersAfter = p.VotersBefore
	}
	p.QuorumAfter, p.FaultToleranceAfter = quorumOf(p.VotersAfter)
	block := func(code, detail string) {
		p.Blockers = append(p.Blockers, removeBlocker{Code: code, Detail: detail})
	}
	if m.Voter && (vp.Code == NodeLastVoter || vp.Code == NodeQuorumLoss) {
		block(vp.Code, "")
	}
	if node == w.raft.Leader {
		block(NodeSelfRemoval, "mydcd answers from this server")
	}
	if m.PendingOperation != "" {
		block(NodeOperationPending, m.PendingOperation)
	}
	for _, v := range w.volumes {
		if v.Kind == "fixed" && v.Node == node {
			block(NodeFixedVolumeStays, v.Tenant+"/"+v.Name)
		}
	}
	for _, r := range w.nodeStorage {
		if r.Node != node {
			continue
		}
		s := removeStorage{ID: r.ID, Path: r.Path, Volumes: []string{}, Drained: r.Draining && r.Closed}
		for _, v := range w.volumes {
			if v.Kind == "fixed" && v.Node == node && v.Storage == r.ID {
				s.Volumes = append(s.Volumes, v.Tenant+"/"+v.Name)
				s.Bytes += v.UsedBytes
			}
		}
		if !s.Drained {
			block(NodeStorageNotDrained, r.ID)
		}
		p.Storage = append(p.Storage, s)
	}
	for _, dt := range w.drainPlan(node).Tasks {
		p.Tasks = append(p.Tasks, removeTask{Tenant: dt.Tenant, App: dt.App, Service: dt.Service, Instance: dt.Instance, Movable: dt.Blocked == "", Reason: dt.Blocked})
	}
	for _, k := range sortedKeys(w.standalones) {
		if e := w.standalones[k]; e.view.Node == node {
			p.Tasks = append(p.Tasks, removeTask{Tenant: e.view.Tenant, Standalone: e.view.Name, Reason: NodePinned})
		}
	}
	p.Removable = len(p.Blockers) == 0
	return p
}

func (c *fakeConn) applyNodeLifecycle(op UserOperation, actor string, next uint64) error {
	w := c.f.w
	ch := op.Change
	var q control.NodeLifecycleChange
	if decodePayload(ch.Payload, &q) != nil || q.ID == "" || q.Operation == "" {
		return errors.New("payload")
	}
	if !w.admin(actor) {
		return errForbidden
	}
	i := w.memberIndex(q.ID)
	if i < 0 || w.members[i].Phase == NodePhaseRemoved || w.members[i].Phase == NodePhasePending {
		return errCAS
	}
	m := &w.members[i]
	if ch.Expected != m.Revision || q.Epoch != fakeNodeEpoch {
		return errCAS
	}
	status := ""
	switch ch.Action {
	case ActionIsolateNode:
		m.Phase, m.AdmitsWork, status = NodePhaseIsolated, false, "isolated"
	case ActionRestoreNode:
		m.Phase, m.AdmitsWork, status = NodePhaseActive, true, "ready"
	case ActionRemoveNode:
		if p := w.removePlan(q.ID); !p.Removable {
			return nodeRemoveRefused{p.Blockers[0].Code}
		}
		m.Phase, m.Voter, m.AdmitsWork, status = NodePhaseRemoved, false, false, "removed"
		now := c.f.now().UTC().Truncate(time.Second)
		w.addEvent(FixtureEvent{Time: now.Unix(), Scope: "node", Node: q.ID, Kind: "node-removed", Target: q.ID, Detail: q.Operation})
	}
	m.Revision = next
	for j := range w.summaries {
		if w.summaries[j].Node == q.ID {
			w.summaries[j].Status = status
			if ch.Action == ActionRemoveNode {
				w.summaries[j].Role = "removed"
			}
		}
	}
	return nil
}
