// SPDX-License-Identifier: Apache-2.0

package control

import (
	"slices"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/identity"
)

type NodeForceQuery struct{ Node, Operation string }

func (q NodeForceQuery) Valid() bool {
	return lifecycle.ValidID(q.Node) && lifecycle.ValidID(q.Operation)
}

type NodeForceChange struct {
	ID, Operation string
	Epoch         uint64
	Probe         lifecycle.RemovalProbe
}
type NodeForcePlan struct {
	NodeRemovePlan
	Operation string
	Forceable bool
	Probe     *lifecycle.RemovalProbe `json:",omitempty"`
}

func (p Policy) PlanNodeForceRemoval(s state.State, session access.Session, at int64, q NodeForceQuery) (NodeForcePlan, error) {
	if !q.Valid() {
		return NodeForcePlan{}, access.ErrInvalid
	}
	base, err := p.PlanNodeRemoval(s, session, at, q.Node)
	if err != nil {
		return NodeForcePlan{}, err
	}
	out := NodeForcePlan{NodeRemovePlan: base, Operation: q.Operation}
	out.Blockers = []NodeBlocker{}
	// The server's own unfinished key rotation does not block a forced
	// removal (membership PlanForceRemoval): pending is read from that plan.
	d, err := p.Members(s)
	if err != nil {
		return NodeForcePlan{}, err
	}
	forced, err := d.PlanForceRemoval(q.Node)
	if err != nil {
		return NodeForcePlan{}, err
	}
	for _, blocker := range base.Blockers {
		switch blocker.Code {
		case "NODE_OPERATION_PENDING":
			if slices.Contains(forced.Blockers, blocker.Code) {
				out.Blockers = append(out.Blockers, blocker)
			}
		case "LAST_VOTER", "QUORUM_LOSS", "CONFIGURATION_NOT_INSTALLED":
			out.Blockers = append(out.Blockers, blocker)
		}
	}
	out.PendingOperation = forced.PendingOperation
	// Retained Task/Volume/root rows describe stranded original resources.
	// They remain pinned and do not pretend that an owner closure was observed.
	out.Removable = false
	return out, nil
}
func (p Policy) CheckNodeForceProbe(s state.State, q NodeForceChange, expected uint64, at int64) state.Code {
	probe := q.Probe
	d, err := p.Members(s)
	if err != nil {
		return state.Invalid
	}
	e, found := d.Entry(q.ID)
	if !found {
		return state.Invalid
	}
	target, err := identity.ParseKey(e.CurrentPeer().Key)
	if err != nil {
		return state.Invalid
	}
	if !probe.Valid() || probe.Cluster != p.Cluster || probe.Node != q.ID || probe.Operation != q.Operation || probe.Target != target || probe.Expected != expected || probe.Epoch != q.Epoch || probe.RootRevision != s.Object(MembersKey).Revision || at < probe.FinishedAt || at-probe.FinishedAt > 30 {
		return state.ConditionFailed
	}
	topology, err := d.Topology()
	if err != nil {
		return state.NodeConfigurationPending
	}
	if probe.ConfigurationIndex != topology.Configuration().Index {
		return state.ConditionFailed
	}
	observer, installed := topology.Configuration().Member(probe.ObserverID(topology.Configuration()))
	if !installed || !observer.Voter || !d.WorkKey(observer.Key) {
		return state.Forbidden
	}
	if probe.Target == probe.Observer {
		return state.NodeSelfRemoval
	}
	if probe.Responding {
		return state.NodeStillResponding
	}
	plan, err := d.PlanForceRemoval(q.ID)
	if err != nil {
		return state.Invalid
	}
	blockers := []NodeBlocker{}
	for _, code := range plan.Blockers {
		blockers = append(blockers, NodeBlocker{Code: code})
	}
	return nodeBlockerCode(blockers)
}
