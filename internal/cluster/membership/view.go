// SPDX-License-Identifier: Apache-2.0

package membership

import (
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/reconcile"
)

// NodeView deliberately omits signed administrator/session origins. A page
// exposes policy and original effect state without returning the whole log.
type NodeView struct {
	Identity       *IdentityRotationView `json:",omitempty"`
	Scheduling     CordonView
	Node           lifecycle.Node
	AdmitsWork     bool
	SharedActivity *lifecycle.Activity `json:",omitempty"`
	Native         *NodeEffectView     `json:",omitempty"`
}
type NodeEffectView struct {
	Operation                string
	JobID                    uint64
	Phase                    reconcile.Phase
	Source                   [32]byte
	BaseIndex, ObservedIndex uint64
}

func (d Directory) NodeView(id string) (NodeView, bool) {
	t, err := d.Topology()
	if err != nil {
		return NodeView{}, false
	}
	n, exists := t.Node(id)
	if !exists {
		return NodeView{}, false
	}
	view := NodeView{Scheduling: d.Cordon(id), Node: n, AdmitsWork: d.WorkKey(n.Member.Key)}
	for _, row := range d.Rotations {
		if row.Node == id {
			view.Identity = &IdentityRotationView{Operation: row.Operation, Phase: row.Phase, Failure: row.Failure, AcceptedIndex: row.AcceptedIndex, ActivatedIndex: row.ActivatedIndex, InstalledIndex: row.InstalledIndex}
			if row.Proof != nil {
				view.Identity.Old = row.Proof.Old
				view.Identity.New = row.Proof.New
			}
		}
	}
	operation := ""
	if n.Pending != nil {
		operation = n.Pending.ID
	} else if n.Retirement != nil {
		operation = n.Retirement.Operation
	} else if n.Closure != nil {
		operation = n.Closure.Operation
	}
	if op, found := d.NodeOperation(operation); found && (op.Action == lifecycle.Remove || op.Action == lifecycle.ForceRemove) {
		effect := NodeEffectView{Operation: op.ID, Source: op.Source, BaseIndex: op.BaseIndex, ObservedIndex: op.ObservedIndex, JobID: op.Job.LastID}
		if op.Job.Pending != nil {
			effect.Phase = op.Job.Pending.Phase
		}
		view.Native = &effect
	}
	return view, true
}

type IdentityRotationView struct {
	Operation, Phase, Failure                     string
	Old, New                                      [32]byte
	AcceptedIndex, ActivatedIndex, InstalledIndex uint64
	// RequestedAt: the rotate-node-identity original's time (UTC RFC 3339),
	// projected by control.
	RequestedAt string `json:",omitempty"`
}
