// SPDX-License-Identifier: Apache-2.0

package control

import (
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/cluster/membership"
	"github.com/jay94ks/mydcd/internal/cluster/state"
)

func (p Policy) validateNodeOrigins(d membership.Directory) error {
	for _, row := range d.Rotations {
		var origin UserOperation
		var q NodeIdentityChange
		if canonical(row.Origin, &origin) != nil || origin.VerifyOriginal(p.Cluster) != nil || origin.Change.Action != "rotate-node-identity" || canonical(origin.Change.Payload, &q) != nil || q.ID != row.Node || q.Operation != row.Operation || origin.Change.Expected != row.Expected {
			return ErrCatalog
		}
	}
	for _, drain := range d.Drains {
		var origin UserOperation
		var plan NodeDrainPlan
		var q NodeDrainChange
		started := map[string]bool{}
		for _, id := range drain.Started {
			started[id] = true
		}
		count := uint32(0)
		if !validateDrainOrigin(drain.Origin, drain.Node, drain.Operation) || canonical(drain.Origin, &origin) != nil || origin.VerifyOriginal(p.Cluster) != nil || canonical(origin.Change.Payload, &q) != nil || canonical(drain.Plan, &plan) != nil || plan.Digest != drainPlanDigest(plan) || q.Plan != plan.Digest {
			return ErrCatalog
		}
		for _, job := range plan.Jobs {
			for _, move := range drainMoves(job) {
				if started[move.Begin.ID] {
					delete(started, move.Begin.ID)
				} else {
					count++
				}
			}
		}

		if count != drain.Pending || len(started) > 0 {
			return ErrCatalog
		}
	}

	for _, entry := range d.Entries {
		if entry.Voting == nil {
			continue
		}
		var op UserOperation
		var q NodeSelection
		if canonical(entry.Voting.Origin, &op) != nil || op.VerifyOriginal(p.Cluster) != nil || canonical(op.Change.Payload, &q) != nil || q.ID != entry.Peer.ID || op.Change.Expected != entry.Voting.AcceptedRevision || op.Change.Action != "promote-node" && op.Change.Action != "demote-node" || (op.Change.Action == "demote-node") != entry.Voting.Before.Voter {
			return ErrCatalog
		}
	}

	for _, row := range d.Cordons {
		var origin UserOperation
		if validateDrainOrigin(row.Origin, row.Node, drainOperationForCordon(row.Origin)) {
			var origin UserOperation
			var q NodeDrainChange
			if canonical(row.Origin, &origin) != nil || origin.VerifyOriginal(p.Cluster) != nil || canonical(origin.Change.Payload, &q) != nil || !row.Enabled || origin.Change.Expected+1 != row.Revision {
				return ErrCatalog
			}
			continue
		}
		if canonical(row.Origin, &origin) != nil || origin.VerifyOriginal(p.Cluster) != nil {
			return ErrCatalog
		}
		target, err := cordonTarget(origin.Change.Action, origin.Change.Payload)
		if err != nil || target.ID != row.Node || origin.Change.Expected+1 != row.Revision || origin.Change.Action != "cordon-node" && origin.Change.Action != "uncordon-node" || (origin.Change.Action == "cordon-node") != row.Enabled {
			return ErrCatalog
		}
	}

	if d.Runtime == nil {
		return nil
	}
	for _, operation := range d.Runtime.Operations {
		for i, raw := range [][]byte{operation.Origin, operation.Authorization} {
			if i == 1 && raw == nil {
				continue
			}
			var origin UserOperation
			var target NodeLifecycleChange
			if canonical(raw, &origin) != nil || origin.VerifyOriginal(p.Cluster) != nil {
				return ErrCatalog
			}
			if operation.Action == lifecycle.ForceRemove && i == 0 {
				var force NodeForceChange
				if canonical(origin.Change.Payload, &force) != nil || !force.Probe.Valid() {
					return ErrCatalog
				}
				target = NodeLifecycleChange{ID: force.ID, Operation: force.Operation, Epoch: force.Epoch}
			} else if canonical(origin.Change.Payload, &target) != nil {
				return ErrCatalog
			}
			if target.ID != operation.Node || target.Operation != operation.ID || target.Epoch != operation.Epoch {
				return ErrCatalog
			}
			action := string(operation.Action) + "-node"
			if i == 1 {
				action = "resume-node-operation"
			}
			if origin.Change.Action != action {
				return ErrCatalog
			}
		}
	}
	return nil
}

// CheckNodeEffect is re-used before the sole native SDK dispatch and in its
// reducer. Original signature/target survives resume; current admin authority
// is necessary for a new effect, not for observing an already sent outcome.
func (p Policy) CheckNodeEffect(s state.State, id string) error {
	d, err := p.Members(s)
	if err != nil {
		return err
	}
	operation, exists := d.NodeOperation(id)
	if !exists {
		return ErrCatalog
	}
	var origin UserOperation
	raw := operation.Origin
	if operation.Authorization != nil {
		raw = operation.Authorization
	}
	if canonical(raw, &origin) != nil {
		return ErrCatalog
	}
	c, err := p.Catalog(s)
	if err != nil {
		return err
	}
	return c.AuthorizeAccepted(origin.Session, p.Cluster, origin.At, "", access.ManageCluster, "")
}

func drainOperationForCordon(raw []byte) string {
	var op UserOperation
	var q NodeDrainChange
	if canonical(raw, &op) != nil || canonical(op.Change.Payload, &q) != nil {
		return ""
	}
	return q.Operation
}
