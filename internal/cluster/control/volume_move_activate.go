// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

// Owner publication, Arm, and the original Inventory's target execution are
// one FSM candidate. A failed plan/claim transition publishes none of them.
func (p Policy) activateMoveApp(s state.State, v Volumes, j VolumeMove) (map[string][]byte, state.Code) {
	writes, code, _ := p.activateMoveAppReason(s, v, j)
	return writes, code
}

// activateMoveAppReason is activateMoveApp with a fixed code naming the check
// that refused it, so a target can log why a Verified move does not start.
func (p Policy) activateMoveAppReason(s state.State, v Volumes, j VolumeMove) (map[string][]byte, state.Code, string) {
	a, err := p.Apps(s)
	if err != nil {
		return nil, state.Invalid, "APPS_UNREADABLE"
	}
	c, err := p.Catalog(s)
	if err != nil {
		return nil, state.Invalid, "CATALOG_UNREADABLE"
	}
	status, err := p.MoveAppQuiescence(s, j)
	if err != nil || status != "ready" || j.App == nil || j.App.Target == nil {
		return nil, state.ConditionFailed, "APP_NOT_QUIESCED"
	}
	group, err := drainMoveGroup(v, j)
	if err != nil {
		return nil, state.ConditionFailed, "MOVE_GROUP"
	}
	bindings := []volumes.Binding{}
	for _, job := range group {
		key := volumeKey(job.Binding.Scope)
		entry := v.entries[key]
		move, ok := entry.State.Move(job.Binding.ID)
		if !ok || move.Preparation == nil || move.Preparation.Target.Spec != job.Target || move.Preparation.Target.Owner != job.Binding.Target || move.Phase != volumes.Verified && move.Phase != volumes.OwnerCommitted || len(entry.State.Consumers()) != 0 {
			return nil, state.ConditionFailed, "GROUP_MOVE_NOT_READY"
		}
		if move.Phase == volumes.Verified {
			entry.State, err = entry.State.CommitOwner(c, job.Origin.Change.Principal, job.Binding.ID, entry.State.Revision(), job.Binding.SourceOwnerRevision)
			if err != nil {
				return nil, state.ConditionFailed, "COMMIT_OWNER"
			}
			entry.Native, entry.CapacityBytes = move.Preparation.Target, job.CapacityBytes
		}
		entry.State, err = entry.State.Arm(c, job.Origin.Change.Principal, job.Binding.ID, entry.State.Revision())
		if err != nil {
			return nil, state.ConditionFailed, "ARM"
		}
		v.entries[key] = entry
		bindings = append(bindings, job.Binding)
	}

	var q VolumeMoveBegin
	if moveBeginForJob(j, &q) != nil {
		return nil, state.Invalid, "MOVE_BEGIN"
	}
	frozen, err := p.frozenMoveBlueprint(a, j.Origin, q)
	if err != nil {
		return nil, state.ConditionFailed, "FROZEN_BLUEPRINT"
	}
	ctx, err := p.AppPlanning(s, j.Origin.Change.Principal, j.Binding.Scope.Tenant)
	if err != nil {
		return nil, state.ConditionFailed, "APP_PLANNING"
	}
	ctx.Project, ctx.Deployment = frozen.Scope().App, frozen.Scope().Deployment
	if j.Origin.Change.Action == "drain-node" {
		if node, ok := ctx.Nodes[j.Binding.Source.Node]; ok {
			node.Draining = false
			ctx.Nodes[j.Binding.Source.Node] = node
		}
	}
	ctx.Actor = frozen.Scope().Actor
	ctx.DefaultNode = frozen.CDDefaultNode()
	// The core reads this same transaction's checked Volume candidate, never
	// a fabricated native observation or a separately committed intermediate.
	for _, job := range group {
		ctx.Volumes[volumeKey(job.Binding.Scope)] = v.entries[volumeKey(job.Binding.Scope)].State
	}
	plan, err := frozen.Rebase(c, ctx)
	if err != nil {
		return nil, state.ConditionFailed, "REBASE"
	}
	entryKey := appKey(j.Binding.Scope.Tenant, j.Binding.Scope.App)
	entry := a.entries[entryKey]
	command, err := j.Origin.Command()
	if err != nil {
		return nil, state.Invalid, "ORIGIN_COMMAND"
	}
	if entry.Delivery != nil {
		if err := p.checkCDMoveAuthority(s, c, entry, j.Origin, q, frozen); err != nil {
			return nil, state.ConditionFailed, "CD_AUTHORITY"
		}
		identity, identityErr := appExecutionOrigin(entry.Origin, entry.Sync, entry.Inventory.Scope())
		if identityErr != nil {
			return nil, state.ConditionFailed, "CD_IDENTITY"
		}
		d, startErr := entry.Delivery.StartMovedGroup(entry.Delivery.Revision(), c, ctx, plan, bindings, j.Origin.Session.User, j.App.Target.Operation, identity.Submitter, command.Epoch)
		err = startErr
		if err == nil {
			selected, ok := d.Selection()
			if !ok {
				return nil, state.ConditionFailed, "CD_SELECTION"
			}
			choice := AppDeliveryChoice{Operation: selected.Operation, Candidate: selected.Candidate, Registration: appRegistrationDigest(entry.Origin)}
			proof := syncFromChoice(choice, selected, command.Epoch, &j.Origin, nil)
			proof.Local = ownLocalGrant(entry.Local)
			if proof.verify(entry.Origin, entry.Inventory.Scope()) != nil {
				return nil, state.ConditionFailed, "CD_SYNC_PROOF"
			}
			entry.Delivery, entry.Inventory, entry.Sync = &d, d.Inventory(), proof
		}
	} else {
		entry.Inventory, err = entry.Inventory.BeginMovedGroup(entry.Inventory.Revision(), c, ctx, plan, bindings, j.App.Target.Operation, command.Actor, command.Epoch)
		entry.Origin = j.Origin
	}
	if err != nil {
		return nil, state.ConditionFailed, "BEGIN_MOVED_GROUP"
	}
	entry.Down, entry.Compacted = nil, nil
	a.entries[entryKey] = entry
	writes, code := p.volumeCheckpoint(s, v)
	if code != state.Applied {
		return nil, code, "VOLUME_CHECKPOINT"
	}
	appWrites, code := p.appsCheckpoint(s, a)
	if code != state.Applied {
		return nil, code, "APPS_CHECKPOINT"
	}
	for key, value := range appWrites {
		writes[key] = value
	}
	return writes, state.Applied, ""
}

func (p Policy) validateMoveAppOrigins(s state.State, a Apps) error {
	var v Volumes
	loaded := false
	for _, entry := range a.entries {
		origin := moveExecutionOrigin(entry)
		if origin.Change.Action != "begin-volume-move" && origin.Change.Action != "drain-node" {
			continue
		}
		if !loaded {
			var err error
			v, err = p.Volumes(s)
			if err != nil {
				return err
			}
			loaded = true
		}
		var q VolumeMoveBegin
		if origin.Change.Action == "drain-node" {
			var err error
			q, _, err = moveBeginForScope(origin, entry.Inventory.Scope())
			if err != nil {
				continue
			}
		} else if canonical(origin.Change.Payload, &q) != nil {
			return invariantFailure("origin-payload")
		}
		job, move, ok := v.Move(VolumeMoveSelection{Scope: q.Scope, ID: q.ID})
		if !ok || move.CommitRevision == 0 || !move.Irreversible || !bytes.Equal(OperationBytes(job.Origin), OperationBytes(origin)) || !bytes.Equal(job.Origin.Signature, origin.Signature) {
			return invariantFailure("origin-move")
		}
		if _, err := p.frozenMoveBlueprint(a, origin, q); err != nil {
			return err
		}
	}
	return nil
}
