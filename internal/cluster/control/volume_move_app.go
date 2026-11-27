// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
)

func sameMoveApp(a, b *VolumeMoveApp) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

// Accepted app moves own their original retirement/target execution until
// terminal settlement. Another upload must not replace that Inventory origin.
func (v Volumes) appMovePending(tenant, app string) bool {
	for _, job := range v.moves {
		if job.App == nil || job.Binding.Scope.Tenant != tenant || job.Binding.Scope.App != app {
			continue
		}
		_, move, ok := v.Move(job.Selection())
		if !ok || movePending(move) {
			return true
		}
	}
	return false
}

func moveAppRetirement(op UserOperation, scopes ...deployment.AppScope) (AppDown, uint64, error) {
	var q VolumeMoveBegin
	if op.Change.Action == "drain-node" {
		if len(scopes) != 1 {
			return AppDown{}, 0, ErrCatalog
		}
		var err error
		q, _, err = moveBeginForScope(op, scopes[0])
		if err != nil {
			return AppDown{}, 0, err
		}
	} else if op.Change.Action != "begin-volume-move" || canonical(op.Change.Payload, &q) != nil {
		return AppDown{}, 0, ErrCatalog
	}
	if q.App == nil || q.App.Operation == "" || q.App.Plan == ([32]byte{}) || q.App.Revision == 0 || q.App.Revision == ^uint64(0) {
		return AppDown{}, 0, ErrCatalog
	}
	d := sha256.Sum256(OperationBytes(op))
	return AppDown{Tenant: q.Scope.Tenant, App: q.Scope.App, Operation: "m-" + hex.EncodeToString(d[:24])}, q.App.Revision, nil
}
func (p Policy) validateMoveAppStart(s state.State, c access.Catalog, op UserOperation, q VolumeMoveBegin) error {
	a, err := p.Apps(s)
	if err != nil {
		return err
	}
	entry, exists := a.entries[appKey(q.Scope.Tenant, q.Scope.App)]
	key := deployment.ResourceKey("volume", q.Scope.Tenant, q.Scope.App, q.Scope.ID)
	owned := false
	if exists {
		for _, claim := range entry.Inventory.Claims() {
			if claim.Step.Key == key && !claim.Removed {
				owned = true
			}
		}
	}
	if q.App == nil {
		if owned {
			return ErrCatalog
		}
		return nil
	}
	if !exists || !owned || entry.Inventory.Revision() < q.App.Revision || c.AuthorizeAcceptedCleanup(op.Session, p.Cluster, op.At, q.Scope.Tenant, access.Deploy) != nil {
		return ErrCatalog
	}
	sameDrainRetirement := op.Change.Action == "drain-node" && entry.Down != nil && bytes.Equal(OperationBytes(*entry.Down), OperationBytes(op)) && bytes.Equal(entry.Down.Signature, op.Signature)
	if !cdMoveSourceMatches(entry, q.App.CD, true) || entry.Delivery != nil && (q.App.Target == nil || entry.PendingSync != nil || entry.Down != nil && !sameDrainRetirement) {
		return ErrCatalog
	}
	if _, busy := entry.Inventory.Retirement(); busy && !sameDrainRetirement {
		return ErrCatalog
	}
	active, ok := entry.Inventory.Active()
	if !sameDrainRetirement && (!ok || active.ID != q.App.Operation || active.Plan != q.App.Plan || active.Status != "Succeeded") {
		return ErrCatalog
	}
	if q.App.Target != nil {
		if _, used := entry.Inventory.Operation(q.App.Target.Operation); used || q.App.Target.Operation == q.App.Operation {
			return ErrCatalog
		}
		_, err = p.moveTargetBlueprint(s, c, a, op, q)
		return err
	}
	return nil
}

// frozenMoveBlueprint verifies stored identity without replanning against I/O or
// today's reservations. It remains usable while the old app is retiring.
func (p Policy) frozenMoveBlueprint(a Apps, op UserOperation, q VolumeMoveBegin) (deployment.Blueprint, error) {
	if q.App == nil || q.App.Target == nil {
		return deployment.Blueprint{}, ErrCatalog
	}
	if op.Change.Action == "drain-node" {
		return drainMoveBlueprint(op, q)
	}
	entry, exists := a.entries[appKey(q.Scope.Tenant, q.Scope.App)]
	if !exists {
		return deployment.Blueprint{}, ErrCatalog
	}
	target := q.App.Target
	for _, u := range a.uploads {
		if u.Tenant != q.Scope.Tenant || u.App != q.Scope.App || u.User != op.Change.Principal || u.Deployment != entry.Inventory.Scope().Deployment || u.ID != target.Upload || u.Digest != target.Plan {
			continue
		}
		raw, err := u.Complete()
		if err != nil {
			return deployment.Blueprint{}, err
		}
		b, err := deployment.DecodeBlueprint(raw)
		scope := b.Scope()
		if err != nil || scope.Cluster != p.Cluster || scope.Actor != movePlanActor(op, q) || scope.Tenant != u.Tenant || scope.App != u.App || scope.Deployment != u.Deployment {
			return deployment.Blueprint{}, ErrCatalog
		}
		if q.App.CD != nil && (!cdMoveSourceMatches(entry, q.App.CD, false) || q.App.CD.Intent != b.IntentDigest() || q.App.CD.Input != b.AppInputDigest()) {
			return deployment.Blueprint{}, ErrCatalog
		}
		return b, nil
	}
	return deployment.Blueprint{}, ErrCatalog
}

func (p Policy) moveTargetBlueprint(s state.State, c access.Catalog, a Apps, op UserOperation, q VolumeMoveBegin) (deployment.Blueprint, error) {
	b, err := p.frozenMoveBlueprint(a, op, q)
	if err != nil {
		return b, err
	}
	entry := a.entries[appKey(q.Scope.Tenant, q.Scope.App)]
	if err := p.checkCDMoveAuthority(s, c, entry, op, q, b); err != nil {
		return b, err
	}
	ctx, err := p.AppPlanning(s, movePlanActor(op, q), q.Scope.Tenant)
	if err != nil {
		return deployment.Blueprint{}, err
	}
	ctx.Project, ctx.Deployment = q.Scope.App, b.Scope().Deployment
	if op.Change.Action == "drain-node" {
		var drain NodeDrainChange
		if canonical(op.Change.Payload, &drain) != nil {
			return deployment.Blueprint{}, ErrCatalog
		}
		if node, ok := ctx.Nodes[drain.ID]; ok {
			node.Draining = false
			ctx.Nodes[drain.ID] = node
		}
	}
	ctx.DefaultNode = b.CDDefaultNode()
	v, err := p.Volumes(s)
	if err != nil {
		return deployment.Blueprint{}, err
	}
	source, ok := v.Volume(q.Scope)
	owner, _ := source.Owner()
	targetOwner, err := restoreTargetOwner(q.Target)
	placement := deployment.VolumeMovePlacement{Scope: q.Scope, Source: owner, SourceOwnerRevision: q.OwnerRevision, Target: targetOwner}
	if op.Change.Action == "drain-node" {
		var drain NodeDrainChange
		if canonical(op.Change.Payload, &drain) != nil {
			return b, ErrCatalog
		}
		for _, job := range drain.Jobs {
			if job.Tenant != q.Scope.Tenant || job.App != q.Scope.App {
				continue
			}
			for _, other := range drainMoves(job) {
				if other.Begin.Scope == q.Scope {
					continue
				}
				state, found := v.Volume(other.Begin.Scope)
				source, _ := state.Owner()
				target, e := restoreTargetOwner(other.Begin.Target)
				if !found || e != nil {
					return b, ErrCatalog
				}
				placement.Others = append(placement.Others, deployment.VolumeMovePlacement{Scope: other.Begin.Scope, Source: source, SourceOwnerRevision: other.Begin.OwnerRevision, Target: target})
			}
		}
	}
	if !ok || err != nil || b.ValidateVolumeMove(c, ctx, placement) != nil {
		return deployment.Blueprint{}, ErrCatalog
	}
	for _, step := range b.Steps() {
		if c.AuthorizeAccepted(op.Session, p.Cluster, op.At, q.Scope.Tenant, step.Action(), step.Node) != nil {
			return deployment.Blueprint{}, access.ErrDenied
		}
	}
	return b, nil
}

// RevalidateMoveAppTarget checks the original artifact before source shutdown.
// It grants neither Secret approval nor native readiness.
func (p Policy) RevalidateMoveAppTarget(s state.State, j VolumeMove) error {
	if j.App == nil || j.App.Target == nil {
		return nil
	}
	// Once this move's own retirement has begun, the source goals drain and
	// the target can no longer be recompiled against them (RESOURCE_DRAINING).
	// The check already passed when quiesce was permitted, before shutdown; a
	// later prepare (a restarted or retrying target) must not undo it.
	if status, err := p.MoveAppQuiescence(s, j); err == nil && (status == "retiring" || status == "ready") {
		return nil
	}
	c, err := p.Catalog(s)
	if err != nil {
		return err
	}
	a, err := p.Apps(s)
	if err != nil {
		return err
	}
	var q VolumeMoveBegin
	if moveBeginForJob(j, &q) != nil {
		return ErrCatalog
	}
	_, err = p.moveTargetBlueprint(s, c, a, j.Origin, q)
	return err
}

func (p Policy) moveAppSecretsReady(s state.State, j VolumeMove, at int64) error {
	_, err := p.moveAppInputReads(s, j, at)
	return err
}

func (p Policy) moveAppInputReads(s state.State, j VolumeMove, at int64) ([]AppInputRead, error) {
	if j.App == nil || j.App.Target == nil {
		return nil, nil
	}
	c, err := p.Catalog(s)
	if err != nil {
		return nil, err
	}
	a, err := p.Apps(s)
	if err != nil {
		return nil, err
	}
	var q VolumeMoveBegin
	if moveBeginForJob(j, &q) != nil {
		return nil, ErrCatalog
	}
	b, err := p.frozenMoveBlueprint(a, j.Origin, q)
	if err != nil {
		return nil, err
	}
	definitions, err := p.externalRegistryDefinitions(s, q.Scope.Tenant)
	if err != nil || b.CheckRegistrySources(definitions) != nil {
		return nil, access.ErrDenied
	}
	entry := a.entries[appKey(q.Scope.Tenant, q.Scope.App)]
	if err := p.checkCDMoveAuthority(s, c, entry, j.Origin, q, b); err != nil {
		return nil, err
	}
	for _, step := range b.Steps() {
		if c.AuthorizeAccepted(j.Origin.Session, p.Cluster, j.Origin.At, q.Scope.Tenant, step.Action(), step.Node) != nil {
			return nil, access.ErrDenied
		}
		if step.Node != "" {
			key, err := p.nodeOwner(s, step.Node)
			if err != nil || !p.ownsResource(s, key, step.Owner) {
				return nil, access.ErrDenied
			}
		}
	}
	requester := moveInputRequester(j.Origin, q)
	uses, err := b.ApprovalUses(requester)
	if err != nil {
		return nil, err
	}
	v, err := p.Vault(s)
	if err != nil {
		return nil, err
	}
	var realms []string
	for realm := range uses {
		realms = append(realms, realm)
	}
	slices.Sort(realms)
	var reads []AppInputRead
	for _, realm := range realms {
		batch := uses[realm]
		tree, ok := v.Trees[realm]
		if !ok {
			return nil, access.ErrDenied
		}
		plan, err := tree.Plan(c, batch)
		if err != nil || len(v.Approvals.Missing(c, tree, plan, at)) != 0 {
			return nil, access.ErrDenied
		}
		for _, use := range plan.Uses {
			profiles, err := p.inputProfiles(s, tree, use)
			if err != nil {
				return nil, err
			}
			reads = append(reads, AppInputRead{Realm: realm, Plan: use, Profiles: profiles})
		}
	}
	return reads, nil
}

func (p Policy) moveUploadHeld(s state.State, u deployment.Upload) bool {
	v, err := p.Volumes(s)
	if err != nil {
		return true
	}
	for _, j := range v.Moves() {
		if j.App != nil && j.App.Target != nil && j.Binding.Scope.Tenant == u.Tenant && j.Binding.Scope.App == u.App && j.Origin.Change.Principal == u.User && j.App.Target.Upload == u.ID {
			_, m, ok := v.Move(j.Selection())
			if ok && movePending(m) {
				return true
			}
		}
	}
	return false
}

// Storage validation checks the accepted reference, not today's authorization:
// revocation must stop new effects without invalidating preserved evidence.
func (p Policy) validateMoveTargetUploads(v Volumes, a Apps) error {
	for _, j := range v.Moves() {
		if j.App == nil || j.App.Target == nil {
			continue
		}
		_, m, ok := v.Move(j.Selection())
		if !ok {
			return invariantFailure("move-unknown")
		}
		if !movePending(m) {
			continue
		}
		held := false
		if j.Origin.Change.Action == "drain-node" {
			var q VolumeMoveBegin
			if moveBeginForJob(j, &q) != nil {
				return invariantFailure("drain-begin")
			}
			if _, err := p.frozenMoveBlueprint(a, j.Origin, q); err != nil {
				return err
			}
			entry, exists := a.entries[appKey(j.Binding.Scope.Tenant, j.Binding.Scope.App)]
			if !exists || !cdMoveSourceMatches(entry, j.App.CD, false) {
				return invariantFailure("drain-source")
			}
			continue
		}
		for _, u := range a.uploads {
			if u.Tenant != j.Binding.Scope.Tenant || u.App != j.Binding.Scope.App || u.User != j.Origin.Change.Principal || u.ID != j.App.Target.Upload || u.Digest != j.App.Target.Plan {
				continue
			}
			raw, err := u.Complete()
			if err != nil {
				return err
			}
			b, err := deployment.DecodeBlueprint(raw)
			entry, exists := a.entries[appKey(u.Tenant, u.App)]
			actor := j.Origin.Change.Principal
			if j.App.CD != nil {
				actor = j.App.CD.Principal
			}
			if err != nil || !exists || b.Scope().Cluster != p.Cluster || b.Scope().Actor != actor || b.Scope().Tenant != u.Tenant || b.Scope().App != u.App || b.Scope().Deployment != u.Deployment || entry.Inventory.Scope().Deployment != u.Deployment || !cdMoveSourceMatches(entry, j.App.CD, false) {
				return invariantFailure("upload-mismatch")
			}
			held = true
			break
		}
		if !held {
			return invariantFailure("upload-missing")
		}
	}
	return nil
}

// MoveAppQuiescence reads the same Inventory/retirement, never infers native
// shutdown from a missing process or a different/newly submitted operation.
func (p Policy) MoveAppQuiescence(s state.State, j VolumeMove) (string, error) {
	if j.App == nil {
		return "ready", nil
	}
	a, err := p.Apps(s)
	if err != nil {
		return "", err
	}
	e, ok := a.entries[appKey(j.Binding.Scope.Tenant, j.Binding.Scope.App)]
	if !ok {
		return "", ErrCatalog
	}
	want, _, err := moveAppRetirement(j.Origin, moveScope(j))
	if err != nil {
		return "", err
	}
	if e.Down == nil {
		active, ok := e.Inventory.Active()
		if !ok || active.ID != j.App.Operation || active.Plan != j.App.Plan || active.Status != "Succeeded" || e.Inventory.Revision() < j.App.Revision {
			return "", ErrCatalog
		}
		return "pending", nil
	}
	if !bytes.Equal(OperationBytes(*e.Down), OperationBytes(j.Origin)) || !bytes.Equal(e.Down.Signature, j.Origin.Signature) {
		return "", ErrCatalog
	}
	if r, ok := e.Inventory.Retirement(); ok {
		id := want.Operation
		if e.Delivery != nil {
			t, pending := e.Delivery.Transition()
			if !pending || t.Mode != deployment.DeliveryDown || t.Selection.Operation != want.Operation {
				return "", ErrCatalog
			}
			id = t.Retirement
		}
		if r.ID != id {
			return "", ErrCatalog
		}
		return "retiring", nil
	}
	if _, active := e.Inventory.Execution(); active {
		return "", ErrCatalog
	}
	for _, b := range a.bindings.Live() {
		if b.Needs().Use.Tenant == want.Tenant && b.Needs().Use.App == want.App {
			return "", ErrCatalog
		}
	}
	key := deployment.ResourceKey("volume", want.Tenant, want.App, j.Binding.Scope.ID)
	for _, claim := range e.Inventory.Claims() {
		if claim.Step.Key == key && claim.Retained && claim.RetainProof != nil && claim.RetainProof.Native == j.Source.Owner.Native && claim.RetainProof.Owner == j.Source.Owner.Key {
			return "ready", nil
		}
	}
	return "", ErrCatalog
}

func (p Policy) quiesceMoveApp(s state.State, j VolumeMove) (map[string][]byte, state.Code) {
	status, err := p.MoveAppQuiescence(s, j)
	if err != nil || status != "pending" {
		return nil, state.ConditionFailed
	}
	a, err := p.Apps(s)
	if err != nil {
		return nil, state.Invalid
	}
	c, err := p.Catalog(s)
	if err != nil {
		return nil, state.Invalid
	}
	down, _, err := moveAppRetirement(j.Origin, moveScope(j))
	if err != nil {
		return nil, state.Invalid
	}
	cmd, err := j.Origin.Command()
	if err != nil {
		return nil, state.Invalid
	}
	e := a.entries[appKey(down.Tenant, down.App)]
	if e.Delivery != nil {
		ctx, planningErr := p.AppPlanning(s, j.Origin.Session.User, down.Tenant)
		if planningErr != nil {
			return nil, state.ConditionFailed
		}
		ctx.Actor, ctx.Project, ctx.Deployment = e.Delivery.Principal(), down.App, e.Inventory.Scope().Deployment
		if begin, err := appOriginBegin(e.Origin, e.Inventory.Scope()); err == nil {
			ctx.DefaultNode = begin.DefaultNode
		}
		d, stopErr := e.Delivery.BeginTransition(e.Delivery.Revision(), c, ctx, j.Origin.Session.User, down.Operation, cmd.Actor, cmd.Epoch, deployment.DeliveryDown)
		err = stopErr
		if err == nil {
			a, e = clearDeliveryInput(a, e)
			e.Delivery, e.Inventory = &d, d.Inventory()
		}
	} else {
		e.Inventory, err = e.Inventory.Retire(e.Inventory.Revision(), c, j.Origin.Session.User, down.Operation, cmd.Actor, cmd.Epoch, nil, true)
	}
	if err != nil {
		return nil, state.ConditionFailed
	}
	original := j.Origin
	e.Down = &original
	a.entries[appKey(down.Tenant, down.App)] = e
	return p.appsCheckpoint(s, a)
}
