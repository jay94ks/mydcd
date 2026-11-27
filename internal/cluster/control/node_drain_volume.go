// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"encoding/json"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
)

func drainMoves(job NodeDrainJob) []NodeDrainVolumeMove {
	if job.Move == nil {
		return nil
	}
	out := []NodeDrainVolumeMove{*job.Move}
	return append(out, job.AdditionalMoves...)
}
func drainRecipes(jobs []NodeDrainJob) []VolumeMoveRecipe {
	var out []VolumeMoveRecipe
	for _, job := range jobs {
		for _, move := range drainMoves(job) {
			out = append(out, move.Recipe)
		}
	}
	return out
}

func (p Policy) PlanNodeDrainWithRecipes(s state.State, session access.Session, at int64, q NodeDrainQuery, recipes []VolumeMoveRecipe) (NodeDrainPlan, error) {
	current, err := p.Current(s)
	if err != nil {
		return NodeDrainPlan{}, err
	}
	catalog, err := current.Catalog(s)
	if err != nil || catalog.AuthorizeSession(session, p.Cluster, current.Issuer(session.Issuer), at, "", access.ManageCluster, "") != nil {
		return NodeDrainPlan{}, access.ErrDenied
	}
	return current.nodeDrainPlan(s, session, at, q, recipes...)
}

// moveBeginForJob resolves a child from the actual signed drain payload. The
// parent signature is never copied onto invented begin-volume-move bytes.
func moveBeginForJob(j VolumeMove, q *VolumeMoveBegin) error {
	begin, expected, err := originalMoveBegin(j.Origin, j.Selection())
	if err != nil || expected+1 != j.Binding.StartedRevision {
		return ErrCatalog
	}
	*q = begin
	return nil
}
func originalMoveBegin(op UserOperation, selection VolumeMoveSelection) (VolumeMoveBegin, uint64, error) {
	var q VolumeMoveBegin
	if op.Change.Action == "begin-volume-move" {
		if canonical(op.Change.Payload, &q) != nil || q.Scope != selection.Scope || q.ID != selection.ID {
			return q, 0, ErrCatalog
		}
		return q, op.Change.Expected, nil
	}
	var drain NodeDrainChange
	if op.Change.Action != "drain-node" || canonical(op.Change.Payload, &drain) != nil {
		return q, 0, ErrCatalog
	}
	for _, job := range drain.Jobs {
		for _, move := range drainMoves(job) {
			if move.Begin.Scope == selection.Scope && move.Begin.ID == selection.ID {
				return move.Begin, move.Expected, nil
			}
		}
	}
	return q, 0, ErrCatalog
}
func moveBeginForScope(op UserOperation, scope deployment.AppScope) (VolumeMoveBegin, uint64, error) {
	if op.Change.Action == "begin-volume-move" {
		var q VolumeMoveBegin
		if canonical(op.Change.Payload, &q) != nil || q.Scope.Tenant != scope.Tenant || q.Scope.App != scope.App {
			return q, 0, ErrCatalog
		}
		return q, op.Change.Expected, nil
	}
	var q NodeDrainChange
	if op.Change.Action != "drain-node" || canonical(op.Change.Payload, &q) != nil {
		return VolumeMoveBegin{}, 0, ErrCatalog
	}
	for _, job := range q.Jobs {
		if job.Tenant == scope.Tenant && job.App == scope.App && job.Deployment == scope.Deployment && job.Move != nil {
			return job.Move.Begin, job.Move.Expected, nil
		}
	}
	return VolumeMoveBegin{}, 0, ErrCatalog
}
func drainMoveBlueprint(op UserOperation, q VolumeMoveBegin) (deployment.Blueprint, error) {
	var drain NodeDrainChange
	if canonical(op.Change.Payload, &drain) != nil {
		return deployment.Blueprint{}, ErrCatalog
	}
	for _, job := range drain.Jobs {
		selected := false
		for _, move := range drainMoves(job) {
			selected = selected || move.Begin.Scope == q.Scope && move.Begin.ID == q.ID
		}
		if !selected {
			continue
		}
		b, err := deployment.DecodeBlueprint(job.Move.Blueprint)
		if err != nil || b.Digest() != job.Plan || b.Scope().Cluster != q.Scope.Cluster || b.Scope().Tenant != job.Tenant || b.Scope().App != job.App || b.Scope().Deployment != job.Deployment || b.Scope().Actor != movePlanActor(op, q) || q.App == nil || q.App.Target == nil || q.App.Target.Plan != job.Plan || q.App.Target.Operation != job.Operation || q.App.Target.Upload != job.Operation {
			return deployment.Blueprint{}, ErrCatalog
		}
		return b, nil
	}
	return deployment.Blueprint{}, ErrCatalog
}
func moveScope(j VolumeMove) deployment.AppScope {
	return deployment.AppScope{Cluster: j.Binding.Scope.Cluster, Tenant: j.Binding.Scope.Tenant, App: j.Binding.Scope.App, Deployment: drainMoveDeployment(j)}
}
func drainMoveDeployment(j VolumeMove) string {
	if j.Origin.Change.Action != "drain-node" {
		return ""
	}
	var q NodeDrainChange
	if canonical(j.Origin.Change.Payload, &q) != nil {
		return ""
	}
	for _, job := range q.Jobs {
		for _, move := range drainMoves(job) {
			if move.Begin.Scope == j.Binding.Scope && move.Begin.ID == j.Binding.ID {
				return job.Deployment
			}
		}
	}
	return ""
}
func drainMoveSelection(job NodeDrainJob) VolumeMoveSelection {
	return VolumeMoveSelection{Scope: job.Move.Begin.Scope, ID: job.Move.Begin.ID}
}
func sameDrainMove(a, b *NodeDrainVolumeMove) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

func (p Policy) drainMoveJob(d membership.Directory, node, operation, child string) (UserOperation, NodeDrainJob, error) {
	for _, row := range d.Drains {
		if row.Node != node || row.Operation != operation {
			continue
		}
		var original UserOperation
		var q NodeDrainChange
		if canonical(row.Origin, &original) != nil || canonical(original.Change.Payload, &q) != nil || original.VerifyOriginal(p.Cluster) != nil {
			return original, NodeDrainJob{}, ErrCatalog
		}
		for _, job := range q.Jobs {
			for _, move := range drainMoves(job) {
				if move.Begin.ID == child {
					copy := job
					copy.Move = &move
					return original, copy, nil
				}
			}
		}
	}
	return UserOperation{}, NodeDrainJob{}, ErrCatalog
}
func (p Policy) startDrainMove(s state.State, d membership.Directory, r MemberReport) (map[string][]byte, state.Code) {
	origin, job, err := p.drainMoveJob(d, r.Node, r.Operation, r.DrainJob)
	if err != nil {
		return nil, state.Invalid
	}
	catalog, err := p.Catalog(s)
	if err != nil || catalog.AuthorizeAccepted(origin.Session, p.Cluster, origin.At, "", access.ManageCluster, "") != nil {
		return nil, state.Forbidden
	}
	for _, node := range []string{r.Node, job.Target} {
		if catalog.AuthorizeAccepted(origin.Session, p.Cluster, origin.At, job.Tenant, access.ManageVolumes, node) != nil {
			return nil, state.Forbidden
		}
	}
	registry, err := p.Volumes(s)
	if err != nil {
		return nil, state.Invalid
	}
	for _, prior := range registry.Moves() {
		_, move, found := registry.Move(prior.Selection())
		if found && movePending(move) && !sameDrainGroupOrigin(prior.Origin, origin, job.Tenant, job.App, prior.Binding.Scope.Tenant, prior.Binding.Scope.App) && (prior.Binding.Source.Node == r.Node || prior.Binding.Target.Node == r.Node || prior.Binding.Source.Node == job.Target || prior.Binding.Target.Node == job.Target) {
			return nil, state.ConditionFailed
		}
	}
	writes, code := p.beginVolumeMoveJob(s, catalog, registry, origin, job.Move.Begin, job.Move.Expected)
	if code != state.Applied {
		return nil, code
	}
	d, err = d.StartDrainMove(r.Node, r.Operation, r.DrainJob)
	if err != nil {
		return nil, state.ConditionFailed
	}
	members, code := p.memberCheckpoint(s, d)
	if code != state.Applied {
		return nil, code
	}
	for key, value := range members {
		writes[key] = value
	}
	return writes, state.Applied
}
func (p Policy) admitDrainMovePatch(s state.State, cmd state.Command, keys []string) bool {
	var report MemberReport
	if canonical([]byte(cmd.Value), &report) != nil || report.Action != "drain-move-start" {
		return false
	}
	writes, code := p.reduceMembers(s, cmd)
	if code != state.Applied {
		return false
	}
	for _, key := range keys {
		if !checkpointPatchKey(writes, VolumesKey, key) {
			return false
		}
	}
	return true
}

func sameDrainGroupOrigin(a, b UserOperation, tenant, app, otherTenant, otherApp string) bool {
	return a.Change.Action == "drain-node" && b.Change.Action == "drain-node" && tenant == otherTenant && app == otherApp && bytes.Equal(OperationBytes(a), OperationBytes(b)) && bytes.Equal(a.Signature, b.Signature)
}
func sameDrainMoveGroup(a, b VolumeMove) bool {
	return sameDrainGroupOrigin(a.Origin, b.Origin, a.Binding.Scope.Tenant, a.Binding.Scope.App, b.Binding.Scope.Tenant, b.Binding.Scope.App)
}

func drainMoveGroup(v Volumes, j VolumeMove) ([]VolumeMove, error) {
	if j.Origin.Change.Action != "drain-node" {
		return []VolumeMove{j}, nil
	}
	var parent NodeDrainChange
	if canonical(j.Origin.Change.Payload, &parent) != nil {
		return nil, ErrCatalog
	}
	for _, job := range parent.Jobs {
		if job.Tenant != j.Binding.Scope.Tenant || job.App != j.Binding.Scope.App {
			continue
		}
		var group []VolumeMove
		for _, child := range drainMoves(job) {
			saved, _, ok := v.Move(VolumeMoveSelection{Scope: child.Begin.Scope, ID: child.Begin.ID})
			if !ok || !sameDrainMoveGroup(saved, j) {
				return nil, ErrCatalog
			}
			group = append(group, saved)
		}
		if len(group) == 0 || len(group) > 128 {
			return nil, ErrCatalog
		}
		return group, nil
	}
	return nil, ErrCatalog
}
