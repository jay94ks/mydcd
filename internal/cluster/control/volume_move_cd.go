// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

func cdMoveSourceMatches(entry appEntry, source *AppCDMoveSource, current bool) bool {
	if entry.Delivery == nil {
		return source == nil
	}
	if source == nil || !source.Valid() || source.Registration != appRegistrationDigest(entry.Origin) || source.Principal != entry.Delivery.Principal() || source.Requester != entry.Origin.Session.Key {
		return false
	}
	if current {
		return source.PolicyRevision == entry.Delivery.PolicyRevision() && source.OverrideRevision == entry.Delivery.OverrideRevision()
	}
	return source.PolicyRevision <= entry.Delivery.PolicyRevision() && source.OverrideRevision <= entry.Delivery.OverrideRevision()
}

func movePlanActor(op UserOperation, q VolumeMoveBegin) string {
	if q.App != nil && q.App.CD != nil {
		return q.App.CD.Principal
	}
	return op.Change.Principal
}

// The current CD registration/authority is checked before consuming this
// signed source anchor. A different administrator may authorize the move but
// must not replace the requester bound to its Secret approval plans.
func moveInputRequester(op UserOperation, q VolumeMoveBegin) [32]byte {
	if q.App != nil && q.App.CD != nil {
		return q.App.CD.Requester
	}
	return op.Session.Key
}

func (p Policy) checkCDMoveAuthority(s state.State, c access.Catalog, entry appEntry, op UserOperation, q VolumeMoveBegin, b deployment.Blueprint) error {
	if q.App == nil {
		return ErrCatalog
	}
	if !cdMoveSourceMatches(entry, q.App.CD, true) {
		return ErrCatalog
	}
	if entry.Delivery == nil {
		return nil
	}
	if p.authorizeLocalBlueprint(s, c, entry, entry.Local, b) != nil || b.Scope().Actor != entry.Delivery.Principal() || q.App.CD.Intent != b.IntentDigest() || q.App.CD.Input != b.AppInputDigest() || c.AuthorizeAccepted(entry.Origin.Session, p.Cluster, entry.Origin.At, q.Scope.Tenant, access.ManageCD, "") != nil || c.AuthorizeAccepted(op.Session, p.Cluster, op.At, q.Scope.Tenant, access.ManageCD, "") != nil {
		return access.ErrDenied
	}
	for _, step := range b.Steps() {
		if c.AuthorizeAccepted(entry.Origin.Session, p.Cluster, entry.Origin.At, q.Scope.Tenant, step.Action(), step.Node) != nil || c.AuthorizeAccepted(op.Session, p.Cluster, op.At, q.Scope.Tenant, step.Action(), step.Node) != nil {
			return access.ErrDenied
		}
	}
	return nil
}

func moveExecutionOrigin(entry appEntry) UserOperation {
	if entry.Delivery != nil && entry.Sync != nil && entry.Sync.User != nil && (entry.Sync.User.Change.Action == "begin-volume-move" || entry.Sync.User.Change.Action == "drain-node") {
		return *entry.Sync.User
	}
	return entry.Origin
}

func sameMoveExecution(entry appEntry, move UserOperation) bool {
	origin := moveExecutionOrigin(entry)
	return bytes.Equal(OperationBytes(origin), OperationBytes(move)) && bytes.Equal(origin.Signature, move.Signature)
}

func sameMoveBinding(source AppBindingSource, move UserOperation) bool {
	origin := source.Origin
	if source.Sync != nil && source.Sync.User != nil && (source.Sync.User.Change.Action == "begin-volume-move" || source.Sync.User.Change.Action == "drain-node") {
		origin = *source.Sync.User
	}
	return bytes.Equal(OperationBytes(origin), OperationBytes(move)) && bytes.Equal(origin.Signature, move.Signature)
}

// Group consent for an explicit move stays with the registered requester,
// even when another currently authorized administrator signed the move.
func (p Policy) cdMoveApprovalBlueprint(s state.State, session access.Session, at int64, a Apps, entry appEntry, operation string) (deployment.Blueprint, bool, error) {
	var zero deployment.Blueprint
	if entry.Delivery == nil || operation == "" {
		return zero, false, nil
	}
	v, err := p.Volumes(s)
	if err != nil {
		return zero, false, err
	}
	c, err := p.Catalog(s)
	if err != nil {
		return zero, false, err
	}
	for _, job := range v.Moves() {
		if job.App == nil || job.App.CD == nil || job.App.Target == nil || job.App.Target.Operation != operation || job.Binding.Scope.Tenant != entry.Inventory.Scope().Tenant || job.Binding.Scope.App != entry.Inventory.Scope().App || job.App.CD.Registration != appRegistrationDigest(entry.Origin) {
			continue
		}
		_, move, exists := v.Move(job.Selection())
		if !exists || move.Phase == volumes.Cancelled || !move.Irreversible && at >= job.ExpiresAt || move.Phase == volumes.Completed && !sameMoveExecution(entry, job.Origin) || session.User != entry.Delivery.Principal() || c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, job.Binding.Scope.Tenant, access.ManageCD, "") != nil {
			return zero, true, access.ErrDenied
		}
		if entry.Down != nil && (!bytes.Equal(OperationBytes(*entry.Down), OperationBytes(job.Origin)) || !bytes.Equal(entry.Down.Signature, job.Origin.Signature)) {
			return zero, true, access.ErrDenied
		}
		var q VolumeMoveBegin
		if moveBeginForJob(job, &q) != nil {
			return zero, true, ErrCatalog
		}
		b, err := p.frozenMoveBlueprint(a, job.Origin, q)
		if err != nil {
			return zero, true, err
		}
		if err := p.checkCDMoveAuthority(s, c, entry, job.Origin, q, b); err != nil {
			return zero, true, err
		}
		for _, step := range b.Steps() {
			if c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, q.Scope.Tenant, step.Action(), step.Node) != nil {
				return zero, true, access.ErrDenied
			}
			if step.Node != "" {
				owner, err := p.nodeOwner(s, step.Node)
				if err != nil || owner != step.Owner {
					return zero, true, access.ErrDenied
				}
			}
		}
		return b, true, nil
	}
	return zero, false, nil
}
