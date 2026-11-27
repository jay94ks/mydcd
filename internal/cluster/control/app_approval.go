// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"encoding/json"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/secrets"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

type AppApprovalSelection struct {
	Operation string    `json:",omitempty"`
	Candidate *[32]byte `json:",omitempty"`
}

func (x AppApprovalSelection) Valid() bool {
	if x.Candidate != nil {
		return x.Operation == "" && *x.Candidate != ([32]byte{})
	}
	return deployment.ResourceKey("task", "tenant", "app", x.Operation) != ""
}

func (x AppApprovalSelection) Equal(y AppApprovalSelection) bool {
	return x.Operation == y.Operation && (x.Candidate == nil && y.Candidate == nil || x.Candidate != nil && y.Candidate != nil && *x.Candidate == *y.Candidate)
}

// appApprovalBlueprint binds a renewed user's request to ONE original signed
// begin and its shared artifact/execution. It never accepts a new requester key,
// replacement artifact, caller supplied consumer recipe, or a retired operation.
func (p Policy) appApprovalBlueprint(s state.State, session access.Session, at int64, origin *UserOperation) (deployment.Blueprint, error) {
	return p.appApprovalBlueprintFor(s, session, at, origin, nil)
}

// A CD approval selects one already accepted sync. The original registration
// proves requester identity; the selector cannot adopt a queued Git candidate.
func (p Policy) appApprovalBlueprintFor(s state.State, session access.Session, at int64, origin *UserOperation, selection *AppApprovalSelection) (deployment.Blueprint, error) {
	if selection != nil && !selection.Valid() {
		return deployment.Blueprint{}, access.ErrDenied
	}
	if origin == nil || origin.VerifyOriginal(p.Cluster) != nil || origin.Session.User != session.User || origin.Change.Principal != session.User {
		return deployment.Blueprint{}, access.ErrDenied
	}
	if origin.Change.Action == "drain-node" {
		if selection == nil || selection.Operation == "" || selection.Candidate != nil {
			return deployment.Blueprint{}, access.ErrDenied
		}
		apps, err := p.Apps(s)
		if err != nil {
			return deployment.Blueprint{}, err
		}
		catalog, err := p.Catalog(s)
		if err != nil {
			return deployment.Blueprint{}, err
		}
		var drain NodeDrainChange
		if canonical(origin.Change.Payload, &drain) != nil {
			return deployment.Blueprint{}, ErrCatalog
		}
		for _, job := range drain.Jobs {
			if job.Operation != selection.Operation || job.Move == nil {
				continue
			}
			if job.CD != nil {
				return deployment.Blueprint{}, access.ErrDenied
			}
			registry, err := p.Volumes(s)
			if err != nil {
				return deployment.Blueprint{}, err
			}
			saved, move, ok := registry.Move(drainMoveSelection(job))
			if !ok || move.Phase != volumes.Prepared || at >= saved.ExpiresAt || !bytes.Equal(OperationBytes(saved.Origin), OperationBytes(*origin)) {
				return deployment.Blueprint{}, access.ErrDenied
			}
			blueprint, err := drainMoveBlueprint(*origin, job.Move.Begin)
			if err != nil {
				return blueprint, err
			}
			for _, step := range blueprint.Steps() {
				if catalog.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, job.Tenant, step.Action(), step.Node) != nil || catalog.AuthorizeAccepted(origin.Session, p.Cluster, origin.At, job.Tenant, step.Action(), step.Node) != nil {
					return deployment.Blueprint{}, access.ErrDenied
				}
			}
			return blueprint, nil
		}
		for _, entry := range apps.entries {
			execution, active := entry.Inventory.Execution()
			if !active || execution.ActiveOperation() != selection.Operation || !bytes.Equal(OperationBytes(entry.Origin), OperationBytes(*origin)) || !bytes.Equal(entry.Origin.Signature, origin.Signature) {
				continue
			}
			blueprint := execution.Blueprint()
			for _, step := range blueprint.Steps() {
				if catalog.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, blueprint.Scope().Tenant, step.Action(), step.Node) != nil || catalog.AuthorizeAccepted(origin.Session, p.Cluster, origin.At, blueprint.Scope().Tenant, step.Action(), step.Node) != nil {
					return deployment.Blueprint{}, access.ErrDenied
				}
			}
			return blueprint, nil
		}
		return deployment.Blueprint{}, access.ErrDenied
	}
	if origin.Change.Action == "begin-volume-move" {
		if selection != nil {
			return deployment.Blueprint{}, access.ErrDenied
		}
		return p.moveApprovalBlueprint(s, session, at, *origin)
	}
	if origin.Change.Action != "begin-app" && origin.Change.Action != "standalone-up" {
		return deployment.Blueprint{}, access.ErrDenied
	}
	var begin AppBegin
	if canonical(origin.Change.Payload, &begin) != nil {
		return deployment.Blueprint{}, ErrCatalog
	}
	c, err := p.Catalog(s)
	if err != nil {
		return deployment.Blueprint{}, err
	}
	a, err := p.Apps(s)
	if err != nil {
		return deployment.Blueprint{}, err
	}
	var b deployment.Blueprint
	entry, exists := a.entries[appKey(begin.Tenant, begin.App)]
	if exists && bytes.Equal(OperationBytes(entry.Origin), OperationBytes(*origin)) && bytes.Equal(entry.Origin.Signature, origin.Signature) {
		if selection != nil && selection.Operation != "" {
			moved, found, err := p.cdMoveApprovalBlueprint(s, session, at, a, entry, selection.Operation)
			if err != nil {
				return b, err
			}
			if found {
				return moved, nil
			}
		}
		if entry.Down != nil {
			return b, access.ErrDenied
		}
		if selection != nil {
			if entry.Delivery == nil || c.AuthorizeAccepted(origin.Session, p.Cluster, origin.At, begin.Tenant, access.ManageCD, "") != nil || c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, begin.Tenant, access.ManageCD, "") != nil {
				return b, access.ErrDenied
			}
			if selection.Candidate != nil {
				candidate, exists := entry.Delivery.CandidateSelection()
				if !exists || candidate.Candidate != *selection.Candidate || entry.Delivery.Paused() {
					return b, access.ErrDenied
				}
				_, ctx, err := p.appDeliveryAccess(s, entry)
				if err != nil {
					return b, err
				}
				// The selector already matched the exact stored candidate above.
				// Refresh only its planning bases: health observations can change
				// plan IDs without changing any source bytes or Secret uses.
				fresh, err := entry.Delivery.RebaseCandidate(entry.Delivery.Revision(), c, ctx)
				if err != nil {
					return b, access.ErrDenied
				}
				b, exists = fresh.CandidateBlueprint()
				if !exists {
					return b, access.ErrDenied
				}
			} else if t, pending := entry.Delivery.Transition(); pending {
				if entry.PendingSync == nil || entry.PendingSync.Choice.Operation != selection.Operation || entry.PendingSync.verify(*origin, entry.Inventory.Scope()) != nil || t.Mode == deployment.DeliveryDown {
					return b, access.ErrDenied
				}
				var ok bool
				b, ok = entry.Delivery.TransitionPlan()
				if !ok {
					return b, access.ErrDenied
				}
			} else {
				e, active := entry.Inventory.Execution()
				identity, err := appExecutionOrigin(entry.Origin, entry.Sync, entry.Inventory.Scope())
				if !active || err != nil || identity.Operation != selection.Operation || e.ActiveOperation() != selection.Operation {
					return b, access.ErrDenied
				}
				b = e.Blueprint()
			}
			selected := entry.Sync
			if entry.PendingSync != nil {
				selected = entry.PendingSync
			}
			if selection.Candidate != nil {
				selected = nil
			}
			if selected != nil && selected.User != nil {
				u := selected.User
				if c.AuthorizeAccepted(u.Session, p.Cluster, u.At, begin.Tenant, access.ManageCD, "") != nil {
					return b, access.ErrDenied
				}
				for _, step := range b.Steps() {
					if c.AuthorizeAccepted(u.Session, p.Cluster, u.At, begin.Tenant, step.Action(), step.Node) != nil {
						return b, access.ErrDenied
					}
				}
			}
		} else {
			e, active := entry.Inventory.Execution()
			if !active || e.ActiveOperation() != begin.Operation {
				return b, access.ErrDenied
			}
			b = e.Blueprint()
		}
	} else {
		if selection != nil {
			return b, access.ErrDenied
		}
		cmd, err := origin.Command()
		if err != nil || s.ModuleExpired(cmd) {
			return b, access.ErrDenied
		}
		if _, found := s.LookupResult(cmd); found {
			return b, access.ErrDenied
		}
		// A pending intent has no retained admission grant yet: require the
		// same current issuer/credential checks as original operation replay.
		if _, err := p.Operation(c, cmd, false); err != nil {
			return b, err
		}
		for _, upload := range a.uploads {
			if upload.User == session.User && upload.Tenant == begin.Tenant && upload.App == begin.App && upload.Deployment == begin.Deployment && upload.ID == begin.Upload {
				raw, err := upload.Complete()
				if err != nil {
					return b, err
				}
				b, err = deployment.DecodeBlueprint(raw)
				if err != nil {
					return b, err
				}
				break
			}
		}
		ctx, err := p.AppPlanning(s, session.User, begin.Tenant)
		inputErr := b.CheckAppInput()
		if origin.Change.Action == "standalone-up" {
			inputErr = b.CheckStandaloneInput()
		}
		if err != nil || inputErr != nil || b.ValidateCurrent(c, ctx) != nil {
			return b, access.ErrDenied
		}
	}
	scope := b.Scope()
	if scope.Cluster != p.Cluster || scope.Actor != session.User || scope.Tenant != begin.Tenant || scope.App != begin.App || scope.Deployment != begin.Deployment {
		return b, access.ErrDenied
	}
	for _, step := range b.Steps() {
		if c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, scope.Tenant, step.Action(), step.Node) != nil || c.AuthorizeAccepted(origin.Session, p.Cluster, origin.At, scope.Tenant, step.Action(), step.Node) != nil {
			return b, access.ErrDenied
		}
	}
	return b, nil
}

// The accepted move authorizes ONE frozen target, never a fabricated begin-app
// signature or caller-provided service/node recipe.
func (p Policy) moveApprovalBlueprint(s state.State, session access.Session, at int64, origin UserOperation) (deployment.Blueprint, error) {
	var q VolumeMoveBegin
	if canonical(origin.Change.Payload, &q) != nil || q.App == nil || q.App.Target == nil {
		return deployment.Blueprint{}, access.ErrDenied
	}
	if q.App.CD != nil {
		return deployment.Blueprint{}, access.ErrDenied
	}
	v, err := p.Volumes(s)
	if err != nil {
		return deployment.Blueprint{}, err
	}
	j, m, ok := v.Move(VolumeMoveSelection{Scope: q.Scope, ID: q.ID})
	if !ok || at < origin.At || !bytes.Equal(OperationBytes(j.Origin), OperationBytes(origin)) || !bytes.Equal(j.Origin.Signature, origin.Signature) {
		return deployment.Blueprint{}, access.ErrDenied
	}
	c, err := p.Catalog(s)
	if err != nil {
		return deployment.Blueprint{}, err
	}
	a, err := p.Apps(s)
	if err != nil {
		return deployment.Blueprint{}, err
	}
	if m.Phase == volumes.Prepared {
		if at >= j.ExpiresAt {
			return deployment.Blueprint{}, access.ErrDenied
		}
	} else {
		entry, exists := a.entries[appKey(q.Scope.Tenant, q.Scope.App)]
		execution, active := entry.Inventory.Execution()
		if !exists || !active || m.CommitRevision == 0 || !m.Irreversible || entry.Down != nil || execution.ActiveOperation() != q.App.Target.Operation || !bytes.Equal(OperationBytes(entry.Origin), OperationBytes(origin)) || !bytes.Equal(entry.Origin.Signature, origin.Signature) {
			return deployment.Blueprint{}, access.ErrDenied
		}
	}
	b, err := p.frozenMoveBlueprint(a, origin, q)
	if err != nil {
		return b, err
	}
	for _, step := range b.Steps() {
		if c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, q.Scope.Tenant, step.Action(), step.Node) != nil || c.AuthorizeAccepted(origin.Session, p.Cluster, origin.At, q.Scope.Tenant, step.Action(), step.Node) != nil {
			return deployment.Blueprint{}, access.ErrDenied
		}
	}
	return b, nil
}

func (p Policy) checkAppApprovalTarget(s state.State, session access.Session, at int64, origin *UserOperation, target secrets.Target, selections ...*AppApprovalSelection) error {
	var selection *AppApprovalSelection
	if len(selections) > 1 {
		return access.ErrDenied
	}
	if len(selections) == 1 {
		selection = selections[0]
	}
	uses, err := p.approvalUsesFor(s, session, at, origin, selection)
	if err != nil || len(uses[target.Realm]) == 0 {
		return access.ErrDenied
	}
	c, err := p.Catalog(s)
	if err != nil {
		return err
	}
	v, err := p.Vault(s)
	if err != nil {
		return err
	}
	plan, err := v.Trees[target.Realm].Plan(c, uses[target.Realm])
	if err != nil {
		return err
	}
	for _, required := range plan.Required {
		required.ApprovalID, required.IssuerPolicy = target.ApprovalID, target.IssuerPolicy
		a, _ := json.Marshal(required)
		b, _ := json.Marshal(target)
		if bytes.Equal(a, b) {
			return nil
		}
	}
	return access.ErrDenied
}
