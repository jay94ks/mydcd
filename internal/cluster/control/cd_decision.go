// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
)

type AppCDDecisionChange struct {
	Strict            bool `json:",omitempty"`
	Tenant, App       string
	Candidate, Target [32]byte
}

func (q AppCDDecisionChange) valid() bool {
	return lifecycle.ValidID(q.Tenant) && lifecycle.ValidID(q.App) && q.Candidate != ([32]byte{}) && q.Target != ([32]byte{})
}
func validAppCDDecisionChange(c Change) bool {
	var q AppCDDecisionChange
	return (c.Action == "cd-approve" || c.Action == "cd-reject") && c.Expected > 0 && canonical(c.Payload, &q) == nil && q.valid()
}

func AppCDDecisionCASAllowed(c Change) bool {
	var q AppCDDecisionChange
	return validAppCDDecisionChange(c) && canonical(c.Payload, &q) == nil && !q.Strict
}

type AppCDDecision struct {
	Origin    UserOperation
	Selection deployment.DeliverySelection
}
type AppCDDecisionView struct {
	Action, User string
	At           int64
	Reason       *OperationReason `json:",omitempty"`
	Selection    deployment.DeliverySelection
}

func (d AppCDDecision) view() *AppCDDecisionView {
	out := &AppCDDecisionView{Action: d.Origin.Change.Action, User: d.Origin.Session.User, At: d.Origin.At, Selection: d.Selection}
	if d.Origin.Reason != nil {
		v := *d.Origin.Reason
		out.Reason = &v
	}
	return out
}
func validCDDecision(d *AppCDDecision, scope deployment.AppScope) bool {
	if d == nil {
		return true
	}
	var q AppCDDecisionChange
	return d.Origin.VerifyOriginal(scope.Cluster) == nil && validAppCDDecisionChange(d.Origin.Change) && canonical(d.Origin.Change.Payload, &q) == nil && q.Tenant == scope.Tenant && q.App == scope.App && q.Candidate == d.Selection.Candidate && d.Selection.Artifact != ([32]byte{}) && d.Selection.Intent != ([32]byte{})
}
func (d AppCDDecision) digest() [32]byte {
	return sha256.Sum256(append([]byte("mydc-cd-decision-1\x00"), OperationBytes(d.Origin)...))
}
func acceptedCDApproval(users access.Catalog, entry appEntry) bool {
	d := entry.CDDecision
	if d == nil || d.Origin.Change.Action != "cd-approve" || entry.Delivery == nil || !entry.Delivery.ExplicitApprovalReady(users) {
		return false
	}
	selected, ok := entry.Delivery.CandidateSelection()
	return ok && selected.Artifact == d.Selection.Artifact && selected.Intent == d.Selection.Intent && selected.Commit == d.Selection.Commit && users.OperationAllowed(d.Origin.Session, "cd-approve") == nil && users.AuthorizeAccepted(d.Origin.Session, d.Origin.Session.Cluster, d.Origin.At, entry.Inventory.Scope().Tenant, access.Read, "") == nil && entry.Delivery.MayDecide(users, d.Origin.Session.User)
}
func (p Policy) reduceCDDecision(s state.State, a Apps, op UserOperation) (map[string][]byte, state.Code) {
	var q AppCDDecisionChange
	if !validAppCDDecisionChange(op.Change) || canonical(op.Change.Payload, &q) != nil {
		return nil, state.Invalid
	}
	entry, ok := a.entries[appKey(q.Tenant, q.App)]
	if !ok || entry.Delivery == nil || entry.Down != nil || entry.PendingSync != nil || op.Change.Expected > entry.Delivery.Revision() || q.Strict && op.Change.Expected != entry.Delivery.Revision() || q.Target != appSyncTarget(entry) {
		return nil, state.ConditionFailed
	}
	selected, ok := entry.Delivery.CandidateSelection()
	if !ok || selected.Candidate != q.Candidate {
		return nil, state.ConditionFailed
	}
	users, err := p.Catalog(s)
	if err != nil {
		return nil, state.Invalid
	}
	ctx, err := p.AppPlanning(s, entry.Delivery.Principal(), q.Tenant)
	if err != nil {
		return nil, state.ConditionFailed
	}
	scope := entry.Inventory.Scope()
	ctx.Actor = entry.Delivery.Principal()
	ctx.Project = q.App
	ctx.Deployment = scope.Deployment
	if begin, err := appOriginBegin(entry.Origin, scope); err == nil {
		ctx.DefaultNode = begin.DefaultNode
	}
	d := *entry.Delivery
	d, err = d.RebaseCandidate(d.Revision(), users, ctx)
	if err != nil {
		return nil, state.ConditionFailed
	}
	current, ok := d.CandidateSelection()
	if !ok || current.Artifact != selected.Artifact || current.Intent != selected.Intent || current.Commit != selected.Commit {
		return nil, state.ConditionFailed
	}
	reason := ""
	if op.Reason != nil {
		reason = op.Reason.Text
	}
	if op.Change.Action == "cd-approve" {
		d, err = d.ApproveDecision(d.Revision(), users, ctx, op.Session.User, current.Candidate, reason)
	} else {
		d, err = d.Reject(d.Revision(), users, ctx, op.Session.User, current.Candidate, reason)
	}
	if err != nil {
		return nil, state.ConditionFailed
	}
	entry.Delivery = &d
	entry.CDDecision = &AppCDDecision{Origin: op, Selection: selected}
	a.entries[appKey(q.Tenant, q.App)] = entry
	return p.appsCheckpoint(s, a, uint64(op.At))
}
