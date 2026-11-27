// SPDX-License-Identifier: Apache-2.0

package control

import (
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/state"
)

// AppCDApproverChange is the grant-cd-approver / revoke-cd-approver payload
// (ManageCD on the tenant). Expected is the CD record revision. A granted
// user may approve or reject this app's candidates while they can read the
// tenant (deployment.Delivery.MayDecide).
type AppCDApproverChange struct {
	Tenant, App, User string
}

func (q AppCDApproverChange) valid() bool {
	return lifecycle.ValidID(q.Tenant) && lifecycle.ValidID(q.App) && lifecycle.ValidID(q.User)
}

func (p Policy) reduceCDApprover(s state.State, a Apps, op UserOperation) (map[string][]byte, state.Code) {
	var q AppCDApproverChange
	if canonical(op.Change.Payload, &q) != nil || !q.valid() {
		return nil, state.Invalid
	}
	key := appKey(q.Tenant, q.App)
	entry, ok := a.entries[key]
	if !ok || entry.Delivery == nil || entry.Down != nil {
		return nil, state.ConditionFailed
	}
	users, err := p.Catalog(s)
	if err != nil {
		return nil, state.Invalid
	}
	d, err := entry.Delivery.SetApprover(op.Change.Expected, users, op.Session.User, q.User, op.Change.Action == "grant-cd-approver")
	if err != nil {
		return nil, state.ConditionFailed
	}
	entry.Delivery = &d
	a.entries[key] = entry
	return p.appsCheckpoint(s, a, uint64(op.At))
}
