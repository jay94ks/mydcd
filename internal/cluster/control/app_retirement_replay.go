// SPDX-License-Identifier: Apache-2.0

package control

import "github.com/jay94ks/mydcd/internal/cluster/state"

// AppRetirementReplay names one original internal Raft mutation. It neither
// replaces the app/Down/move nor authorizes a different native effect.
type AppRetirementReplay struct {
	Tenant, App, Retirement, Key, Phase string
	Command                             [32]byte
}

func (p Policy) reduceAppRetirementReplay(s state.State, a Apps, op UserOperation) (map[string][]byte, state.Code) {
	var q AppRetirementReplay
	if canonical(op.Change.Payload, &q) != nil || q.Retirement == "" || q.Key == "" || q.Command == ([32]byte{}) ||
		(q.Phase != "drain" && q.Phase != "proof" && q.Phase != "delete") {
		return nil, state.Invalid
	}
	entry, found := a.entries[appKey(q.Tenant, q.App)]
	r, retiring := entry.Inventory.Retirement()
	if !found || !retiring || r.ID != q.Retirement || entry.Inventory.Revision() != op.Change.Expected {
		return nil, state.ConditionFailed
	}
	if p.authorizeAppRemoval(s, entry) != nil {
		return nil, state.Forbidden
	}
	c, err := p.Catalog(s)
	if err != nil {
		return nil, state.Invalid
	}
	i, err := entry.Inventory.AuthorizeRemovalReplay(op.Change.Expected, c, op.Session.User, q.Key, q.Phase, op.RequestID, q.Command, s)
	if err != nil {
		return nil, state.ConditionFailed
	}
	entry.Inventory = i
	a.entries[appKey(q.Tenant, q.App)] = entry
	return p.appsCheckpoint(s, a, uint64(op.At))
}
