// SPDX-License-Identifier: Apache-2.0

package control

import "github.com/jay94ks/seafield/internal/cluster/state"

// AppStepReplay names one deploy stage whose command send was left Unknown
// and lets its owner send that exact command once more. It changes no plan,
// target or native effect; the shared ledger deduplicates the command.
type AppStepReplay struct {
	Tenant, App, Operation, Key string
	Command                     [32]byte
}

func (p Policy) reduceAppStepReplay(s state.State, a Apps, op UserOperation) (map[string][]byte, state.Code) {
	var q AppStepReplay
	if canonical(op.Change.Payload, &q) != nil || q.Tenant == "" || q.App == "" || q.Operation == "" || q.Key == "" || q.Command == ([32]byte{}) {
		return nil, state.Invalid
	}
	entry, found := a.entries[appKey(q.Tenant, q.App)]
	if !found || entry.Inventory.Revision() != op.Change.Expected {
		return nil, state.ConditionFailed
	}
	if _, retiring := entry.Inventory.Retirement(); retiring {
		return nil, state.ConditionFailed
	}
	e, ok := entry.Inventory.Execution()
	if !ok || e.ActiveOperation() != q.Operation {
		return nil, state.ConditionFailed
	}
	c, err := p.Catalog(s)
	if err != nil {
		return nil, state.Invalid
	}
	if p.authorizeAppStep(s, c, entry, e, q.Key) != nil {
		return nil, state.Forbidden
	}
	e, err = e.AuthorizeReplay(e.Revision(), q.Key, op.RequestID, q.Command, s)
	if err != nil {
		return nil, state.ConditionFailed
	}
	if entry.Inventory, err = p.advanceAppInventory(s, entry.Inventory, e); err != nil {
		return nil, state.ConditionFailed
	}
	a.entries[appKey(q.Tenant, q.App)] = entry
	return p.appsCheckpoint(s, a, uint64(op.At))
}
