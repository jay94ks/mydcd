// SPDX-License-Identifier: Apache-2.0

package secrets

import "slices"

// Public ownership views do not expose provider material. Copies keep FSM
// candidates independent of the currently published tree.
func (t Tree) Objects() []Object {
	var out []Object
	for _, o := range t.objects {
		out = append(out, ownObject(o))
	}
	slices.SortFunc(out, func(a, b Object) int {
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	return out
}
func (t Tree) Writes() []WriteRecord {
	var out []WriteRecord
	for _, w := range t.writes {
		out = append(out, ownWrite(w))
	}
	slices.SortFunc(out, func(a, b WriteRecord) int {
		if a.Request.ID < b.Request.ID {
			return -1
		}
		if a.Request.ID > b.Request.ID {
			return 1
		}
		return 0
	})
	return out
}
func (t Tree) WriteProfile(id string) (WriteProfile, bool) { return t.profile(id) }
func (t Tree) Quiescent() bool {
	for _, o := range t.objects {
		if o.PendingWrite != "" || o.PasswordChange != "" {
			return false
		}
	}
	for _, w := range t.writes {
		if !writeTerminal(w) {
			return false
		}
	}
	return true
}
func (a Approvals) Quiescent() bool { return len(a.usages) == 0 && allApprovalConsumersReturned(a) }
func allApprovalConsumersReturned(a Approvals) bool {
	for _, r := range a.records {
		if len(r.Consumers) != 0 {
			return false
		}
	}
	return true
}
