// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"slices"

	"github.com/jay94ks/seafield/internal/access"
)

// REQ-9 (mock): the incident-response account. A system administrator
// registers or turns off another account's public key with add-credential
// and disable-credential. set-account-scope limits the
// actions the account's operations may carry (an allow list; any other
// action is Forbidden, on top of the usual permission checks) and can mark
// the account key-only (no password or token login, none can be issued).
// Operations can carry display-only reason metadata, never used for
// permission.

const ActionSetAccountScope = "set-account-scope"

// AccountScopeChange: the set-account-scope payload (system admin),
// sfcd's access.AccountScope {User, Add, Remove, Unlimited, KeyOnly?}: a
// change to the ceiling, not the whole list. Expected = the account
// revision. Every session of the account ends.
type AccountScopeChange = access.AccountScope

// AccountScope: `account-scope`, read from the account record
// (User.Operations, User.AutomationOnly). Revision is the account revision,
// the Expected of the next set-account-scope.
type AccountScope struct {
	User     string   // user ID
	Actions  []string `json:",omitempty"` // allowed actions; empty = no limit
	KeyOnly  bool     `json:",omitempty"`
	Revision uint64   `json:",omitempty"`
}

func accountScopeOf(user string, operations []string, keyOnly bool, revision uint64) AccountScope {
	return AccountScope{User: user, Actions: slices.Clone(operations), KeyOnly: keyOnly, Revision: revision}
}

// OperationReason: display metadata of one operation (each field ≤ 256).
// In sfcd it would be part of the signed envelope; the mock keeps it
// beside the ledger entry.
type OperationReason struct {
	Reason     string `json:",omitempty"` // e.g. "autofix"
	Incident   string `json:",omitempty"`
	ApprovedBy string `json:",omitempty"` // username, when a person approved it
}
