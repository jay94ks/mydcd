// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"context"
	"errors"
	"slices"

	"github.com/jay94ks/mydcd/internal/access"
)

// The fake keeps the scope where mydcd does: User.Operations (the account's
// action ceiling) and User.AutomationOnly (key-only). set-account-scope
// replaces only those two and bumps the account revision, as mydcd's
// access.Catalog.SetAccountScope.

func (w *world) scopeAllows(user, action string) bool {
	u := w.users[user]
	return u == nil || u.rec.Operations == nil || slices.Contains(u.rec.Operations, action)
}

func (w *world) keyOnly(user string) bool {
	u := w.users[user]
	return u != nil && u.rec.AutomationOnly
}

func (c *fakeConn) applyAccountScope(op UserOperation, actor string, next uint64) error {
	w := c.f.w
	var q AccountScopeChange
	if decodePayload(op.Change.Payload, &q) != nil || q.User == "" || !access.ValidCredentialOperations(nilIfEmpty(q.Operations)) {
		return errors.New("payload")
	}
	if !w.admin(actor) {
		return errForbidden
	}
	u := w.users[q.User]
	if u == nil {
		return errors.New("user")
	}
	if op.Change.Expected != u.rec.Revision {
		return errCAS
	}
	if u.rec.SystemAdmin && len(q.Operations) > 0 {
		return errors.New("a system administrator takes no action ceiling")
	}
	if q.KeyOnly && slices.ContainsFunc(u.rec.Credentials, func(cr Credential) bool { return cr.Enabled && cr.Method != MethodPrivateKey }) {
		return errors.New("key-only account has a password or token login")
	}
	rec := cloneUser(u.rec)
	rec.Operations = nil
	if len(q.Operations) > 0 {
		rec.Operations = slices.Sorted(slices.Values(q.Operations))
	}
	rec.AutomationOnly, rec.Revision = q.KeyOnly, next
	u.rec = rec
	return nil
}

func nilIfEmpty(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}

// AccountScope: `account-scope` (system admin, or the account itself).
// No scope reads as {User} with Revision 0.
func (c *fakeConn) AccountScope(ctx context.Context, user string) (AccountScope, error) {
	const m = "account-scope"
	me, err := c.lockSession(ctx, m)
	if err != nil {
		return AccountScope{}, err
	}
	defer c.unlock()
	w := c.f.w
	if me != user && !w.admin(me) {
		return AccountScope{}, fail(m, CodeDenied, "")
	}
	u := w.users[user]
	if u == nil {
		return AccountScope{}, fail(m, CodeMissing, "")
	}
	return accountScopeOf(u.rec.ID, u.rec.Operations, u.rec.AutomationOnly, u.rec.Revision), nil
}

func validReason(r OperationReason) bool {
	q := opReason(r)
	return q == nil || q.Valid()
}

// PrepareReason is Prepare with reason metadata for the operation.
func (c *fakeConn) PrepareReason(ctx context.Context, change Change, rootRevision uint64, reason OperationReason) (SignedOp, error) {
	return c.prepareReason(ctx, "", change, rootRevision, reason)
}

// PrepareRequestReason is PrepareRequest with reason metadata (e.g. an
// incident's put-certificate, whose RequestID is the receipt's Request).
func (c *fakeConn) PrepareRequestReason(ctx context.Context, requestID string, change Change, rootRevision uint64, reason OperationReason) (SignedOp, error) {
	if !validRequestID(requestID) {
		return nil, fail("prepare", CodeInvalid, "request ID")
	}
	return c.prepareReason(ctx, requestID, change, rootRevision, reason)
}

func (c *fakeConn) prepareReason(ctx context.Context, requestID string, change Change, rootRevision uint64, reason OperationReason) (SignedOp, error) {
	if !validReason(reason) {
		return nil, fail("prepare", CodeInvalid, "reason: at most 512 characters, incident at most 128 bytes on one line")
	}
	return c.prepare(ctx, requestID, change, rootRevision, opReason(reason))
}
