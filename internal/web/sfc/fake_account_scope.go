// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"context"
	"errors"
	"slices"

	"github.com/jay94ks/seafield/internal/access"
)

// The fake keeps the scope where sfcd does: User.Operations (the account's
// action ceiling) and User.AutomationOnly (key-only). set-account-scope
// changes only those two by its delta and bumps the account revision, as
// sfcd's access.Catalog.SetAccountScope.

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
	if decodePayload(op.Change.Payload, &q) != nil || q.User == "" || !access.ValidCredentialOperations(nilIfEmpty(q.Add)) || !access.ValidCredentialOperations(nilIfEmpty(q.Remove)) ||
		len(q.Add)+len(q.Remove) == 0 && !q.Unlimited && q.KeyOnly == nil || q.Unlimited && len(q.Add)+len(q.Remove) > 0 {
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
	ops := slices.Clone(u.rec.Operations)
	if q.Unlimited {
		if ops == nil {
			return errCAS
		}
		ops = nil
	}
	for _, a := range q.Remove {
		i := slices.Index(ops, a)
		if i < 0 || slices.Contains(q.Add, a) {
			return errCAS
		}
		ops = slices.Delete(ops, i, i+1)
	}
	for _, a := range q.Add {
		if slices.Contains(u.rec.Operations, a) {
			return errCAS
		}
		ops = append(ops, a)
	}
	if !q.Unlimited && len(ops) == 0 && u.rec.Operations != nil {
		return errors.New("lifting the limit is Unlimited")
	}
	if u.rec.SystemAdmin && len(ops) > 0 {
		return errors.New("a system administrator takes no action ceiling")
	}
	keyOnly := u.rec.AutomationOnly
	if q.KeyOnly != nil {
		if *q.KeyOnly == keyOnly {
			return errCAS
		}
		keyOnly = *q.KeyOnly
	}
	if keyOnly && slices.ContainsFunc(u.rec.Credentials, func(cr Credential) bool { return cr.Enabled && cr.Method != MethodPrivateKey }) {
		return errors.New("key-only account has a password or token login")
	}
	rec := cloneUser(u.rec)
	rec.Operations = nil
	if len(ops) > 0 {
		rec.Operations = slices.Sorted(slices.Values(ops))
	}
	rec.AutomationOnly, rec.Revision = keyOnly, next
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
