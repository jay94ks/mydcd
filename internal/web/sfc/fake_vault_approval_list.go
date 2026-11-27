// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"context"
	"errors"
	"slices"

	"github.com/jay94ks/seafield/internal/secrets"
)

// recordApproval keeps the REQ-42 row of an approval ApproveVault committed.
func (w *world) recordApproval(t secrets.Target, issuer string, at int64) {
	if w.approvalRows == nil {
		w.approvalRows = map[string]*VaultApprovalRow{}
	}
	if r := w.approvalRows[t.ApprovalID]; r != nil && !r.Revoked {
		return
	}
	row := &VaultApprovalRow{ID: t.ApprovalID, Realm: t.Realm, Group: t.Group, User: t.User, App: t.App, Deployment: t.Deployment,
		Services: slices.Clone(t.Services), ApprovedAt: at, Issuer: issuer}
	for _, n := range t.Nodes {
		row.Nodes = append(row.Nodes, n.ID)
	}
	if i := slices.IndexFunc(w.vault, func(v VaultView) bool { return v.Realm == t.Realm && v.ID == t.Group }); i >= 0 && w.vault[i].MaxApprovalAge > 0 {
		row.ExpiresAt = at + w.vault[i].MaxApprovalAge
	}
	w.approvalRows[t.ApprovalID] = row
	w.approvalRev++
}

// vaultApprovals: the vault-approvals rows PublicRead pages.
// ManageSecrets in the realm or a system administrator sees every approval
// of the realm; another reader of the realm sees only their own. app "" =
// all apps. The page's Collection is Vault's Page.ApprovalRevision.
func (c *fakeConn) vaultApprovals(ctx context.Context, realm, app, after string) (VaultApprovalPage, error) {
	const m = "vault-approvals"
	if err := checkAfter(m, after); err != nil {
		return VaultApprovalPage{}, err
	}
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return VaultApprovalPage{}, err
	}
	defer c.unlock()
	w := c.f.w
	all := w.admin(user) || w.canManage(user, realm)
	if !all && !w.canRead(user, realm) {
		return VaultApprovalPage{}, fail(m, CodeDenied, "")
	}
	var items []VaultApprovalRow
	for _, id := range sortedKeys(w.approvalRows) {
		r := w.approvalRows[id]
		if r.Realm != realm || app != "" && r.App != app || !all && r.User != user {
			continue
		}
		v := *r
		v.Services, v.Nodes = slices.Clone(r.Services), slices.Clone(r.Nodes)
		items = append(items, v)
	}
	p := paginate(items, func(r VaultApprovalRow) string { return r.ID }, after, c.f.pageSize, w.root)
	p.Collection = w.approvalRev
	return p, nil
}

// applyRevokeApproval: secrets.Approvals.Revoke — ManageSecrets in the
// realm (cleanup) or a system administrator, Expected = the Approvals
// revision; revoking twice is a no-op. The approval no longer counts for a
// begin-app.
func (c *fakeConn) applyRevokeApproval(op UserOperation, actor string) error {
	w := c.f.w
	var q VaultApprovalSelection
	if decodePayload(op.Change.Payload, &q) != nil || q.ID == "" {
		return errors.New("payload")
	}
	r := w.approvalRows[q.ID]
	if r == nil {
		return errors.New("no approval")
	}
	if !w.admin(actor) && !w.canManage(actor, r.Realm) {
		return errForbidden
	}
	if op.Change.Expected != w.approvalRev {
		return errCAS
	}
	if r.Revoked {
		return nil
	}
	r.Revoked, r.RevokedAt = true, c.f.now().Unix()
	for k, t := range w.approvals {
		if t.ApprovalID == q.ID {
			delete(w.approvals, k)
		}
	}
	w.approvalRev++
	return nil
}
