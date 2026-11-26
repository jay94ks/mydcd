// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"encoding/json"
	"errors"
	"path"
	"regexp"
	"slices"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/secrets"
)

// Vault object policy changes with the real payload types and the
// secrets.Tree rules: vault-acl / vault-move / vault-approval-age need an
// active object (ManageSecrets); vault-revoke makes it revoking and
// vault-retire then retires an empty, unreferenced (no live REQ-44 usage),
// revoking object
// (cleanup authority). Expected is the object revision. The root group
// (ID = tenant) has no row in the fake. The cluster Vault (realm "") exists
// only after vault-init, and its root group is a row (Parent ""), as in
// mydcd's page.

// fillVaultIDs derives ID / Parent / Status of rows that lack them.
func (w *world) fillVaultIDs() {
	for i := range w.vault {
		v := &w.vault[i]
		if v.ID == "" {
			v.ID = path.Base(v.Path)
		}
		if v.Parent == "" {
			v.Parent = v.Realm
			if d := path.Dir(v.Path); d != "." {
				v.Parent = path.Base(d)
			}
		}
		if v.Status == "" {
			v.Status = string(secrets.Active)
		}
	}
}

func sortedNames(names []string) ([]string, bool) {
	out := slices.Clone(names)
	slices.Sort(out)
	for i, n := range out {
		if n == "" || i > 0 && out[i-1] == n {
			return nil, false
		}
	}
	if out == nil {
		out = []string{}
	}
	return out, true
}

func (c *fakeConn) applyVaultObject(op UserOperation, actor string, next uint64) error {
	w := c.f.w
	ch := op.Change
	var sel struct{ Realm, ID string }
	if json.Unmarshal(ch.Payload, &sel) != nil || sel.ID == "" {
		return errors.New("payload")
	}
	if !w.canManageRealm(actor, sel.Realm) {
		return errForbidden
	}
	i := slices.IndexFunc(w.vault, func(v VaultView) bool { return v.Realm == sel.Realm && v.ID == sel.ID })
	if i < 0 || w.vault[i].Revision != ch.Expected {
		return errCAS
	}
	v := w.vault[i]
	active := v.Status == string(secrets.Active)
	switch ch.Action {
	case ActionVaultACL:
		var q control.VaultACL
		if decodePayload(ch.Payload, &q) != nil {
			return errors.New("payload")
		}
		var ok [5]bool
		var a VaultACL
		a.Users, ok[0] = sortedNames(q.ACL.Users)
		a.Services, ok[1] = sortedNames(q.ACL.Services)
		a.DenyUsers, ok[2] = sortedNames(q.ACL.DenyUsers)
		a.DenyServices, ok[3] = sortedNames(q.ACL.DenyServices)
		a.TenantGrants, ok[4] = sortedNames(q.ACL.TenantGrants)
		if slices.Contains(ok[:], false) || len(a.TenantGrants) > 0 || !active {
			return errCAS // tenant grants: only a shared realm's root
		}
		if len(a.TenantGrants) == 0 {
			a.TenantGrants = nil
		}
		v.ACL = a
	case ActionVaultMove:
		var q control.VaultMove
		if decodePayload(ch.Payload, &q) != nil || q.Parent == "" {
			return errors.New("payload")
		}
		parentPath := ""
		if q.Parent != sel.Realm {
			j := slices.IndexFunc(w.vault, func(p VaultView) bool { return p.Realm == sel.Realm && p.ID == q.Parent })
			if j < 0 || w.vault[j].Kind != "group" || w.vault[j].Status != string(secrets.Active) {
				return errCAS
			}
			parentPath = w.vault[j].Path
		}
		if !active || v.Parent == q.Parent || q.Parent == v.ID {
			return errCAS
		}
		v.Parent, v.Path = q.Parent, path.Join(parentPath, v.ID)
	case ActionVaultApprovalAge:
		var q control.VaultAge
		if decodePayload(ch.Payload, &q) != nil || q.Seconds < 0 {
			return errors.New("payload")
		}
		if v.Kind != "group" || !active {
			return errCAS
		}
		v.MaxApprovalAge = q.Seconds
	case ActionVaultRevoke:
		if v.Status == string(secrets.Retired) {
			return errCAS
		}
		if v.Status == string(secrets.Revoking) {
			return nil
		}
		v.Status = string(secrets.Revoking)
	case ActionVaultRetire:
		children := slices.ContainsFunc(w.vault, func(o VaultView) bool {
			return o.Realm == sel.Realm && o.Parent == v.ID && o.Status != string(secrets.Retired)
		})
		if v.Status != string(secrets.Revoking) || children || v.PendingWrite != "" || w.vaultLiveUse(sel.Realm, v.ID) {
			return errCAS
		}
		v.Status = string(secrets.Retired)
	default:
		return errors.New("action")
	}
	v.Revision = next
	w.vault[i] = v
	w.vaultRev[sel.Realm] = next
	return nil
}

// applyVaultInit creates a Vault tree: in the fake only the cluster Vault
// (tenant trees exist from the fixture). Expected 0; system administrators.
func (c *fakeConn) applyVaultInit(op UserOperation, actor string, next uint64) error {
	w := c.f.w
	var q control.VaultRealm
	if decodePayload(op.Change.Payload, &q) != nil || q.Root == "" || !vaultRootRE.MatchString(q.Root) {
		return errors.New("payload")
	}
	if q.Realm != "" {
		if !w.canManage(actor, q.Realm) {
			return errForbidden
		}
		return errCAS // the fixture's tenant trees already exist
	}
	if !w.admin(actor) {
		return errForbidden
	}
	if op.Change.Expected != 0 || slices.ContainsFunc(w.vault, func(v VaultView) bool { return v.Realm == "" }) {
		return errCAS
	}
	w.vault = append(w.vault, VaultView{Realm: "", ID: q.Root, Path: q.Root, Kind: "group", Status: string(secrets.Active), Revision: next})
	w.vaultRev[""] = next
	return nil
}

var vaultRootRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
