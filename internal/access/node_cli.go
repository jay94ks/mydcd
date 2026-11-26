// SPDX-License-Identifier: Apache-2.0

package access

import "slices"

// NodeCLIPolicy is committed alongside users. Revision is the catalog ordinal
// of the last explicit change, not a wall clock or a session issuance cutoff.
// An absent policy retains the old default: node CLI operation is not disabled.
type NodeCLIPolicy struct {
	Revision                uint64
	DisableNodeCLIOperation bool `json:"disable_node_cli_operation"`
}

func (c Catalog) NodeCLI() NodeCLIPolicy { return c.nodeCLI }

// WithNodeKeys supplies the installed cluster's public identity policy to this
// catalog view. Membership remains in its existing committed Directory; it is
// not copied into the access checkpoint or another membership database.
func (c Catalog) WithNodeKeys(keys [][32]byte) Catalog {
	c.nodeKeys = make(map[[32]byte]bool, len(keys))
	for _, key := range keys {
		if key != ([32]byte{}) {
			c.nodeKeys[key] = true
		}
	}
	return c
}

func (c Catalog) manager(actor, tenant string) bool {
	m, exists := c.members[memberKey(tenant, actor)]
	t, found := c.tenants[tenant]
	return exists && found && m.Enabled && m.Role == Manager && t.Enabled && t.Phase != TenantDeleted
}

func (c Catalog) administrator(actor string) bool {
	if c.SystemAllowed(actor) {
		return true
	}
	u, found := c.users[actor]
	if !found || !u.Enabled {
		return false
	}
	for _, m := range c.members {
		if m.User == actor && c.manager(actor, m.Tenant) {
			return true
		}
	}
	return false
}

// VerifyManagementApproval checks the independent approval needed to start a
// new command under the node CLI policy. It does not replace current session,
// token scope or action authorization, and is not used to revoke old accepted
// grants merely because the global option was enabled afterwards.
func (c Catalog) VerifyManagementApproval(s Session) error {
	if c.VerifySessionApproval(s) != nil || !c.administrator(s.User) || c.nodeKeys[s.Approval.PublicKey] {
		return ErrDenied
	}
	return nil
}

func (c Catalog) hasApprovalAdministrator() bool {
	for _, u := range c.users {
		if !u.Enabled || !u.SystemAdmin {
			continue
		}
		for _, credential := range u.Credentials {
			if credential.Enabled && credential.Method == PrivateKey && !c.nodeKeys[credential.PublicKey] && (credential.Operations == nil || slices.Contains(credential.Operations, "put-user")) {
				return true
			}
		}
	}
	return false
}

// ValidateNodeCLI also runs after membership changes: installing an admin's
// last independent key as a node key cannot silently lock policy management.
func (c Catalog) ValidateNodeCLI() error {
	if c.nodeCLI.Revision > c.revision || c.nodeCLI.DisableNodeCLIOperation &&
		(c.nodeCLI.Revision == 0 || !c.hasApprovalAdministrator()) {
		return ErrInvalid
	}
	return nil
}

// SetNodeCLI uses the policy's own CAS while retaining the catalog/root CAS in
// its signed outer operation. The control adapter additionally requires a
// verified independent admin approval for BOTH on and off, even from default.
func (c Catalog) SetNodeCLI(actor string, expected uint64, disable bool) (Catalog, error) {
	if !c.SystemAllowed(actor) {
		return c, ErrDenied
	}
	if c.nodeCLI.Revision != expected {
		return c, ErrConflict
	}
	if c.nodeCLI.Revision != 0 && c.nodeCLI.DisableNodeCLIOperation == disable {
		return c, nil
	}
	n, err := c.clone()
	if err != nil {
		return c, err
	}
	n.nodeCLI = NodeCLIPolicy{Revision: n.revision, DisableNodeCLIOperation: disable}
	if n.ValidateNodeCLI() != nil {
		return c, ErrDenied
	}
	return n, nil
}
