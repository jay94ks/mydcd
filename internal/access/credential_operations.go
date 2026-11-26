// SPDX-License-Identifier: Apache-2.0

package access

import "slices"

// Equal compares the public credential, including its optional action ceiling.
// Nil and empty ceilings are distinct: only nil preserves ordinary authority.
func (c Credential) Equal(other Credential) bool {
	return c.ID == other.ID && c.Method == other.Method && c.PublicKey == other.PublicKey &&
		c.VerifierRef == other.VerifierRef && c.Enabled == other.Enabled && c.Label == other.Label && c.OneTime == other.OneTime && equalVolumeFileGrants(c.VolumeFiles, other.VolumeFiles) &&
		(c.Operations == nil) == (other.Operations == nil) && slices.Equal(c.Operations, other.Operations)
}

// A nil list preserves ordinary credentials. An explicit list is an additional
// ceiling on typed management action names, never a role or tenant grant.
func ValidCredentialOperations(operations []string) bool {
	if operations == nil {
		return true
	}
	if len(operations) == 0 || len(operations) > 64 {
		return false
	}
	seen := map[string]bool{}
	for _, operation := range operations {
		if !identifier(operation) || seen[operation] {
			return false
		}
		seen[operation] = true
	}
	return true
}

func ownCredentials(credentials []Credential) []Credential {
	out := slices.Clone(credentials)
	for i := range out {
		out[i].VolumeFiles = ownVolumeFileGrants(out[i].VolumeFiles)
		out[i].Operations = slices.Clone(out[i].Operations)
		slices.Sort(out[i].Operations)
	}
	return out
}

// OperationAllowed is used after normal session authentication and before every
// typed management reducer. Result lookup and settling an already accepted
// original do not turn into authorization for a new operation.
func (c Catalog) OperationAllowed(session Session, operation string) error {
	user, ok := c.users[session.User]
	if !ok || !user.Enabled || user.Revision != session.AccountRevision || !identifier(operation) || user.Operations != nil && !slices.Contains(user.Operations, operation) {
		return ErrDenied
	}
	for _, credential := range user.Credentials {
		if credential.ID == session.Credential && credential.Enabled {
			if credential.Operations != nil && !slices.Contains(credential.Operations, operation) {
				return ErrDenied
			}
			if session.Approval != nil {
				// A restricted approval key cannot widen an unrestricted
				// password/token or another credential of the same account.
				for _, approver := range user.Credentials {
					if approver.Enabled && approver.Method == PrivateKey && approver.PublicKey == session.Approval.PublicKey {
						if approver.Operations == nil || slices.Contains(approver.Operations, operation) {
							return nil
						}
						return ErrDenied
					}
				}
				return ErrDenied
			}
			return nil
		}
	}
	return ErrDenied
}

// AccountScope is the set-account-scope payload: the account's action
// ceiling (empty = none) and whether it may log in with private keys only
// (User.AutomationOnly). Expected is the account revision.
type AccountScope struct {
	User       string
	Operations []string `json:",omitempty"`
	KeyOnly    bool     `json:",omitempty"`
}

// SetAccountScope replaces only the account's ceiling and key-only flag. It
// goes through the same full-account boundary as PutUser, so a key-only
// account with an enabled password or token, or a ceiling on a system
// administrator, is refused, and every earlier session of the account ends.
func (c Catalog) SetAccountScope(actor string, expected uint64, q AccountScope) (Catalog, error) {
	if !c.SystemAllowed(actor) {
		return c, ErrDenied
	}
	u, ok := c.users[q.User]
	if !ok {
		return c, ErrInvalid
	}
	u.Operations = nil
	if len(q.Operations) > 0 {
		u.Operations = slices.Clone(q.Operations)
	}
	u.AutomationOnly = q.KeyOnly
	u.Revision = 0
	return c.replaceUser(expected, u)
}
