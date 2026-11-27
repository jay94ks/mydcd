// SPDX-License-Identifier: Apache-2.0

package access

// InstallInitialCredential is the deterministic publication boundary. Provider
// authentication and write evidence belong to the control/adapter boundary.
// It never replaces an existing method: a new password or token needs every
// earlier one of its kind turned off (a new invitation after a used one).
func (c Catalog) InstallInitialCredential(actor, user string, expected uint64, credential Credential) (Catalog, error) {
	if !c.SystemAllowed(actor) {
		return c, ErrDenied
	}
	u, ok := c.User(user)
	if !ok || u.Revision != expected {
		return c, ErrConflict
	}
	if !u.Enabled || u.AutomationOnly || credential.Method != Password && credential.Method != Token || !credential.Enabled || credential.Operations != nil || credential.OneTime != (credential.Method == Token) {
		return c, ErrInvalid
	}
	for _, old := range u.Credentials {
		if old.Enabled && old.Method == credential.Method || old.ID == credential.ID {
			return c, ErrConflict
		}
	}
	u.Credentials = append(u.Credentials, credential)
	u.Revision = 0
	return c.replaceUser(expected, u)
}
