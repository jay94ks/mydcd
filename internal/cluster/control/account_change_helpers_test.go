// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
)

// accountFields is u as put-user changes an existing account: its own fields
// only, never its login methods or ceiling.
func accountFields(u access.User) access.User {
	return access.User{ID: u.ID, Username: u.Username, Enabled: u.Enabled, SystemAdmin: u.SystemAdmin}
}

// reissued is session signed again by node for its account's current revision.
func reissued(p Policy, s state.State, node ed25519.PrivateKey, session access.Session) access.Session {
	c, _ := p.Catalog(s)
	u, _ := c.User(session.User)
	session.AccountRevision = u.Revision
	session.Signature = ed25519.Sign(node, access.SessionBytes(session))
	return session
}

// replaceOwnKey has the administrator add key id (with an optional ceiling)
// to its own account and then turn off credential old, as two committed
// changes. f.session is the original session again afterwards.
func (f *backupCoreFixture) replaceOwnKey(old, id string, key [32]byte, operations []string) {
	f.t.Helper()
	c, _ := f.p.Catalog(f.s)
	u, _ := c.User(f.session.User)
	f.apply(id+"-add", "add-credential", u.Revision, access.CredentialAddition{User: u.ID, Credential: access.CredentialKey{ID: id, Method: access.PrivateKey, PublicKey: key}, Operations: operations}, state.Applied)
	original := f.session
	f.session = reissued(f.p, f.s, f.node, f.session)
	c, _ = f.p.Catalog(f.s)
	u, _ = c.User(f.session.User)
	f.apply(id+"-disable-"+old, "disable-credential", u.Revision, access.CredentialDisable{User: u.ID, Credential: old}, state.Applied)
	f.session = original
}

// changeAccount commits a put-user that changes only the account's fields.
func (f *backupCoreFixture) changeAccount(id, user string, edit func(*access.User)) {
	f.t.Helper()
	c, _ := f.p.Catalog(f.s)
	u, _ := c.User(user)
	next := accountFields(u)
	edit(&next)
	f.apply(id, "put-user", u.Revision, next, state.Applied)
}

// changeAccount commits, as the administrator, a put-user that changes only
// the account's fields.
func (f *nodeStorageFixture) changeAccount(user string, edit func(*access.User)) {
	f.t.Helper()
	c, _ := f.p.Catalog(f.s)
	u, _ := c.User(user)
	next := accountFields(u)
	edit(&next)
	f.apply("admin", "put-user", u.Revision, next, state.Applied)
}

// limitAccount gives a non-administrator account an action ceiling, which
// every one of its credentials then shares.
func (f *nodeStorageFixture) limitAccount(user string, operations ...string) {
	f.t.Helper()
	c, _ := f.p.Catalog(f.s)
	u, _ := c.User(user)
	f.apply("admin", "set-account-scope", u.Revision, access.AccountScope{User: user, Add: operations}, state.Applied)
}

// addKey has the administrator add key id, with an optional ceiling, to user.
func (f *nodeStorageFixture) addKey(user, id string, key [32]byte, operations []string) {
	f.t.Helper()
	c, _ := f.p.Catalog(f.s)
	u, _ := c.User(user)
	f.apply("admin", "add-credential", u.Revision, access.CredentialAddition{User: user, Credential: access.CredentialKey{ID: id, Method: access.PrivateKey, PublicKey: key}, Operations: operations}, state.Applied)
}
