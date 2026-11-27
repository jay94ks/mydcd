// SPDX-License-Identifier: Apache-2.0

package access

import (
	"errors"
	"slices"
	"testing"
)

func TestAccountScopeCeilingAndKeyOnly(t *testing.T) {
	c := enrolled(t)
	c = put(t, c, "admin", user("bot", false))
	u, _ := c.User("bot")
	if _, err := c.SetAccountScope("bot", u.Revision, AccountScope{User: "bot", Add: []string{"restart-task"}}); !errors.Is(err, ErrDenied) {
		t.Fatal("scope by a non-admin", err)
	}
	if _, err := c.SetAccountScope("admin", u.Revision+1, AccountScope{User: "bot", Add: []string{"restart-task"}}); !errors.Is(err, ErrConflict) {
		t.Fatal("stale revision", err)
	}
	yes, no := true, false
	for _, bad := range []AccountScope{
		{User: "bot"}, // no change
		{User: "bot", Unlimited: true, Add: []string{"restart-task"}},
		{User: "bot", Add: []string{"restart-task"}, Remove: []string{"restart-task"}},
	} {
		if _, err := c.SetAccountScope("admin", u.Revision, bad); !errors.Is(err, ErrInvalid) {
			t.Fatal("bad change", bad, err)
		}
	}
	for _, stale := range []AccountScope{
		{User: "bot", Remove: []string{"restart-task"}}, // not in the ceiling
		{User: "bot", Unlimited: true},                  // already unlimited
		{User: "bot", KeyOnly: &no},                     // already off
	} {
		if _, err := c.SetAccountScope("admin", u.Revision, stale); !errors.Is(err, ErrConflict) {
			t.Fatal("stale change", stale, err)
		}
	}
	n, err := c.SetAccountScope("admin", u.Revision, AccountScope{User: "bot", Add: []string{"restart-task", "pause-app-cd"}, KeyOnly: &yes})
	c = must(t, n, err)
	u, _ = c.User("bot")
	if !u.AutomationOnly || !slices.Equal(u.Operations, []string{"pause-app-cd", "restart-task"}) || !slices.Equal(PublicUserOf(u).Operations, u.Operations) {
		t.Fatalf("scope %+v", u)
	}
	s := Session{User: "bot", Credential: "key", AccountRevision: u.Revision}
	if c.OperationAllowed(s, "restart-task") != nil || !errors.Is(c.OperationAllowed(s, "down-app"), ErrDenied) {
		t.Fatal("account ceiling")
	}
	// The account and credential ceilings intersect.
	u.Credentials[0].Operations = []string{"down-app", "restart-task"}
	c = put(t, c, "admin", u)
	u, _ = c.User("bot")
	s.AccountRevision = u.Revision
	if c.OperationAllowed(s, "restart-task") != nil || c.OperationAllowed(s, "down-app") == nil || c.OperationAllowed(s, "pause-app-cd") == nil {
		t.Fatal("intersection")
	}
	// Key-only refuses a password login; an admin takes no ceiling.
	withPassword := u
	withPassword.Credentials = append(slices.Clone(u.Credentials), Credential{ID: "password", Method: Password, VerifierRef: "v", Enabled: true})
	if _, err := c.replaceUser(u.Revision, withPassword); err == nil {
		t.Fatal("password on a key-only account")
	}
	a, _ := c.User("admin")
	if _, err := c.SetAccountScope("admin", a.Revision, AccountScope{User: "admin", Add: []string{"put-user"}}); err == nil {
		t.Fatal("ceiling on a system administrator")
	}
	// One action at a time; the last one goes only with Unlimited.
	n, err = c.SetAccountScope("admin", u.Revision, AccountScope{User: "bot", Remove: []string{"pause-app-cd"}, Add: []string{"down-app"}})
	c = must(t, n, err)
	u, _ = c.User("bot")
	if !slices.Equal(u.Operations, []string{"down-app", "restart-task"}) {
		t.Fatalf("swapped %+v", u.Operations)
	}
	if _, err := c.SetAccountScope("admin", u.Revision, AccountScope{User: "bot", Remove: []string{"down-app", "restart-task"}}); !errors.Is(err, ErrInvalid) {
		t.Fatal("removed the last action", err)
	}
	n, err = c.SetAccountScope("admin", u.Revision, AccountScope{User: "bot", Unlimited: true, KeyOnly: &no})
	c = must(t, n, err)
	u, _ = c.User("bot")
	if u.Operations != nil || u.AutomationOnly {
		t.Fatalf("cleared %+v", u)
	}
}

// put-user changes only the account's own fields; administrators add and
// turn off another account's login methods with add/disable-credential.
func TestPutUserAndAdministratorCredentials(t *testing.T) {
	c := enrolled(t)
	c = put(t, c, "admin", user("bob", false))
	u, _ := c.User("bob")
	for _, bad := range []User{
		{ID: "bob", Username: "bob", Enabled: true},                                        // nothing changes
		{ID: "bob", Username: "bob", Enabled: false, Credentials: u.Credentials},           // carries login methods
		{ID: "bob", Username: "bob", Enabled: false, Operations: []string{"restart-task"}}, // carries a ceiling
	} {
		if _, err := c.PutUser("admin", u.Revision, bad); !errors.Is(err, ErrInvalid) {
			t.Fatal("put-user", bad, err)
		}
	}
	if _, err := c.PutUser("admin", u.Revision+1, User{ID: "bob", Username: "bob"}); !errors.Is(err, ErrConflict) {
		t.Fatal("stale put-user", err)
	}
	n, err := c.PutUser("admin", u.Revision, User{ID: "bob", Username: "bobby", Enabled: false})
	c = must(t, n, err)
	if v, _ := c.User("bob"); v.Username != "bobby" || v.Enabled || len(v.Credentials) != 1 || v.Revision == u.Revision {
		t.Fatalf("account change %+v", v)
	}
	u, _ = c.User("bob")
	add := CredentialAddition{User: "bob", Credential: CredentialKey{ID: "ci", Method: PrivateKey, PublicKey: key(77)}, Operations: []string{"restart-task"}}
	if _, err := c.AddCredential("carol", [32]byte{1}, u.Revision, add); !errors.Is(err, ErrDenied) {
		t.Fatal("a non-admin added a key to another account", err)
	}
	withProof := add
	withProof.Challenge = [32]byte{1}
	if _, err := c.AddCredential("admin", [32]byte{1}, u.Revision, withProof); !errors.Is(err, ErrInvalid) {
		t.Fatal("admin addition with a self proof", err)
	}
	n, err = c.AddCredential("admin", [32]byte{1}, u.Revision, add)
	c = must(t, n, err)
	u, _ = c.User("bob")
	if len(u.Credentials) != 2 || !slices.Equal(u.Credentials[1].Operations, []string{"restart-task"}) {
		t.Fatalf("admin key %+v", u.Credentials)
	}
	if _, err := c.AddCredential("admin", [32]byte{1}, u.Revision, add); !errors.Is(err, ErrConflict) {
		t.Fatal("added the same key twice", err)
	}
	n, err = c.DisableCredential("admin", u.Revision, CredentialDisable{User: "bob", Credential: "key"})
	c = must(t, n, err)
	u, _ = c.User("bob")
	if u.Credentials[0].Enabled {
		t.Fatal("admin disable", u.Credentials)
	}
	if _, err := c.DisableCredential("admin", u.Revision, CredentialDisable{User: "bob", Credential: "key"}); !errors.Is(err, ErrConflict) {
		t.Fatal("disabled twice", err)
	}
	// An ordinary account may end with no method on (a revoked invitation).
	if _, err := c.DisableCredential("admin", u.Revision, CredentialDisable{User: "bob", Credential: "ci"}); err != nil {
		t.Fatal("disabled the last login method of an ordinary account", err)
	}
}
