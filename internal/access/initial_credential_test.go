// SPDX-License-Identifier: Apache-2.0

package access

import "testing"

func TestInitialCredentialPublishesOnlyOnceAtExactUserCAS(t *testing.T) {
	c := enrolled(t)
	var err error
	c, err = c.PutUser("admin", 0, User{ID: "new-user", Username: "new.user", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := c.User("new-user")
	if c.SystemAllowed(u.ID) {
		t.Fatal("empty account became administrator")
	}
	password := Credential{ID: "password", Method: Password, VerifierRef: "vault/system/system/credentials/initial/public-intent@1", Enabled: true}
	next, err := c.InstallInitialCredential("admin", u.ID, u.Revision, password)
	if err != nil {
		t.Fatal(err)
	}
	current, _ := next.User(u.ID)
	if len(current.Credentials) != 1 || !current.Credentials[0].Equal(password) || len(u.Credentials) != 0 {
		t.Fatal("publication/ownership")
	}
	if _, err := next.InstallInitialCredential("admin", u.ID, current.Revision, password); err != ErrConflict {
		t.Fatal("duplicate method", err)
	}
	if _, err := c.InstallInitialCredential("admin", u.ID, u.Revision+1, password); err != ErrConflict {
		t.Fatal("stale CAS", err)
	}
	if _, err := c.InstallInitialCredential(u.ID, u.ID, u.Revision, password); err != ErrDenied {
		t.Fatal("self issue", err)
	}
	for _, bad := range []Credential{
		{ID: "key", Method: PrivateKey, PublicKey: key(9), Enabled: true},
		{ID: "token", Method: Token, VerifierRef: password.VerifierRef, Enabled: true},
		{ID: "password", Method: Password, VerifierRef: password.VerifierRef, Enabled: true, OneTime: true},
		{ID: "password", Method: Password, VerifierRef: password.VerifierRef, Enabled: true, Operations: []string{"put-user"}},
	} {
		if _, err := c.InstallInitialCredential("admin", u.ID, u.Revision, bad); err == nil {
			t.Fatal("invalid initial credential")
		}
	}
	raw, err := next.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Decode(raw); err != nil {
		t.Fatal("snapshot", err)
	}
	// The initial user snapshot also remains canonical and has a usable admin.
	raw, _ = c.Encode()
	if _, err = Decode(raw); err != nil {
		t.Fatal(err)
	}
	if _, err := c.PutUser("admin", 0, User{ID: "empty-admin", Username: "empty-admin", Enabled: true, SystemAdmin: true}); err == nil {
		t.Fatal("unusable admin counted")
	}
}

func TestCredentialEqualIncludesOptionalActionCeilingAndOneTime(t *testing.T) {
	a := Credential{ID: "key", Method: PrivateKey, PublicKey: key(1), Enabled: true}
	b := a
	if !a.Equal(b) {
		t.Fatal("same credential")
	}
	b.Operations = []string{}
	if a.Equal(b) {
		t.Fatal("nil ceiling changed")
	}
	b = a
	b.OneTime = true
	if a.Equal(b) {
		t.Fatal("one-time downgrade")
	}
	b = a
	b.Operations = []string{"restart-task"}
	a.Operations = []string{"restart-task"}
	if !a.Equal(b) {
		t.Fatal("equal non-comparable credential")
	}
}
