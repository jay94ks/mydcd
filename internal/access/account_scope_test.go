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
	if _, err := c.SetAccountScope("bot", u.Revision, AccountScope{User: "bot", Operations: []string{"restart-task"}}); !errors.Is(err, ErrDenied) {
		t.Fatal("scope by a non-admin", err)
	}
	if _, err := c.SetAccountScope("admin", u.Revision+1, AccountScope{User: "bot"}); !errors.Is(err, ErrConflict) {
		t.Fatal("stale revision", err)
	}
	n, err := c.SetAccountScope("admin", u.Revision, AccountScope{User: "bot", Operations: []string{"restart-task", "pause-app-cd"}, KeyOnly: true})
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
	if _, err := c.PutUser("admin", u.Revision, withPassword); err == nil {
		t.Fatal("password on a key-only account")
	}
	a, _ := c.User("admin")
	if _, err := c.SetAccountScope("admin", a.Revision, AccountScope{User: "admin", Operations: []string{"put-user"}}); err == nil {
		t.Fatal("ceiling on a system administrator")
	}
	// Empty clears it.
	n, err = c.SetAccountScope("admin", u.Revision, AccountScope{User: "bot"})
	c = must(t, n, err)
	u, _ = c.User("bot")
	if u.Operations != nil || u.AutomationOnly {
		t.Fatalf("cleared %+v", u)
	}
}
