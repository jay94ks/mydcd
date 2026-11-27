// SPDX-License-Identifier: Apache-2.0

package access

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestCredentialOperationsIntersectSourceAndApprovalWithoutGrantingRoles(t *testing.T) {
	c := enrolled(t)
	bot := user("bot", true)
	bot.AutomationOnly = true
	bot.Credentials[0].Operations = []string{"restart-task", "pause-app-cd"}
	c = put(t, c, "admin", bot)
	u, _ := c.User("bot")
	session := Session{User: "bot", Credential: "key", AccountRevision: u.Revision}
	if c.OperationAllowed(session, "restart-task") != nil || !errors.Is(c.OperationAllowed(session, "down-app"), ErrDenied) {
		t.Fatal("credential action ceiling")
	}
	// Metadata is owned at every boundary, including public lists and edits.
	u.Credentials[0].Operations[0] = "put-user"
	owned, _ := c.User("bot")
	if owned.Credentials[0].Operations[0] == "put-user" {
		t.Fatal("credential list aliases catalog")
	}
	public := PublicUserOf(owned)
	public.Credentials[0].Operations[0] = "put-user"
	if c.OperationAllowed(session, "put-user") == nil {
		t.Fatal("public projection widened catalog")
	}
	// A restricted approval key cannot approve a forged broader grant of this
	// same account. Session signature verification remains the caller's duty.
	owned.AutomationOnly = false
	owned.Credentials = append(owned.Credentials, Credential{ID: "password", Method: Password, VerifierRef: "protected", Enabled: true})
	c = put(t, c, "admin", owned)
	owned, _ = c.User("bot")
	session.Credential = "password"
	session.AccountRevision = owned.Revision
	session.Approval = &SessionApproval{PublicKey: owned.Credentials[0].PublicKey}
	if c.OperationAllowed(session, "restart-task") != nil || c.OperationAllowed(session, "put-user") == nil {
		t.Fatal("approval credential ceiling ignored")
	}
	// No role is introduced: ordinary tenant/user checks still follow this guard.
	owned.SystemAdmin = false
	c = put(t, c, "admin", owned)
	if c.Authorize("bot", "foreign", Deploy, "") == nil {
		t.Fatal("operation name granted a tenant role")
	}
	owned, _ = c.User("bot")
	session.AccountRevision = owned.Revision
	owned.Credentials[0].Enabled = false
	c = put(t, c, "admin", owned)
	if c.OperationAllowed(session, "restart-task") == nil {
		t.Fatal("account revision/key revocation ignored")
	}
}

func TestAutomationOnlyAndPublicCredentialBudgetRejectInvalidPolicy(t *testing.T) {
	c := enrolled(t)
	for _, operations := range [][]string{{}, {"*"}, {"restart-task", "restart-task"}, {"Restart-Task"}} {
		candidate := user("bot", false)
		candidate.Credentials[0].Operations = operations
		if _, err := c.PutUser("admin", 0, candidate); !errors.Is(err, ErrInvalid) {
			t.Fatal("bad operation policy accepted", operations, err)
		}
	}
	candidate := user("bot", false)
	candidate.AutomationOnly = true
	candidate.Credentials = append(candidate.Credentials, Credential{ID: "password", Method: Password, VerifierRef: "protected", Enabled: true})
	if _, err := c.PutUser("admin", 0, candidate); !errors.Is(err, ErrInvalid) {
		t.Fatal("automation password login allowed", err)
	}
	candidate.Credentials[1].Enabled = false
	if _, err := c.PutUser("admin", 0, candidate); err != nil {
		t.Fatal("disabled historical credential need not be erased", err)
	}
	candidate = user("large", false)
	candidate.Credentials = nil
	for i := range 64 {
		credential := Credential{ID: fmt.Sprintf("key-%d", i), Method: PrivateKey, PublicKey: key(byte(i + 1)), Enabled: true, Label: strings.Repeat("<", 128)}
		for j := range 64 {
			credential.Operations = append(credential.Operations, "operation-"+strings.Repeat("a", 50)+fmt.Sprintf("%02d", j))
		}
		candidate.Credentials = append(candidate.Credentials, credential)
	}
	if _, err := c.PutUser("admin", 0, candidate); !errors.Is(err, ErrInvalid) {
		t.Fatal("unqueryable oversized public user accepted", err)
	}
}

func TestRestrictedLastIndependentAdminCannotLockNodeCLIPolicy(t *testing.T) {
	c := enrolled(t)
	c, err := c.SetNodeCLI("admin", 0, true)
	if err != nil {
		t.Fatal(err)
	}
	admin, _ := c.User("admin")
	admin.Credentials[0].Operations = []string{"restart-task"}
	admin.Revision = 0
	if _, err = c.replaceUser(c.users["admin"].Revision, admin); !errors.Is(err, ErrDenied) {
		t.Fatal("last recovery administrator was removed by operation ceiling", err)
	}
	admin.Credentials[0].Operations = []string{"put-user"}
	if _, err = c.replaceUser(c.users["admin"].Revision, admin); err != nil {
		t.Fatal("an independent key able to restore account policy remains recoverable", err)
	}
}
