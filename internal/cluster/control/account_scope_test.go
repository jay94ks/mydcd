// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"slices"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
)

func TestSetAccountScopeIsASignedCatalogChange(t *testing.T) {
	f := newBackupCore(t)
	key := [32]byte(f.admin.Public().(ed25519.PublicKey))
	f.apply("scope-user", "put-user", 0, access.User{ID: "bot", Username: "bot", Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: key, Enabled: true}}}, state.Applied)
	catalog, _ := f.p.Catalog(f.s)
	bot, _ := catalog.User("bot")
	keyOnly := true
	f.apply("scope-stale", "set-account-scope", bot.Revision+5, access.AccountScope{User: "bot", Add: []string{"restart-task"}}, state.ConditionFailed)
	f.apply("scope-empty", "set-account-scope", bot.Revision, access.AccountScope{User: "bot"}, state.Invalid)
	f.apply("scope-remove-missing", "set-account-scope", bot.Revision, access.AccountScope{User: "bot", Remove: []string{"restart-task"}}, state.ConditionFailed)
	f.apply("scope-set", "set-account-scope", bot.Revision, access.AccountScope{User: "bot", Add: []string{"restart-task"}, KeyOnly: &keyOnly}, state.Applied)
	catalog, _ = f.p.Catalog(f.s)
	bot, _ = catalog.User("bot")
	if !bot.AutomationOnly || !slices.Equal(bot.Operations, []string{"restart-task"}) {
		t.Fatalf("scope %+v", bot)
	}
	f.apply("scope-add-twice", "set-account-scope", bot.Revision, access.AccountScope{User: "bot", Add: []string{"restart-task"}}, state.ConditionFailed)
	f.apply("scope-lift", "set-account-scope", bot.Revision, access.AccountScope{User: "bot", Unlimited: true}, state.Applied)
	catalog, _ = f.p.Catalog(f.s)
	if bot, _ = catalog.User("bot"); bot.Operations != nil || !bot.AutomationOnly {
		t.Fatalf("lifted %+v", bot)
	}
	// put-user changes account fields only; an administrator adds and turns
	// off another account's keys with add/disable-credential.
	other := [32]byte{9}
	f.apply("put-user-with-keys", "put-user", bot.Revision, access.User{ID: "bot", Username: "bot", Enabled: false, Credentials: bot.Credentials}, state.Invalid)
	f.apply("admin-add-key", "add-credential", bot.Revision, access.CredentialAddition{User: "bot", Credential: access.CredentialKey{ID: "ci", Method: access.PrivateKey, PublicKey: other}, Operations: []string{"restart-task"}}, state.Applied)
	catalog, _ = f.p.Catalog(f.s)
	bot, _ = catalog.User("bot")
	f.apply("admin-disable-key", "disable-credential", bot.Revision, access.CredentialDisable{User: "bot", Credential: "key"}, state.Applied)
	catalog, _ = f.p.Catalog(f.s)
	bot, _ = catalog.User("bot")
	f.apply("put-user-disable", "put-user", bot.Revision, access.User{ID: "bot", Username: "bot"}, state.Applied)
	catalog, _ = f.p.Catalog(f.s)
	if bot, _ = catalog.User("bot"); bot.Enabled || len(bot.Credentials) != 2 || bot.Credentials[0].ID != "ci" || !bot.Credentials[0].Enabled || !slices.Equal(bot.Credentials[0].Operations, []string{"restart-task"}) || bot.Credentials[1].Enabled {
		t.Fatalf("account after changes %+v", bot)
	}
	if CommandKey("set-account-scope") != CatalogKey {
		t.Fatal("command key")
	}
}
