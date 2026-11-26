// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"slices"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
)

func TestSetAccountScopeIsASignedCatalogChange(t *testing.T) {
	f := newBackupCore(t)
	key := [32]byte(f.admin.Public().(ed25519.PublicKey))
	f.apply("scope-user", "put-user", 0, access.User{ID: "bot", Username: "bot", Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: key, Enabled: true}}}, state.Applied)
	catalog, _ := f.p.Catalog(f.s)
	bot, _ := catalog.User("bot")
	f.apply("scope-stale", "set-account-scope", bot.Revision+5, access.AccountScope{User: "bot", Operations: []string{"restart-task"}}, state.ConditionFailed)
	f.apply("scope-set", "set-account-scope", bot.Revision, access.AccountScope{User: "bot", Operations: []string{"restart-task"}, KeyOnly: true}, state.Applied)
	catalog, _ = f.p.Catalog(f.s)
	bot, _ = catalog.User("bot")
	if !bot.AutomationOnly || !slices.Equal(bot.Operations, []string{"restart-task"}) {
		t.Fatalf("scope %+v", bot)
	}
	if CommandKey("set-account-scope") != CatalogKey {
		t.Fatal("command key")
	}
}
