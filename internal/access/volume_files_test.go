// SPDX-License-Identifier: Apache-2.0

package access

import (
	"testing"
)

func TestVolumeFileCredentialDelegationIsOwnedAndCannotEscapePrefixOrVolume(t *testing.T) {
	c := tenant(t, enrolled(t), "tenant")
	bot := user("backup-bot", false)
	bot.AutomationOnly = true
	bot.Credentials[0].Operations = []string{"volume-file-put", "volume-file-get", "volume-file-list", "volume-file-delete"}
	bot.Credentials[0].VolumeFiles = []VolumeFileGrant{{Tenant: "tenant", Volume: "backups", Prefix: "mydc-web-backups/", Operations: []string{"volume-file-put", "volume-file-get", "volume-file-list", "volume-file-delete"}}}
	c = put(t, c, "admin", bot)
	c = member(t, c, "tenant", "backup-bot", Viewer, true)
	c = put(t, c, "admin", user("manager", false))
	c = member(t, c, "tenant", "manager", Manager, true)
	session, issuer, _ := signedSession(c, "backup-bot", "key", []Scope{{Tenant: "tenant", Actions: []Action{Read}}})
	for _, operation := range bot.Credentials[0].Operations {
		name := "mydc-web-backups/today.bin"
		if operation == "volume-file-list" {
			name = "mydc-web-backups/"
		}
		if c.AuthorizeVolumeFile(session, key(1), issuer, 100, "tenant", "", "backups", name, operation, "") == nil {
			t.Fatal("credential ceiling created folder authority", operation)
		}
	}
	grant := VolumeFileFolderGrant{Tenant: "tenant", Volume: "backups", Prefix: "mydc-web-backups/", User: "backup-bot"}
	var err error
	c, err = c.SetVolumeFileGrant("manager", c.Revision(), grant, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range bot.Credentials[0].Operations {
		name := "mydc-web-backups/today.bin"
		if operation == "volume-file-list" {
			name = "mydc-web-backups/"
		}
		if c.AuthorizeVolumeFile(session, key(1), issuer, 100, "tenant", "", "backups", name, operation, "") != nil {
			t.Fatal("delegated operation refused", operation)
		}
	}
	for _, q := range []struct{ tenant, app, volume, path, op string }{{"tenant", "", "other", "mydc-web-backups/a", "volume-file-put"}, {"tenant", "app", "backups", "mydc-web-backups/a", "volume-file-put"}, {"tenant", "", "backups", "mydc-web-backups-other/a", "volume-file-put"}, {"tenant", "", "backups", "mydc-web-backups/../other", "volume-file-delete"}, {"tenant", "", "backups", "mydc-web-backups", "volume-file-list"}, {"other", "", "backups", "mydc-web-backups/a", "volume-file-get"}} {
		if c.AuthorizeVolumeFile(session, key(1), issuer, 100, q.tenant, q.app, q.volume, q.path, q.op, "") == nil {
			t.Fatal("delegation escaped", q)
		}
	}
	if c.AuthorizeSession(session, key(1), issuer, 100, "tenant", ManageVolumes, "") == nil || c.OperationAllowed(session, "delete-volume") == nil {
		t.Fatal("file delegation became Volume manager")
	}
	owned, _ := c.User("backup-bot")
	owned.Credentials[0].VolumeFiles[0].Prefix = "other/"
	public := PublicUserOf(bot)
	public.Credentials[0].VolumeFiles[0].Operations[0] = "delete-volume"
	if c.AuthorizeVolumeFile(session, key(1), issuer, 100, "tenant", "", "backups", "mydc-web-backups/a", "volume-file-put", "") != nil {
		t.Fatal("public grant alias changed catalog")
	}
	c, err = c.SetVolumeFileGrant("manager", c.Revision(), grant, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range bot.Credentials[0].Operations {
		name := "mydc-web-backups/today.bin"
		if operation == "volume-file-list" {
			name = "mydc-web-backups/"
		}
		if c.AuthorizeVolumeFile(session, key(1), issuer, 100, "tenant", "", "backups", name, operation, "") == nil {
			t.Fatal("credential ceiling bypassed current folder revocation", operation)
		}
	}
	c, err = c.SetVolumeFileGrant("manager", c.Revision(), grant, false)
	if err != nil {
		t.Fatal(err)
	}
	c = member(t, c, "tenant", "backup-bot", Viewer, false)
	if c.AuthorizeVolumeFile(session, key(1), issuer, 100, "tenant", "", "backups", "mydc-web-backups/a", "volume-file-put", "") == nil {
		t.Fatal("membership removal did not revoke delegation")
	}
}

func TestVolumeFileCredentialRequiresAnExplicitFileOnlyActionCeiling(t *testing.T) {
	c := enrolled(t)
	for _, operations := range [][]string{nil, {"put-user"}, {"volume-file-put", "delete-volume"}} {
		bot := user("bot", false)
		bot.Credentials[0].Operations = operations
		bot.Credentials[0].VolumeFiles = []VolumeFileGrant{{Tenant: "tenant", Volume: "backup", Prefix: "mydc-web-backups/", Operations: []string{"volume-file-put"}}}
		if _, err := c.PutUser("admin", 0, bot); err == nil {
			t.Fatal("broad unattended credential accepted", operations)
		}
	}
}

func TestVolumeFileCredentialCeilingNarrowsManagerAndFolderAuthority(t *testing.T) {
	for _, role := range []Role{Manager, Viewer} {
		t.Run(string(role), func(t *testing.T) {
			c := tenant(t, enrolled(t), "tenant")
			bot := user("bot", false)
			bot.Credentials[0].Operations = []string{"volume-file-put", "volume-file-get", "volume-file-list", "volume-file-delete"}
			bot.Credentials[0].VolumeFiles = []VolumeFileGrant{{Tenant: "tenant", Volume: "backup", Prefix: "exports/daily/", Operations: []string{"volume-file-put", "volume-file-list"}}}
			c = put(t, c, "admin", bot)
			c = member(t, c, "tenant", "bot", role, true)
			tenant, _ := c.Tenant("tenant")
			var err error
			c, err = c.SetNodes("admin", "tenant", tenant.Revision, []string{"node-a"})
			if err != nil {
				t.Fatal(err)
			}
			if role == Viewer {
				c, err = c.SetVolumeFileGrant("admin", c.Revision(), VolumeFileFolderGrant{Tenant: "tenant", Volume: "backup", Prefix: "exports/", User: "bot"}, false)
				if err != nil {
					t.Fatal(err)
				}
			}
			session, issuer, _ := signedSession(c, "bot", "key", []Scope{{Tenant: "tenant", Actions: []Action{Read, ManageVolumes}}})
			for _, q := range []struct{ name, operation string }{{"exports/daily/a", "volume-file-put"}, {"exports/daily/", "volume-file-list"}} {
				if c.AuthorizeVolumeFile(session, key(1), issuer, 100, "tenant", "", "backup", q.name, q.operation, "node-a") != nil {
					t.Fatal("intersection of actual authority and credential ceiling denied", q)
				}
			}
			for _, q := range []struct{ app, volume, name, operation string }{
				{"", "backup", "exports/weekly/a", "volume-file-put"},
				{"", "backup", "exports/daily-other/a", "volume-file-put"},
				{"", "backup", "exports/", "volume-file-list"},
				{"", "backup", "exports/daily/a", "volume-file-get"},
				{"", "backup", "exports/daily/a", "volume-file-delete"},
				{"", "other", "exports/daily/a", "volume-file-put"},
				{"app", "backup", "exports/daily/a", "volume-file-put"},
			} {
				if c.AuthorizeVolumeFile(session, key(1), issuer, 100, "tenant", q.app, q.volume, q.name, q.operation, "node-a") == nil {
					t.Fatal("ordinary authority widened credential file/path/operation ceiling", q)
				}
			}
			withoutRead, _, _ := signedSession(c, "bot", "key", []Scope{{Tenant: "tenant", Actions: []Action{ManageVolumes}}})
			if c.AuthorizeVolumeFile(withoutRead, key(1), issuer, 100, "tenant", "", "backup", "exports/daily/a", "volume-file-put", "node-a") == nil {
				t.Fatal("file ceiling bypassed current Read scope")
			}
			if c.AuthorizeVolumeFile(session, key(1), issuer, 100, "tenant", "", "backup", "exports/daily/a", "volume-file-put", "node-b") == nil {
				t.Fatal("file ceiling bypassed current node allocation")
			}
			tenant, _ = c.Tenant("tenant")
			c, err = c.SetNodes("admin", "tenant", tenant.Revision, nil)
			if err != nil {
				t.Fatal(err)
			}
			if c.AuthorizeVolumeFile(session, key(1), issuer, 100, "tenant", "", "backup", "exports/daily/a", "volume-file-put", "node-a") == nil {
				t.Fatal("node revocation left file authority")
			}
		})
	}
}

func TestVolumeFileSourceAndApprovalCeilingsIntersectCurrentAuthority(t *testing.T) {
	operations := []string{"volume-file-put", "volume-file-get", "volume-file-list", "volume-file-delete"}
	wide := []VolumeFileGrant{{Tenant: "tenant", Volume: "backup", Prefix: "exports/", Operations: operations}}
	narrow := []VolumeFileGrant{{Tenant: "tenant", Volume: "backup", Prefix: "exports/daily/", Operations: []string{"volume-file-put"}}}
	for _, role := range []Role{Manager, Viewer} {
		for _, limit := range []string{"source", "approval"} {
			t.Run(string(role)+"/"+limit, func(t *testing.T) {
				c := tenant(t, enrolled(t), "tenant")
				public, private := signingKey(7)
				u := user("operator", false)
				u.Credentials[0].PublicKey = public
				u.Credentials[0].Operations = operations
				u.Credentials[0].VolumeFiles = wide
				token := Credential{ID: "token", Method: Token, VerifierRef: "protected-token", Enabled: true, Operations: operations, VolumeFiles: wide}
				if limit == "source" {
					token.VolumeFiles = narrow
				} else {
					u.Credentials[0].VolumeFiles = narrow
				}
				u.Credentials = append(u.Credentials, token)
				c = put(t, c, "admin", u)
				c = member(t, c, "tenant", "operator", role, true)
				session, issuer, _ := signedSession(c, "operator", "token", []Scope{{Tenant: "tenant", Actions: []Action{Read, ManageVolumes}}})
				approved, err := ApproveSession(session, private)
				if err != nil || c.VerifySession(approved, key(1), issuer, 100) != nil {
					t.Fatal("actual signed source/approval fixture invalid", err)
				}
				grant := VolumeFileFolderGrant{Tenant: "tenant", Volume: "backup", Prefix: "exports/", User: "operator"}
				if role == Viewer {
					if c.AuthorizeVolumeFile(approved, key(1), issuer, 100, "tenant", "", "backup", "exports/daily/a", "volume-file-put", "") == nil {
						t.Fatal("approved ceilings created a role or folder grant")
					}
					c, err = c.SetVolumeFileGrant("admin", c.Revision(), grant, false)
					if err != nil {
						t.Fatal(err)
					}
				}
				if c.AuthorizeVolumeFile(approved, key(1), issuer, 100, "tenant", "", "backup", "exports/daily/a", "volume-file-put", "") != nil {
					t.Fatal("current authority within both credential ceilings rejected")
				}
				for _, q := range []struct{ name, operation string }{{"exports/weekly/a", "volume-file-put"}, {"exports/daily/a", "volume-file-get"}, {"exports/daily/a", "volume-file-delete"}} {
					if c.AuthorizeVolumeFile(approved, key(1), issuer, 100, "tenant", "", "backup", q.name, q.operation, "") == nil {
						t.Fatal("source or approval ceiling was expanded", q)
					}
				}
				if role == Viewer {
					c, err = c.SetVolumeFileGrant("admin", c.Revision(), grant, true)
					if err != nil {
						t.Fatal(err)
					}
				} else {
					c = member(t, c, "tenant", "operator", Viewer, true)
				}
				if c.AuthorizeVolumeFile(approved, key(1), issuer, 100, "tenant", "", "backup", "exports/daily/a", "volume-file-put", "") == nil {
					t.Fatal("current manager/folder authority revoked but approved ceiling still allowed write")
				}
			})
		}
	}
}

func TestTenantManagerFolderGrantSurvivesSnapshotAndRevocationDoesNotEditCredential(t *testing.T) {
	c := tenant(t, enrolled(t), "tenant")
	c = put(t, c, "admin", user("manager", false))
	c = member(t, c, "tenant", "manager", Manager, true)
	bot := user("bot", false)
	bot.AutomationOnly = true
	bot.Credentials[0].Operations = []string{"volume-file-put", "volume-file-get", "volume-file-list", "volume-file-delete"}
	c = put(t, c, "admin", bot)
	c = member(t, c, "tenant", "bot", Viewer, true)
	g := VolumeFileFolderGrant{Tenant: "tenant", Volume: "backup", Prefix: "mydc-web-backups/", User: "bot"}
	before, _ := c.User("bot")
	next, err := c.SetVolumeFileGrant("manager", c.Revision(), g, false)
	if err != nil {
		t.Fatal(err)
	}
	session, issuer, _ := signedSession(next, "bot", "key", []Scope{{Tenant: "tenant", Actions: []Action{Read}}})
	if next.AuthorizeVolumeFile(session, key(1), issuer, 100, "tenant", "", "backup", "mydc-web-backups/today", "volume-file-put", "") != nil {
		t.Fatal("manager delegation rejected")
	}
	if next.AuthorizeVolumeFile(session, key(1), issuer, 100, "tenant", "", "backup", "other/today", "volume-file-put", "") == nil {
		t.Fatal("folder escaped")
	}
	after, _ := next.User("bot")
	if before.Revision != after.Revision || !before.Credentials[0].Equal(after.Credentials[0]) {
		t.Fatal("folder grant altered global credential")
	}
	raw, err := next.Encode()
	if err != nil {
		t.Fatal(err)
	}
	next, err = Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	rows := next.VolumeFileGrants("tenant", "bot", "", "backup")
	if len(rows) != 1 || rows[0].Revision == 0 {
		t.Fatal("grant lost in snapshot")
	}
	rows[0].Prefix = "other/"
	if next.AuthorizeVolumeFile(session, key(1), issuer, 100, "tenant", "", "backup", "other/a", "volume-file-put", "") == nil {
		t.Fatal("query aliases catalog")
	}
	next, err = next.SetVolumeFileGrant("manager", next.Revision(), g, true)
	if err != nil {
		t.Fatal(err)
	}
	if next.AuthorizeVolumeFile(session, key(1), issuer, 100, "tenant", "", "backup", "mydc-web-backups/today", "volume-file-put", "") == nil {
		t.Fatal("revoke left folder authority")
	}
	if _, err = next.SetVolumeFileGrant("bot", next.Revision(), g, false); err == nil {
		t.Fatal("viewer granted authority")
	}
}

func TestVolumeFileGrantReadSelectorsEnumerateOnlyOneExactTenant(t *testing.T) {
	c := tenant(t, tenant(t, enrolled(t), "tenant"), "foreign")
	c = put(t, c, "admin", user("bot", false))
	c = member(t, c, "tenant", "bot", Viewer, true)
	c = member(t, c, "foreign", "bot", Viewer, true)
	for _, g := range []VolumeFileFolderGrant{{Tenant: "tenant", Volume: "backup", Prefix: "backups/", User: "bot"}, {Tenant: "tenant", App: "app", Volume: "logs", Prefix: "logs/", User: "bot"}, {Tenant: "foreign", Volume: "backup", Prefix: "private/", User: "bot"}} {
		var err error
		c, err = c.SetVolumeFileGrant("admin", c.Revision(), g, false)
		if err != nil {
			t.Fatal(err)
		}
	}
	all := c.VolumeFileGrants("tenant", "", "", "")
	if len(all) != 2 {
		t.Fatal("optional selectors lost grants", all)
	}
	for _, g := range all {
		if g.Tenant != "tenant" {
			t.Fatal("tenant selector became wildcard")
		}
	}
	if got := c.VolumeFileGrants("tenant", "bot", "app", ""); len(got) != 1 || got[0].Volume != "logs" {
		t.Fatal("app selector", got)
	}
	if got := c.VolumeFileGrants("tenant", "", "", "backup"); len(got) != 1 || got[0].Prefix != "backups/" {
		t.Fatal("volume selector", got)
	}
	if len(c.VolumeFileGrants("", "", "", "")) != 0 {
		t.Fatal("empty tenant enumerated all realms")
	}
	// A read selector wildcard is not accepted in a write delegation.
	for _, g := range []VolumeFileFolderGrant{{Tenant: "tenant", Volume: "*", Prefix: "backups/", User: "bot"}, {Tenant: "*", Volume: "backup", Prefix: "backups/", User: "bot"}} {
		if _, err := c.SetVolumeFileGrant("admin", c.Revision(), g, false); err == nil {
			t.Fatal("read wildcard became a grant scope", g)
		}
	}
}
