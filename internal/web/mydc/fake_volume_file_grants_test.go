// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
)

// the grant list follows grant/revoke, a turned-off user and a
// deleted volume.
func TestVolumeFileGrants(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	alice := passwordLogin(t, f, "alice", "alice")
	admin := passwordLogin(t, f, "admin", "admin")
	bob, _ := keyLogin(t, f, "bob", FixtureKey("bob"))
	grant := access.VolumeFileFolderGrant{Tenant: "shop", Volume: "uploads", Prefix: "mydc-web-backups/", User: "u-bob"}

	cat := func() uint64 {
		t.Helper()
		p, err := alice.TenantMembers(ctx, "shop", "")
		if err != nil {
			t.Fatal(err)
		}
		return p.Collection
	}
	if rows, err := fc(alice).volumeFileGrants(ctx, "shop", ""); err != nil || len(rows) != 0 {
		t.Fatalf("empty %+v %v", rows, err)
	}
	_, err := fc(bob).volumeFileGrants(ctx, "shop", "")
	wantCode(t, err, CodeDenied)
	if _, res := submit(t, alice, ActionGrantVolumeFiles, cat(), grant, rootFor(t, alice, ActionGrantVolumeFiles)); res.Code != ResultApplied {
		t.Fatalf("grant %+v", res)
	}
	rows, err := fc(alice).volumeFileGrants(ctx, "shop", "uploads")
	if err != nil || len(rows) != 1 || rows[0].Username != "bob" || rows[0].GrantedBy != "alice" || !rows[0].Active || rows[0].Revision == 0 || rows[0].Prefix != grant.Prefix {
		t.Fatalf("rows %+v %v", rows, err)
	}
	if mine, err := fc(bob).volumeFileGrants(ctx, "shop", ""); err != nil || len(mine) != 1 {
		t.Fatalf("own rows %+v %v", mine, err)
	}
	if other, _ := fc(alice).volumeFileGrants(ctx, "shop", "mysql-data"); len(other) != 0 {
		t.Fatalf("other volume %+v", other)
	}

	// A turned-off user keeps the row, inactive.
	off, _ := admin.UserCredentials(ctx, "bob")
	off.Enabled = false
	if _, res := submit(t, admin, ActionPutUser, off.Revision, off, rootFor(t, admin, ActionPutUser)); res.Code != ResultApplied {
		t.Fatalf("disable %+v", res)
	}
	if rows, _ := fc(alice).volumeFileGrants(ctx, "shop", ""); len(rows) != 1 || rows[0].Active {
		t.Fatalf("inactive %+v", rows)
	}

	// Revoke removes it.
	if _, res := submit(t, alice, ActionRevokeVolumeFileGrant, cat(), grant, rootFor(t, alice, ActionRevokeVolumeFileGrant)); res.Code != ResultApplied {
		t.Fatalf("revoke %+v", res)
	}
	if rows, _ := fc(alice).volumeFileGrants(ctx, "shop", ""); len(rows) != 0 {
		t.Fatalf("after revoke %+v", rows)
	}
}
