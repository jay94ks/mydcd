// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"fmt"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
)

// RQ10 reads through mydcd's common PublicRead envelope.
func TestPublicRead(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	admin := passwordLogin(t, f, "admin", "admin")
	alice := passwordLogin(t, f, "alice", "alice")
	bob, _ := keyLogin(t, f, "bob", FixtureKey("bob"))

	read := func(c Conn, method, tenant string, q control.PublicReadQuery, after string) (control.PublicReadPage, error) {
		t.Helper()
		return c.PublicRead(ctx, method, tenant, q, after)
	}
	// Selector rules of control.PublicReadQuery.Valid.
	_, err := read(alice, "network-users", "shop", control.PublicReadQuery{}, "")
	wantCode(t, err, CodeInvalid)
	_, err = read(alice, "image-trust", "shop", control.PublicReadQuery{Name: "x"}, "")
	wantCode(t, err, CodeInvalid)
	_, err = read(alice, "no-such-read", "shop", control.PublicReadQuery{}, "")
	wantCode(t, err, CodeInvalid)

	p, err := read(bob, "network-users", "shop", control.PublicReadQuery{Name: "shop-net"}, "")
	if err != nil || p.Schema != 1 || p.Method != "network-users" || p.Tenant != "shop" || p.Index == 0 || p.RootRevision == 0 || p.CatalogRevision == 0 || p.TenantRevision == 0 || p.Total == 0 || len(p.Rows) == 0 {
		t.Fatalf("network-users %+v %v", p, err)
	}
	for _, r := range p.Rows {
		if r.Key == "" || r.User == nil || r.User.Tenant != "shop" || r.User.Kind != "app-service" && r.User.Kind != "standalone" {
			t.Fatalf("row %+v", r)
		}
	}
	p, err = read(bob, "volume-users", "shop", control.PublicReadQuery{Name: "mysql-data"}, "")
	if err != nil || len(p.Rows) == 0 || p.Rows[0].User == nil || p.Rows[0].User.Writable == nil {
		t.Fatalf("volume-users %+v %v", p, err)
	}
	_, err = read(bob, "volume-users", "payments", control.PublicReadQuery{Name: "ledger-data"}, "")
	wantCode(t, err, CodeDenied)

	// network-closure needs ManageNetwork; a reader is refused.
	_, err = read(bob, "network-closure", "shop", control.PublicReadQuery{Name: "shop-net"}, "")
	wantCode(t, err, CodeDenied)
	if p, err := read(alice, "network-closure", "shop", control.PublicReadQuery{Name: "shop-net-node-a"}, ""); err != nil || len(p.Rows) != 1 || p.Rows[0].Closure == nil || p.Rows[0].Closure.State == "" {
		t.Fatalf("network-closure %+v %v", p, err)
	}
	_, err = read(alice, "network-closure", "shop", control.PublicReadQuery{Name: "shop-net"}, "x")
	wantCode(t, err, CodeInvalid)

	// lifecycle-uses: ManageServices (a manager).
	if p, err := read(alice, "lifecycle-uses", "shop", control.PublicReadQuery{Name: "http-ready"}, ""); err != nil || p.Total == 0 || p.Rows[0].Lifecycle == nil || p.RootRevision == 0 {
		t.Fatalf("lifecycle-uses %+v %v", p, err)
	}
	_, err = read(bob, "lifecycle-uses", "shop", control.PublicReadQuery{Name: "http-ready"}, "")
	wantCode(t, err, CodeDenied)

	// image-trust carries the page Rules.
	if p, err := read(alice, "image-trust", "shop", control.PublicReadQuery{}, ""); err != nil || p.Rows == nil {
		t.Fatalf("image-trust %+v %v", p, err)
	}
	// route-endpoints: any tenant manager; rows have only the four names.
	if p, err := read(alice, "route-endpoints", "payments", control.PublicReadQuery{}, ""); err != nil || p.TenantRevision != 0 || len(p.Rows) == 0 || p.Rows[0].RouteEndpoint == nil || p.Rows[0].Key != p.Rows[0].RouteEndpoint.Network+"/"+p.Rows[0].RouteEndpoint.Node+"/"+p.Rows[0].RouteEndpoint.Pool {
		t.Fatalf("route-endpoints %+v %v", p, err)
	}
	// volume-backup-limits: Tenant "" is the system admin's.
	_, err = read(alice, "volume-backup-limits", "", control.PublicReadQuery{}, "")
	wantCode(t, err, CodeDenied)
	if _, err := read(admin, "volume-backup-limits", "", control.PublicReadQuery{}, ""); err != nil {
		t.Fatalf("system backup limits %v", err)
	}
	if p, err := read(alice, "volume-backup-limits", "shop", control.PublicReadQuery{}, ""); err != nil {
		t.Fatalf("backup limits %+v %v", p, err)
	} else {
		for _, r := range p.Rows {
			if r.BackupLimit == nil || r.BackupLimit.Tenant != "shop" {
				t.Fatalf("backup limit row %+v", r)
			}
		}
	}
	// Vault reads: realm ManageSecrets; retained sources: tenant Read.
	if _, err := read(alice, "vault-approvals", "shop", control.PublicReadQuery{}, ""); err != nil {
		t.Fatalf("vault-approvals %v", err)
	}
	_, err = read(bob, "vault-approvals", "shop", control.PublicReadQuery{}, "")
	wantCode(t, err, CodeDenied)
	if p, err := read(bob, "volume-retained-sources", "shop", control.PublicReadQuery{Name: "mysql-data"}, ""); err != nil || p.RootRevision == 0 {
		t.Fatalf("volume-retained-sources %+v %v", p, err)
	}
	// Only the methods with a tenant-less form take Tenant "".
	_, err = read(admin, "network-users", "", control.PublicReadQuery{Name: "shop-net"}, "")
	wantCode(t, err, CodeDenied)
}

// Pages of at most 8 rows; Next is the After of the next page, Total is all.
func TestPublicReadPages(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	alice := passwordLogin(t, f, "alice", "alice")
	for i := range 10 {
		grant(t, alice, "shop", "uploads", fmt.Sprintf("p%02d/", i), "u-bob")
	}
	q := control.PublicReadQuery{Name: "uploads"}
	p, err := alice.PublicRead(ctx, "volume-file-grants", "shop", q, "")
	if err != nil || len(p.Rows) != PublicReadPageRows || p.Next == "" || p.Total < 10 {
		t.Fatalf("page 1 %d %q %d %v", len(p.Rows), p.Next, p.Total, err)
	}
	if g := p.Rows[0].FileGrant; g == nil || g.Volume != "uploads" || len(g.Operations) != 4 || !g.VolumePresent {
		t.Fatalf("grant row %+v", p.Rows[0])
	}
	n, err := alice.PublicRead(ctx, "volume-file-grants", "shop", q, p.Next)
	if err != nil || len(n.Rows) != p.Total-PublicReadPageRows || n.Next != "" || n.Rows[0].Key == p.Rows[7].Key {
		t.Fatalf("page 2 %+v %v", n, err)
	}
	_, err = alice.PublicRead(ctx, "volume-file-grants", "shop", q, "nope")
	wantCode(t, err, CodeCursorExpired)
}

func grant(t *testing.T, c Conn, tenant, volume, prefix, user string) {
	t.Helper()
	p, err := c.TenantMembers(ctx, tenant, "")
	if err != nil {
		t.Fatal(err)
	}
	g := access.VolumeFileFolderGrant{Tenant: tenant, Volume: volume, Prefix: prefix, User: user}
	if _, res := submit(t, c, ActionGrantVolumeFiles, p.Collection, g, rootFor(t, c, ActionGrantVolumeFiles)); res.Code != ResultApplied {
		t.Fatalf("grant %s %+v", prefix, res)
	}
}
