// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"net/netip"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/network/services"
)

func TestVolumeUsers(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	alice := passwordLogin(t, f, "alice", "alice")
	bob, _ := keyLogin(t, f, "bob", FixtureKey("bob"))

	u, err := fc(bob).volumeUsers(ctx, "shop", "mysql-data", "")
	if err != nil || len(u.Users) != 1 {
		t.Fatalf("mysql-data %+v %v", u, err)
	}
	db := u.Users[0]
	if db.Kind != NetworkUserService || db.App != "php-shop" || db.Service != "db" || db.Node != "node-b" || db.ReadOnly || !db.Attached || len(db.Selection) != 1 {
		t.Fatalf("db %+v", db)
	}
	vols, _ := bob.Volumes(ctx, "shop", "")
	for _, v := range vols.Items {
		if v.Scope.ID == "mysql-data" && (v.Kind != "node-fixed" || v.Owner.Node != "node-b" || v.Consumers != 1) {
			t.Fatalf("row %+v", v)
		}
	}
	if u, _ := fc(bob).volumeUsers(ctx, "shop", "mysql-data", "shop-worker"); len(u.Users) != 0 {
		t.Fatalf("app filter %+v", u)
	}

	// payments: a read-only standalone that has exited (Consumers 0).
	admin := passwordLogin(t, f, "admin", "admin")
	p, err := fc(admin).volumeUsers(ctx, "payments", "ledger-data", "")
	if err != nil || len(p.Users) != 1 || p.Users[0].Standalone != "ledger-migrate" || !p.Users[0].ReadOnly || p.Users[0].Attached {
		t.Fatalf("ledger-data %+v %v", p, err)
	}
	_, err = fc(bob).volumeUsers(ctx, "payments", "ledger-data", "")
	wantCode(t, err, CodeDenied)
	_, err = fc(alice).volumeUsers(ctx, "shop", "nope", "")
	wantCode(t, err, CodeMissing)

	// Down the app: it drops out.
	apps, _ := alice.Apps(ctx, "shop", "")
	for _, a := range apps.Items {
		if a.App == "php-shop" {
			if _, res := submit(t, alice, ActionDownApp, a.Revision, control.AppDown{Tenant: "shop", App: "php-shop", Operation: "down-p"}, rootFor(t, alice, ActionDownApp)); res.Code != ResultApplied {
				t.Fatalf("down %+v", res)
			}
		}
	}
	if u, _ := fc(alice).volumeUsers(ctx, "shop", "mysql-data", ""); len(u.Users) != 0 {
		t.Fatalf("after down %+v", u)
	}
}

// the network row carries the whole DNS policy and its revision;
// members report the resolver while enabled.
func TestNetworkDNSRead(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	admin := passwordLogin(t, f, "admin", "admin")
	alice := passwordLogin(t, f, "alice", "alice")
	row := func() *Network {
		p, _ := admin.Resources(ctx, "payments", "")
		for _, e := range p.Items {
			if e.Network != nil && e.Network.Name == "payments-net" {
				return e.Network
			}
		}
		t.Fatal("no payments-net")
		return nil
	}
	pol := services.ManagedDNSPolicy{Enabled: true, Zone: "pay.internal", ClientZone: "pay.internal", TTL: 30, NegativeTTL: 5,
		Transports: []string{"udp"}, Upstreams: []netip.AddrPort{netip.MustParseAddrPort("10.0.0.53:53")}, MaxQueries: 100}
	if _, res := submit(t, admin, ActionConfigureNetworkDNS, 0, services.ManagedDNSDefinition{Schema: 1, Tenant: "payments", Network: "payments-net", Policy: pol}, rootFor(t, admin, ActionConfigureNetworkDNS)); res.Code != ResultApplied {
		t.Fatalf("configure %+v", res)
	}
	n := row()
	if n.DNS == nil || n.DNS.Revision == 0 || n.DNS.Policy.MaxQueries != 100 || n.DNS.Policy.ClientZone != "pay.internal" || n.Members[0].Resolver == "" ||
		len(n.DNS.Resolvers) == 0 || n.DNS.Ready == nil || !*n.DNS.Ready || n.DNS.State != "ready" {
		t.Fatalf("after configure %+v %+v", n.DNS, n.Members)
	}
	off := n.DNS.Policy
	off.Enabled = false
	if _, res := submit(t, admin, ActionConfigureNetworkDNS, n.DNS.Revision, services.ManagedDNSDefinition{Schema: 1, Tenant: "payments", Network: "payments-net", Policy: off}, rootFor(t, admin, ActionConfigureNetworkDNS)); res.Code != ResultApplied {
		t.Fatalf("disable %+v", res)
	}
	m := row()
	if m.DNS.Enabled || m.DNS.Revision <= n.DNS.Revision || m.DNS.Policy.MaxQueries != 100 || m.DNS.Zone != "pay.internal" || m.Members[0].Resolver != "" || len(m.DNS.Resolvers) != 0 || m.DNS.State != "stopped" {
		t.Fatalf("after disable %+v %+v", m.DNS, m.Members)
	}
	p, _ := alice.Resources(ctx, "shop", "")
	for _, e := range p.Items {
		if e.Tenant != "shop" && e.Tenant != "" {
			t.Fatalf("other tenant row %+v", e)
		}
	}
}
