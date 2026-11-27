// SPDX-License-Identifier: Apache-2.0

package tenancy

import (
	"errors"
	"fmt"
	"net/netip"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
)

// A local network stays on one server: join is refused while it is on, it
// can be turned off at any time and on again only with one member.
func TestLocalToggleKeepsANetworkOnOneServer(t *testing.T) {
	f, q, d := logicalFixture(t)
	if _, err := f.n.CreateTUN(f.c, q, "admin", f.n.Revision(), TUNDefinition{Tenant: d.Tenant, Name: d.Name, Members: d.Members, Toggles: []NetworkToggle{ToggleLocal}}); err == nil {
		t.Fatal("a local network was created on two servers")
	}
	one := copyTUN(d)
	one.Members = one.Members[:1]
	if _, err := f.n.CreateTUN(f.c, q, "admin", f.n.Revision(), TUNDefinition{Tenant: d.Tenant, Name: d.Name, Members: one.Members, Toggles: []NetworkToggle{"unknown"}}); err == nil {
		t.Fatal("an unknown toggle was accepted")
	}
	one.Toggles = []NetworkToggle{ToggleLocal}
	n, err := f.n.CreateTUN(f.c, q, "admin", f.n.Revision(), one)
	if err != nil {
		t.Fatal(err)
	}
	if v := n.AllNetworks()[0]; len(v.Toggles) != 1 || v.Toggles[0] != ToggleLocal {
		t.Fatalf("toggles %+v", v.Toggles)
	}
	if _, err = n.JoinTUN(f.c, q, "admin", n.Revision(), "first", "services", d.Members[1]); err == nil {
		t.Fatal("a server joined a local network")
	}
	if _, err = n.SetToggle(f.c, "admin", n.Revision(), "first", "services", ToggleLocal, true); !errors.Is(err, access.ErrConflict) {
		t.Fatal("setting the current value", err)
	}
	if _, err = n.SetToggle(f.c, "nobody", n.Revision(), "first", "services", ToggleLocal, false); err == nil {
		t.Fatal("an unauthorized actor set a toggle")
	}
	before := n.AllNetworks()[0]
	cross, err := n.SetToggle(f.c, "admin", n.Revision(), "first", "services", ToggleLocal, false)
	if err != nil {
		t.Fatal(err)
	}
	after := cross.AllNetworks()[0]
	if len(after.Toggles) != 0 || after.Generation != before.Generation || after.Revision != before.Revision {
		t.Fatalf("turned off %+v", after)
	}
	src, _ := n.TUNSources("first", "services")
	dst, _ := cross.TUNSources("first", "services")
	if src[0].Bridge.Network != dst[0].Bridge.Network || len(dst[0].Tunnel.Routes) != 0 {
		t.Fatal("the toggle changed the native sources")
	}
	// A planned change keeps the toggles; it cannot change them.
	target := after
	target.Toggles = []NetworkToggle{ToggleLocal}
	target.Generation, target.Revision = 0, 0
	if _, err = cross.PlanChange(f.c, "admin", "first", after.ID, "chg", after.Revision, target); err == nil {
		t.Fatal("a planned change set a toggle")
	}
	target.Toggles = nil
	if _, err = cross.PlanChange(f.c, "admin", "first", after.ID, "chg", after.Revision, target); err != nil {
		t.Fatal("a planned change without toggles", err)
	}
	joined, err := cross.JoinTUN(f.c, q, "admin", cross.Revision(), "first", "services", d.Members[1])
	if err != nil {
		t.Fatal(err)
	}
	if _, err = joined.SetToggle(f.c, "admin", joined.Revision(), "first", "services", ToggleLocal, true); err == nil {
		t.Fatal("a network on two servers was made local")
	}
	if _, err = joined.SetToggle(f.c, "admin", joined.Revision(), "", SystemNetwork, ToggleLocal, true); err == nil {
		t.Fatal("the system network took a toggle")
	}
}

// A toggle changes no member revision, so an Active route bound to the
// network stays current and keeps allowing new flows.
func TestToggleKeepsRoutesBoundToTheNetworkActive(t *testing.T) {
	f, q, d := logicalFixture(t)
	first := copyTUN(d)
	first.Members = first.Members[:1]
	n, err := f.n.CreateTUN(f.c, q, "admin", f.n.Revision(), first)
	if err != nil {
		t.Fatal(err)
	}
	second := TUNDefinition{Tenant: "second", Name: "db", Members: []TUNNode{{Node: "node-b", Owner: public(f.b), Pools: definition("second", "unused", "node-b", "10.2.0.0/24", f.b).Pools}}}
	if n, err = n.CreateTUN(f.c, q, "admin", n.Revision(), second); err != nil {
		t.Fatal(err)
	}
	src, err := n.Bind("first", logicalMemberID("first", "services", "node-a"), netip.MustParsePrefix("10.71.1.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	dst, err := n.Bind("second", logicalMemberID("second", "db", "node-b"), netip.MustParsePrefix("10.2.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	if n, err = n.Propose(f.c, "alice", n.Revision(), Route{ID: "sql", Source: src, Destination: dst, Protocol: 6, Ports: []Ports{{3306, 3306}}}); err != nil {
		t.Fatal(err)
	}
	for _, side := range []struct{ actor, side string }{{"alice", "first"}, {"bob", "second"}} {
		r, _ := n.Route("first", "sql")
		if n, err = n.Approve(f.c, side.actor, "first", "sql", side.side, r.Revision); err != nil {
			t.Fatal(err)
		}
	}
	check := func(n Networks, when string) {
		t.Helper()
		r, _ := n.Route("first", "sql")
		if r.Phase != Active || !n.AllowsNewFlow(f.c, "first", "sql", netip.MustParseAddr("10.71.1.10"), netip.MustParseAddr("10.2.0.10"), 6, 3306) {
			t.Fatal("route not active", when, r.Phase)
		}
		revoked, err := n.RevokeUnauthorized(f.c)
		if err != nil {
			t.Fatal(err)
		}
		if r, _ := revoked.Route("first", "sql"); r.Phase != Active {
			t.Fatal("route revoked", when, r.Phase)
		}
		if _, err := n.Encode(); err != nil {
			t.Fatal(when, err)
		}
	}
	check(n, "before")
	for _, on := range []bool{true, false} {
		if n, err = n.SetToggle(f.c, "admin", n.Revision(), "first", "services", ToggleLocal, on); err != nil {
			t.Fatal(on, err)
		}
		check(n, fmt.Sprint("local ", on))
	}
}
