// SPDX-License-Identifier: Apache-2.0

package tenancy

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"net/netip"
	"slices"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/network"
)

func TestSystemPolicyUsersAreSortedAndKeptAcrossDecode(t *testing.T) {
	f := newFixture(t)
	empty, err := f.n.Encode()
	if err != nil || bytes.Contains(empty, []byte(`"System"`)) {
		t.Fatalf("an empty policy is encoded: %s %v", empty, err)
	}
	n, err := f.n.SetSystemUse("node-b", true)
	if err != nil {
		t.Fatal(err)
	}
	if n, err = n.SetSystemUse("node-a", true); err != nil {
		t.Fatal(err)
	}
	if _, err = n.SetSystemUse("node-a", true); !errors.Is(err, access.ErrConflict) {
		t.Fatalf("repeated use: %v", err)
	}
	if _, err = n.SetSystemUse("Bad", true); !errors.Is(err, ErrPolicy) {
		t.Fatalf("bad node: %v", err)
	}
	raw, err := n.Encode()
	if err != nil {
		t.Fatal(err)
	}
	back, err := Decode(raw)
	if err != nil || !slices.Equal(back.SystemPolicy().Users, []string{"node-a", "node-b"}) || back.SystemPolicy().RangeOrDefault() != DefaultSystemRange {
		t.Fatalf("decode: %+v %v", back.SystemPolicy(), err)
	}
	if n, err = back.SetSystemUse("node-a", false); err != nil || !slices.Equal(n.SystemPolicy().Users, []string{"node-b"}) {
		t.Fatalf("off: %+v %v", n.SystemPolicy(), err)
	}
	if n, err = n.SetSystemUse("node-b", false); err != nil {
		t.Fatal(err)
	}
	if raw, _ = n.Encode(); bytes.Contains(raw, []byte(`"System"`)) {
		t.Fatalf("an emptied policy is encoded: %s", raw)
	}
}

func TestSystemRangeChangesOnlyWithoutMembers(t *testing.T) {
	f, q, _ := logicalFixture(t)
	for _, bad := range []string{"10.20.0.0/23", "10.20.1.0/16", "fd00::/48", "10.0.0.0/7"} {
		if _, err := f.n.SetSystemRange(f.n.Revision(), netip.MustParsePrefix(bad)); !errors.Is(err, ErrPolicy) {
			t.Fatalf("%s: %v", bad, err)
		}
	}
	if _, err := f.n.SetSystemRange(f.n.Revision(), DefaultSystemRange); !errors.Is(err, access.ErrConflict) {
		t.Fatalf("same range: %v", err)
	}
	if _, err := f.n.SetSystemRange(f.n.Revision()+1, netip.MustParsePrefix("10.20.0.0/16")); !errors.Is(err, access.ErrConflict) {
		t.Fatalf("stale revision: %v", err)
	}
	n, err := f.n.SetSystemRange(f.n.Revision(), netip.MustParsePrefix("10.20.0.0/22"))
	if err != nil || n.SystemPolicy().RangeOrDefault() != netip.MustParsePrefix("10.20.0.0/22") {
		t.Fatalf("set: %+v %v", n.SystemPolicy(), err)
	}
	// Setting the default again stores nothing.
	if back, err := n.SetSystemRange(n.Revision(), DefaultSystemRange); err != nil || back.SystemPolicy().Range.IsValid() {
		t.Fatalf("default: %+v %v", back.SystemPolicy(), err)
	}
	member, err := n.NextSystemMember("node-a", public(f.a))
	if err != nil {
		t.Fatal(err)
	}
	sys := TUNDefinition{Name: SystemNetwork, System: true, GatewayMode: network.ManagedGatewayMode, Members: []TUNNode{member}}
	if n, err = n.CreateSystemTUN(q, n.Revision(), sys); err != nil {
		t.Fatal(err)
	}
	if _, err = n.SetSystemRange(n.Revision(), netip.MustParsePrefix("10.30.0.0/16")); !errors.Is(err, ErrPolicy) {
		t.Fatalf("range moved under a member: %v", err)
	}
}

func TestNextSystemMemberTakesTheFirstFreeAddresses(t *testing.T) {
	f, q, _ := logicalFixture(t)
	n := f.n
	a, err := n.NextSystemMember("node-a", public(f.a))
	if err != nil || a.Addresses[0] != netip.MustParsePrefix("10.254.0.1/32") || a.Pools[0].Prefix != netip.MustParsePrefix("10.254.1.0/24") || a.Pools[0].MTU != SystemMTU || a.Pools[0].Gateway != netip.MustParseAddr("10.254.1.1") {
		t.Fatalf("first: %+v %v", a, err)
	}
	sys := TUNDefinition{Name: SystemNetwork, System: true, GatewayMode: network.ManagedGatewayMode, Members: []TUNNode{a}}
	if n, err = n.CreateSystemTUN(q, n.Revision(), sys); err != nil {
		t.Fatal(err)
	}
	b, err := n.NextSystemMember("node-b", public(f.b))
	if err != nil || b.Addresses[0] != netip.MustParsePrefix("10.254.0.2/32") || b.Pools[0].Prefix != netip.MustParsePrefix("10.254.2.0/24") {
		t.Fatalf("second: %+v %v", b, err)
	}
	if n, err = n.JoinSystemTUN(q, n.Revision(), b); err != nil {
		t.Fatal(err)
	}
	if got := n.SystemMembers(); len(got) != 2 || got[0].Node != "node-a" || got[1].Node != "node-b" {
		t.Fatalf("members: %+v", got)
	}
	// A full range has no pool for another member.
	small, err := f.n.SetSystemRange(f.n.Revision(), netip.MustParsePrefix("10.40.0.0/22"))
	if err != nil {
		t.Fatal(err)
	}
	for i, node := range []string{"node-a", "node-b"} {
		k := []ed25519.PrivateKey{f.a, f.b}[i]
		m, err := small.NextSystemMember(node, public(k))
		if err != nil {
			t.Fatal(err)
		}
		def := TUNDefinition{Name: SystemNetwork, System: true, GatewayMode: network.ManagedGatewayMode, Members: []TUNNode{m}}
		if i == 0 {
			small, err = small.CreateSystemTUN(q, small.Revision(), def)
		} else {
			small, err = small.JoinSystemTUN(q, small.Revision(), m)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if m, err := small.NextSystemMember("node-c", public(f.a)); err != nil || m.Pools[0].Prefix != netip.MustParsePrefix("10.40.3.0/24") {
		t.Fatalf("last pool: %+v %v", m, err)
	}
}

func TestSystemMemberDrainsAndRetiresOnItsOwnClosure(t *testing.T) {
	f, q, _ := logicalFixture(t)
	a, err := f.n.NextSystemMember("node-a", public(f.a))
	if err != nil {
		t.Fatal(err)
	}
	n, err := f.n.CreateSystemTUN(q, f.n.Revision(), TUNDefinition{Name: SystemNetwork, System: true, GatewayMode: network.ManagedGatewayMode, Members: []TUNNode{a}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = n.DrainSystem("node-b", 0); !errors.Is(err, ErrPolicy) {
		t.Fatalf("drained a server that is not a member: %v", err)
	}
	v := n.SystemMembers()[0]
	if _, err = n.DrainSystem("node-a", v.Revision+1); !errors.Is(err, access.ErrConflict) {
		t.Fatalf("stale drain: %v", err)
	}
	if n, err = n.DrainSystem("node-a", v.Revision); err != nil {
		t.Fatal(err)
	}
	v = n.SystemMembers()[0]
	p := NetworkClosure{Cluster: n.cluster, Network: v.ID, Node: v.Node, Owner: v.Owner, Generation: v.Generation, Revision: v.Revision, NativeGone: true}
	p.Signature = ed25519.Sign(f.a, NetworkClosureBytes(p))
	if _, err = n.Retire(f.c, "admin", p); !errors.Is(err, ErrPolicy) {
		t.Fatalf("a user retired the system member: %v", err)
	}
	wrong := p
	wrong.Signature = ed25519.Sign(f.b, NetworkClosureBytes(p))
	if _, err = n.RetireSystem(wrong); !errors.Is(err, ErrPolicy) {
		t.Fatalf("another server's closure: %v", err)
	}
	if n, err = n.RetireSystem(p); err != nil || len(n.SystemMembers()) != 0 {
		t.Fatalf("retire: %v", err)
	}
}

// A tenant network never takes the system range: not its pools, not its
// tunnel addresses, whether the system network exists or not, and the
// range cannot move onto a tenant network.
func TestTenantNetworksStayOutOfTheSystemRange(t *testing.T) {
	f, q, d := logicalFixture(t)
	pool := copyTUN(d)
	pool.Members[1].Pools[0].Prefix = netip.MustParsePrefix("10.254.9.0/24")
	pool.Members[1].Pools[0].Gateway = netip.MustParseAddr("10.254.9.1")
	tunnel := copyTUN(d)
	tunnel.Members[0].Addresses = []netip.Prefix{netip.MustParsePrefix("10.254.200.1/32")}
	for name, bad := range map[string]TUNDefinition{"pool": pool, "tunnel": tunnel} {
		if _, err := f.n.CreateTUN(f.c, q, "admin", f.n.Revision(), bad); !errors.Is(err, ErrPolicy) {
			t.Fatalf("create with a %s in the system range: %v", name, err)
		}
	}
	one := copyTUN(d)
	one.Members = one.Members[:1]
	n, err := f.n.CreateTUN(f.c, q, "admin", f.n.Revision(), one)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = n.JoinTUN(f.c, q, "admin", n.Revision(), one.Tenant, one.Name, pool.Members[1]); !errors.Is(err, ErrPolicy) {
		t.Fatalf("join in the system range: %v", err)
	}
	// Every reservation goes through the same check (reservedOverlap):
	// a plain network, a plan's target, and reconfigure-tun-network, which
	// creates its target through CreateTUN.
	if _, err = n.Create(f.c, "admin", n.Revision(), definition("first", "lan", "node-a", "10.254.40.0/24", f.a)); !errors.Is(err, ErrPolicy) {
		t.Fatalf("plain network in the system range: %v", err)
	}
	if _, err = n.Create(f.c, "admin", n.Revision(), definition("first", "lan", "node-a", "10.73.40.0/24", f.a)); err != nil {
		t.Fatalf("plain network outside the system range: %v", err)
	}
	// The range cannot move onto 10.71.1.0/24 (one's pool).
	if _, err = n.SetSystemRange(n.Revision(), netip.MustParsePrefix("10.71.0.0/16")); !errors.Is(err, ErrPolicy) {
		t.Fatalf("range moved onto a tenant network: %v", err)
	}
	moved, err := n.SetSystemRange(n.Revision(), netip.MustParsePrefix("10.90.0.0/16"))
	if err != nil {
		t.Fatal(err)
	}
	// 10.254 is free once the range moves.
	if _, err = moved.JoinTUN(f.c, q, "admin", moved.Revision(), one.Tenant, one.Name, pool.Members[1]); err != nil {
		t.Fatalf("join after the range moved: %v", err)
	}
}
