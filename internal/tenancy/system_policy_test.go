// SPDX-License-Identifier: Apache-2.0

package tenancy

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"net/netip"
	"slices"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/network"
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
	if err != nil || !slices.Equal(back.SystemPolicy().Users, []string{"node-a", "node-b"}) {
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

func TestNextSystemMemberTakesTheFirstFreeAddresses(t *testing.T) {
	f, q, _ := logicalFixture(t)
	n := f.n
	a, err := n.NextSystemMember("node-a", public(f.a))
	if err != nil || len(a.Addresses) != 0 || a.Pools[0].Prefix != netip.MustParsePrefix("10.254.1.0/24") || a.Pools[0].MTU != SystemMTU || a.Pools[0].Gateway != netip.MustParseAddr("10.254.1.1") || a.Pools[0].IPAM.Dynamic != netip.MustParsePrefix("10.254.1.128/25") {
		t.Fatalf("first: %+v %v", a, err)
	}
	sys := TUNDefinition{Name: SystemNetwork, System: true, GatewayMode: network.ManagedGatewayMode, Members: []TUNNode{a}}
	if n, err = n.CreateSystemTUN(q, n.Revision(), sys); err != nil {
		t.Fatal(err)
	}
	b, err := n.NextSystemMember("node-b", public(f.b))
	if err != nil || b.Pools[0].Prefix != netip.MustParsePrefix("10.254.2.0/24") {
		t.Fatalf("second: %+v %v", b, err)
	}
	if n, err = n.JoinSystemTUN(q, n.Revision(), b); err != nil {
		t.Fatal(err)
	}
	if got := n.SystemMembers(); len(got) != 2 || got[0].Node != "node-a" || got[1].Node != "node-b" || got[0].TunnelAddresses[0] != netip.MustParsePrefix("10.254.240.1/32") || got[1].TunnelAddresses[0] != netip.MustParsePrefix("10.254.240.2/32") {
		t.Fatalf("members: %+v", got)
	}
	// A third server takes the next pool.
	small := f.n
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
	if m, err := small.NextSystemMember("node-c", public(f.a)); err != nil || m.Pools[0].Prefix != netip.MustParsePrefix("10.254.3.0/24") {
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
	tunnel.Members[1].Pools[0].Prefix = netip.MustParsePrefix("10.254.244.0/24") // the server block
	tunnel.Members[1].Pools[0].Gateway = netip.MustParseAddr("10.254.244.1")
	for name, bad := range map[string]TUNDefinition{"pool": pool, "server block": tunnel} {
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
}

// A cluster app runs on one server: the first claim wins while its
// runner uses the network; another server's claim is refused. Its address
// is the cluster-wide one, its container sits at the fixed host in the
// runner's pool, and the other members' TUNs route the address to it.
func TestClusterAppRunsOnOneServer(t *testing.T) {
	f, q, _ := logicalFixture(t)
	a, err := f.n.NextSystemMember("node-a", public(f.a))
	if err != nil {
		t.Fatal(err)
	}
	n, err := f.n.CreateSystemTUN(q, f.n.Revision(), TUNDefinition{Name: SystemNetwork, System: true, GatewayMode: network.ManagedGatewayMode, Members: []TUNNode{a}})
	if err != nil {
		t.Fatal(err)
	}
	b, err := n.NextSystemMember("node-b", public(f.b))
	if err != nil {
		t.Fatal(err)
	}
	if n, err = n.JoinSystemTUN(q, n.Revision(), b); err != nil {
		t.Fatal(err)
	}
	both := []string{"node-a", "node-b"}
	for _, node := range both {
		if n, err = n.SetSystemUse(node, true); err != nil {
			t.Fatal(err)
		}
	}
	// only a server that uses the network
	if _, err = n.ClaimClusterApp(n.Revision(), "node-a", "web", []string{"node-b"}); !errors.Is(err, ErrPolicy) {
		t.Fatalf("not a user: %v", err)
	}
	if _, err = n.ClaimClusterApp(n.Revision()+1, "node-a", "web", both); !errors.Is(err, access.ErrConflict) {
		t.Fatalf("stale: %v", err)
	}
	if n, err = n.ClaimClusterApp(n.Revision(), "node-b", "web", both); err != nil {
		t.Fatal(err)
	}
	for _, node := range both {
		if _, err = n.ClaimClusterApp(n.Revision(), node, "web", both); !errors.Is(err, access.ErrConflict) {
			t.Fatalf("%s claims a running app: %v", node, err)
		}
	}
	if node, addr, ok := n.ClusterAppAddress("web", both); !ok || node != "node-b" || addr != netip.MustParseAddr("10.254.0.2") {
		t.Fatalf("address: %s %v %v", node, addr, ok)
	}
	if node, addr, ok := n.ClusterAppPoolAddress("web", both); !ok || node != "node-b" || addr != netip.MustParseAddr("10.254.2.2") {
		t.Fatalf("pool address: %s %v %v", node, addr, ok)
	}
	rows, err := n.TUNSources("", SystemNetwork)
	if err != nil || len(rows) != 2 {
		t.Fatal(rows, err)
	}
	cluster := netip.MustParsePrefix("10.254.0.2/32")
	for _, row := range rows {
		if got := slices.Contains(row.Tunnel.Routes, cluster); got != (row.Network.Node == "node-a") {
			t.Fatalf("%s routes %v", row.Network.Node, row.Tunnel.Routes)
		}
	}
	// stopping clears the record and the route
	if off, err := n.SetSystemUse("node-b", false); err != nil || len(off.ClusterAppHosts()) != 0 {
		t.Fatal(off.ClusterAppHosts(), err)
	}
	raw, err := n.Encode()
	if err != nil {
		t.Fatal(err)
	}
	back, err := Decode(raw)
	if want := []ClusterAppRunner{{App: "web", Node: "node-b"}}; err != nil || !slices.Equal(back.SystemPolicy().Runners, want) {
		t.Fatalf("decode: %+v %v", back.SystemPolicy(), err)
	}
	// node-b left the cluster (no longer a user): node-a may claim
	if _, ok := back.ClusterAppRunner("web", []string{"node-a"}); ok {
		t.Fatal("a server that left still runs it")
	}
	if n, err = back.ClaimClusterApp(back.Revision(), "node-a", "web", []string{"node-a"}); err != nil {
		t.Fatal(err)
	}
	// stopping cluster apps drops the server's runs
	if n, err = n.SetSystemUse("node-a", false); err != nil || len(n.SystemPolicy().Runners) != 0 {
		t.Fatalf("off: %+v %v", n.SystemPolicy(), err)
	}
}
