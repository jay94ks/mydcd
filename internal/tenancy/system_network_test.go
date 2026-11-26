// SPDX-License-Identifier: Apache-2.0

package tenancy

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
)

func systemDefinition(d TUNDefinition) TUNDefinition {
	d = copyTUN(d)
	d.Tenant, d.Name, d.System = "", SystemNetwork, true
	return d
}

func TestSystemNetworkUsesTheTUNCoreAndOnlyTheServerLimit(t *testing.T) {
	f, q, d := logicalFixture(t)
	sys := systemDefinition(d)
	n, err := f.n.CreateSystemTUN(q, f.n.Revision(), sys)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := n.TUNSources("", SystemNetwork)
	if err != nil || len(rows) != 2 || rows[0].Tunnel == nil || !rows[0].Network.System {
		t.Fatalf("rows=%+v err=%v", rows, err)
	}
	if err = q.ValidateNetworks(n); err != nil {
		t.Fatalf("one server-wide slot per member: %v", err)
	}
	if err = n.ValidateTenants(f.c); err != nil {
		t.Fatalf("no tenant to validate: %v", err)
	}
	raw, err := n.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if back, err := Decode(raw); err != nil || len(back.AllNetworks()) != 2 {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := n.NamedNetwork("", SystemNetwork, "node-a"); ok {
		t.Fatal("a user app resolved the system network")
	}
	// The same addresses cannot be reused by a tenant network.
	if _, err = n.CreateTUN(f.c, q, "admin", n.Revision(), d); err == nil {
		t.Fatal("tenant network overlapped the system network")
	}
}

func TestSystemNetworkRefusesManualManagement(t *testing.T) {
	f, q, d := logicalFixture(t)
	sys := systemDefinition(d)
	if _, err := f.n.CreateTUN(f.c, q, "admin", f.n.Revision(), sys); !errors.Is(err, ErrPolicy) {
		t.Fatalf("create-tun-network made a system network: %v", err)
	}
	for _, bad := range []TUNDefinition{d, {Tenant: "", Name: "other", Members: sys.Members, System: true}} {
		if _, err := f.n.CreateSystemTUN(q, f.n.Revision(), bad); !errors.Is(err, ErrPolicy) {
			t.Fatalf("system create took %s/%s: %v", bad.Tenant, bad.Name, err)
		}
	}
	n, err := f.n.CreateSystemTUN(q, f.n.Revision(), sys)
	if err != nil {
		t.Fatal(err)
	}
	member := n.AllNetworks()[0]
	if _, err = n.Drain(f.c, "admin", "", member.ID, member.Revision); err == nil {
		t.Fatal("drain-network reached the system network")
	}
	if _, err = n.Retire(f.c, "admin", NetworkClosure{Tenant: "", Network: member.ID}); err == nil {
		t.Fatal("a member retire reached the system network")
	}
	target := member
	target.Pools = append([]Subnet(nil), member.Pools...)
	if _, err = n.PlanChange(f.c, "admin", "", member.ID, "change", member.Revision, target); err == nil {
		t.Fatal("plan-network-change reached the system network")
	}
	if _, err = n.ReplaceTUN(f.c, q, "admin", n.Revision(), []NetworkChangeVersion{{Tenant: "", ID: member.ID}}, sys); err == nil {
		t.Fatal("reconfigure-tun-network reached the system network")
	}
	if _, err = n.Propose(f.c, "admin", n.Revision(), Route{ID: "r", Source: Binding{Tenant: "first"}, Destination: Binding{Tenant: "", Network: member.ID, Prefix: netip.MustParsePrefix("10.71.1.0/24")}}); err == nil {
		t.Fatal("a route reached the system network")
	}
	if err = q.AdmitNetwork(f.c, "admin", "", "node-a", member.Owner, n); !errors.Is(err, access.ErrDenied) {
		t.Fatalf("admit without a tenant: %v", err)
	}
}

func TestSystemNetworkSourceKeysCannotNameATenant(t *testing.T) {
	sys := SourceIdentity{Kind: "bridge", Network: SystemNetwork, Node: "node-a"}
	key := sys.Key()
	if key != ManagedNetworkSourcePrefix+"bridge/@system/mydc-system/node-a" {
		t.Fatalf("key %q", key)
	}
	if back, err := ParseSourceIdentity(key); err != nil || back != sys {
		t.Fatalf("parse %+v %v", back, err)
	}
	if (SourceIdentity{Kind: "bridge", Network: "other", Node: "node-a"}).Key() != "" {
		t.Fatal("an empty tenant named a non-system network")
	}
	if PacketNamespace("", SystemNetwork) == PacketNamespace("mydc-system", SystemNetwork) {
		t.Fatal("system packet namespace collides with a tenant's")
	}
}

func TestJoinTUNAddsOneServerAndLeavesTheOthersAsTheyWere(t *testing.T) {
	f, q, d := logicalFixture(t)
	one := copyTUN(d)
	one.Members = one.Members[:1]
	n, err := f.n.CreateTUN(f.c, q, "admin", f.n.Revision(), one)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := n.TUNSources("first", "services")
	joiner := d.Members[1]
	if _, err = n.JoinTUN(f.c, q, "admin", n.Revision(), "first", "services", d.Members[0]); err == nil {
		t.Fatal("a server joined twice")
	}
	if _, err = n.JoinTUN(f.c, q, "admin", n.Revision(), "", SystemNetwork, joiner); err == nil {
		t.Fatal("the tenant join reached the system network")
	}
	joined, err := n.JoinTUN(f.c, q, "admin", n.Revision(), "first", "services", joiner)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := joined.TUNSources("first", "services")
	if err != nil || len(rows) != 2 || rows[0].Tunnel == nil || rows[1].Tunnel == nil {
		t.Fatalf("rows %+v %v", rows, err)
	}
	old, added := rows[0], rows[1]
	if old.Network.Node != before[0].Network.Node {
		old, added = added, old
	}
	if old.Network.Generation != before[0].Network.Generation || old.Network.Revision != before[0].Network.Revision || old.BridgeKey != before[0].BridgeKey || added.Network.Node != joiner.Node {
		t.Fatal("the existing member was replaced")
	}
	if added.Network.GatewayMode != before[0].Network.GatewayMode {
		t.Fatal("the joiner did not take the network's gateway mode")
	}
	sys, err := f.n.CreateSystemTUN(q, f.n.Revision(), TUNDefinition{Name: SystemNetwork, System: true, Members: one.Members})
	if err != nil {
		t.Fatal(err)
	}
	sys, err = sys.JoinSystemTUN(q, sys.Revision(), joiner)
	if err != nil || len(sys.AllNetworks()) != 2 || !sys.AllNetworks()[0].System || !sys.AllNetworks()[1].System {
		t.Fatal("system join", err)
	}
}
