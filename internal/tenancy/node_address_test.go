// SPDX-License-Identifier: Apache-2.0

package tenancy

import (
	"net/netip"
	"testing"

	"github.com/jay94ks/seafield/internal/network"
)

// Each server's fixed address (membership) is its tunnel address in every
// TUN network, tenant and system alike; a definition cannot name another,
// and a server the view does not know gets no member.
func TestServerAddressIsSharedByEveryNetworkOnTheServer(t *testing.T) {
	f, q, d := logicalFixture(t)
	n, err := f.n.CreateTUN(f.c, q, "admin", f.n.Revision(), d)
	if err != nil {
		t.Fatal(err)
	}
	b := netip.PrefixFrom(testServers["node-b"], 32)
	if v, _ := n.NamedNetwork("first", "services", "node-b"); v.TunnelAddresses[0] != b {
		t.Fatalf("first network on node-b: %v", v.TunnelAddresses)
	}
	other := copyTUN(d)
	other.Tenant, other.Members = "second", other.Members[1:]
	other.Members[0].Pools[0].Prefix, other.Members[0].Pools[0].Gateway = netip.MustParsePrefix("10.73.0.0/24"), netip.MustParseAddr("10.73.0.1")
	if n, err = n.CreateTUN(f.c, q, "admin", n.Revision(), other); err != nil {
		t.Fatal(err)
	}
	if v, _ := n.NamedNetwork("second", "services", "node-b"); v.TunnelAddresses[0] != b {
		t.Fatalf("second network on node-b: %v", v.TunnelAddresses)
	}
	member, err := n.NextSystemMember("node-b", public(f.b))
	if err != nil {
		t.Fatal(err)
	}
	if n, err = n.CreateSystemTUN(q, n.Revision(), TUNDefinition{Name: SystemNetwork, System: true, GatewayMode: network.ManagedGatewayMode, Members: []TUNNode{member}}); err != nil {
		t.Fatal(err)
	}
	if v := n.SystemMembers(); v[0].TunnelAddresses[0] != b || v[0].Pools[0].Prefix != netip.MustParsePrefix("10.254.1.0/24") {
		t.Fatalf("system member on node-b: %+v", v[0])
	}
	named := copyTUN(d)
	named.Name = "named"
	named.Members[0].Addresses = []netip.Prefix{netip.MustParsePrefix("10.72.0.1/32")}
	if _, err = f.n.CreateTUN(f.c, q, "admin", f.n.Revision(), named); err == nil {
		t.Fatal("a named tunnel address was accepted")
	}
	unknown := f.n.WithServers(map[string]netip.Addr{"node-a": testServers["node-a"]})
	if _, err = unknown.CreateTUN(f.c, q, "admin", unknown.Revision(), d); err == nil {
		t.Fatal("a server without an address joined")
	}
	if _, err = f.n.NextSystemMember("node-z", public(f.a)); err == nil {
		t.Fatal("a system member without a server address")
	}
}
