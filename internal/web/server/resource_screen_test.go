// SPDX-License-Identifier: Apache-2.0

package server

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/workload"
)

func TestResourceEntriesGroupTUNMembers(t *testing.T) {
	pool := func(s string) []tenancy.Subnet {
		return []tenancy.Subnet{{ID: "main", Prefix: netip.MustParsePrefix(s)}}
	}
	rows := []control.ResourceEntry{
		{Key: "limit/shop/node-a", Limit: &tenancy.NodeLimit{Tenant: "shop", Node: "node-a", Revision: 2, Capacity: workload.Resources{CPU: 2 * cpuUnit, Memory: 1 << 30}}},
		{Key: "network/shop/lan", Network: &tenancy.Network{Tenant: "shop", ID: "lan", Node: "node-a", Revision: 3, Pools: pool("10.1.0.0/24")}},
		{Key: "network/shop/mesh-node-b", Network: &tenancy.Network{Tenant: "shop", ID: "mesh-node-b", Node: "node-b", Logical: "mesh", Revision: 5, Pools: pool("10.2.1.0/24"),
			TunnelAddresses: []netip.Prefix{netip.MustParsePrefix("10.255.0.2/32")}},
			Change: &control.NetworkChangeStatus{ID: "c1", Phase: tenancy.ChangePhase("reserved"), Target: tenancy.Network{Pools: pool("10.3.0.0/24")}}},
		{Key: "network/shop/mesh-node-a", Network: &tenancy.Network{Tenant: "shop", ID: "mesh-node-a", Node: "node-a", Logical: "mesh", Revision: 4, Pools: pool("10.2.0.0/24")}},
	}
	got := resourceEntries(rows)
	if len(got) != 3 || got[0].Limit == nil || got[0].Limit.CPUs != 2 || got[0].Key != "shop/limit/node-a" {
		t.Fatalf("%+v", got)
	}
	if n := got[1].Network; n == nil || n.Kind != "bridge" || n.Name != "lan" || n.CIDR != "10.1.0.0/24" || len(n.Members) != 1 {
		t.Fatalf("bridge %+v", got[1].Network)
	}
	n := got[2].Network
	if n == nil || got[2].Key != "shop/network/mesh" || n.Kind != "tun" || n.Revision != 5 || !slices.Equal(n.Nodes, []string{"node-a", "node-b"}) ||
		n.CIDR != "10.2.0.0/24" || n.Members[1].Tunnel != "10.255.0.2" || n.Members[1].Change == nil || n.Members[1].Change.TargetCIDR != "10.3.0.0/24" {
		t.Fatalf("tun %+v", n)
	}
}

// The networks list is regrouped from sfcd's per-member rows: one row per
// network with its members, and the use counts from network-users.
func TestNetworksScreenRow(t *testing.T) {
	f, _ := newFakeFixture(t)
	fakeLogin(t, f, "alice")
	code, out := f.do("GET", "/api/v1/t/shop/networks", nil)
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	var net map[string]any
	for _, it := range out["items"].([]any) {
		if n := it.(map[string]any)["network"].(map[string]any); n["name"] == "shop-net" {
			net = n
		}
	}
	if net == nil || net["kind"] != "tun" || len(net["members"].([]any)) != 2 || len(net["nodes"].([]any)) != 2 || net["apps"] == nil {
		t.Fatalf("shop-net %v", net)
	}
}
