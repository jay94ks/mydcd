// SPDX-License-Identifier: Apache-2.0

package app

import (
	"github.com/jay94ks/seafield/internal/observability"
	"github.com/jay94ks/seafield/internal/tenancy"
	"net/netip"
	"slices"
	"testing"
)

// These are explicit committed-view model inputs to the shared product core;
// no tunnel/transport success is inferred from this algorithm test.
func TestTunnelEventsProjectOnlyCurrentTenantLogicalMemberships(t *testing.T) {
	networks, err := tenancy.New([32]byte{22})
	if err != nil {
		t.Fatal(err)
	}
	networks = networks.WithServers(map[string]netip.Addr{"node-a": netip.MustParseAddr("10.254.240.1"), "node-b": netip.MustParseAddr("10.254.240.2")})
	var rows []tenancy.Network
	for group, tenant := range []string{"payments", "orders", "unpaired"} {
		nodes := []string{"node-a", "node-b"}
		if tenant == "unpaired" {
			nodes = nodes[:1]
		}
		for i, node := range nodes {
			identity := tenancy.SourceIdentity{Kind: "bridge", Tenant: tenant, Network: "services", Node: node}
			offset := group*2 + i
			address := netip.AddrFrom4([4]byte{10, 254, 240, byte(i + 1)})
			prefix := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 76, byte(offset), 0}), 24)
			rows = append(rows, tenancy.Network{Tenant: tenant, ID: identity.MemberID(), Logical: "services", Node: node, Owner: [32]byte{byte(i + 1)}, Generation: 1, Revision: 1, Pools: []tenancy.Subnet{{ID: "pool", Prefix: prefix, Gateway: prefix.Addr().Next(), MTU: 1280}}, TunnelAddresses: []netip.Prefix{netip.PrefixFrom(address, 32)}})
		}
	}
	// Every server is also a member of the system network, which has no
	// tenant: its outages must not become (invalid) tenant events.
	var system []tenancy.Network
	for i, node := range []string{"node-a", "node-b"} {
		identity := tenancy.SourceIdentity{Kind: "tun", Network: tenancy.SystemNetwork, Node: node}
		address := netip.AddrFrom4([4]byte{10, 254, 240, byte(i + 1)})
		prefix := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 77, byte(i), 0}), 24)
		system = append(system, tenancy.Network{ID: identity.MemberID(), Logical: tenancy.SystemNetwork, System: true, Node: node, Owner: [32]byte{byte(i + 1)}, Generation: 1, Revision: 1, Pools: []tenancy.Subnet{{ID: "pool", Prefix: prefix, Gateway: prefix.Addr().Next(), MTU: 1280}}, TunnelAddresses: []netip.Prefix{netip.PrefixFrom(address, 32)}})
	}
	networks, err = networks.WithCommittedNetworks(append(slices.Clone(rows), system...))
	if err != nil {
		t.Fatal("valid current membership projection", err)
	}
	current := observability.Report{Node: "node-a", Key: [32]byte{1}, At: 4000, Link: &observability.Link{ID: observability.PairID("node-a", "node-b"), Peer: "node-b", Outages: []observability.Outage{{StartedAt: 2000, EndedAt: 3000}}}}
	events := networkTunnelEvents(current, networks)
	if len(events) != 4 {
		t.Fatal("expected distinct pair facts for two tenants", events)
	}
	counts := map[string]int{}
	for _, row := range events {
		e := row.Event
		if !e.Valid() || e.Scope != "tenant" || e.Target.Network != "services" || e.Target.Tenant == "unpaired" || e.Target.PairID != current.Link.ID || e.Target.Node != "node-a" {
			t.Fatal("unrelated or unscoped event", row)
		}
		counts[e.Target.Tenant+"/"+e.Kind]++
		if e.Kind == "tunnel-down" && e.At != 2000 || e.Kind == "tunnel-up" && e.At != 3000 {
			t.Fatal("event replaced original outage time", e)
		}
	}
	for _, tenant := range []string{"payments", "orders"} {
		if counts[tenant+"/tunnel-down"] != 1 || counts[tenant+"/tunnel-up"] != 1 {
			t.Fatal("cross-tenant event collapse", counts)
		}
	}
	for _, mode := range []string{"bridge", "draining", "old-owner"} {
		changed := make([]tenancy.Network, len(rows))
		copy(changed, rows)
		for i := range changed {
			switch mode {
			case "bridge":
				changed[i].Logical = ""
				changed[i].ID = "bridge-" + changed[i].Node
				changed[i].TunnelAddresses = nil
			case "draining":
				changed[i].Draining = true
			case "old-owner":
				if changed[i].Node == current.Node {
					changed[i].Owner = [32]byte{99}
				}
			}
		}
		empty, err := tenancy.New([32]byte{22})
		if err != nil {
			t.Fatal(err)
		}
		filtered, err := empty.WithCommittedNetworks(changed)
		if err != nil {
			t.Fatal(mode, err)
		}
		if len(networkTunnelEvents(current, filtered)) != 0 {
			t.Fatal("non-current TUN membership fabricated outage", mode)
		}
	}
	current.Link.Peer = "node-c"
	if len(networkTunnelEvents(current, networks)) != 0 {
		t.Fatal("mismatched signed pair fabricated tenant outage")
	}
}
