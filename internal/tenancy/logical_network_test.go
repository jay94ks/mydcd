// SPDX-License-Identifier: Apache-2.0

package tenancy

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"slices"
	"testing"

	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/workload"
)

func logicalFixture(t *testing.T) (fixture, Quotas, TUNDefinition) {
	t.Helper()
	f := newFixture(t)
	q, _ := NewQuotas(f.n.Cluster())
	for _, scope := range []string{"", "first", "second", "third"} {
		for _, node := range []string{"node-a", "node-b"} {
			owner := public(f.a)
			if node == "node-b" {
				owner = public(f.b)
			}
			var err error
			q, err = q.Set(f.c, "admin", 0, NodeLimit{Tenant: scope, Node: node, Owner: owner, Capacity: workload.Resources{CPU: 8, Memory: 80}, Networks: 4, MaxConsumers: 4, PacketQueuePackets: 4, PacketQueueBytes: 8192}, f.n)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	d := TUNDefinition{Tenant: "first", Name: "services", Members: []TUNNode{
		{Node: "node-a", Owner: public(f.a), Pools: definition("first", "unused", "node-a", "10.71.1.0/24", f.a).Pools},
		{Node: "node-b", Owner: public(f.b), Pools: definition("first", "unused", "node-b", "10.71.2.0/24", f.b).Pools},
	}}
	return f, q, d
}

func copyTUN(d TUNDefinition) TUNDefinition {
	raw, _ := json.Marshal(d)
	var out TUNDefinition
	_ = json.Unmarshal(raw, &out)
	return out
}

func TestManagedGatewayProjectionKeepsLegacyBytesAndRequiresExplicitMode(t *testing.T) {
	f, quotas, definition := logicalFixture(t)
	legacy, err := f.n.CreateTUN(f.c, quotas, "alice", 0, definition)
	if err != nil {
		t.Fatal(err)
	}
	before := snapshotBytes(t, legacy)
	restored, err := Decode(before)
	if err != nil || !bytes.Equal(before, snapshotBytes(t, restored)) {
		t.Fatal("old network metadata rewritten on decode", err)
	}
	old, err := restored.TUNSources(definition.Tenant, definition.Name)
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range old {
		if !source.Bridge.Internal || source.Bridge.GatewayMode != "" || source.Network.GatewayMode != "" {
			t.Fatal("legacy native mode changed without explicit management transition")
		}
		raw, _ := json.Marshal(source.Bridge)
		if bytes.Contains(raw, []byte("GatewayMode")) {
			t.Fatal("legacy Bridge signature bytes changed")
		}
	}
	definition.GatewayMode = network.ManagedGatewayMode
	managed, err := f.n.CreateTUN(f.c, quotas, "alice", 0, definition)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := managed.TUNSources(definition.Tenant, definition.Name)
	if err != nil || len(rows) != len(old) {
		t.Fatal(err)
	}
	for _, source := range rows {
		if source.Bridge.Internal || source.Bridge.GatewayMode != network.ManagedGatewayMode || source.Network.GatewayMode != network.ManagedGatewayMode {
			t.Fatal("explicit managed mode not retained in native projection")
		}
	}
	original := rows[0].Network
	target := original
	target.Generation, target.Revision, target.PendingChange = 0, 0, 0
	target.GatewayMode = "" // An ordinary CIDR/gateway edit must not downgrade it.
	planned, err := managed.PlanMetadataChange(f.c, "alice", original.Tenant, original.ID, "preserve-mode", original.Revision, target)
	if err != nil {
		t.Fatal(err)
	}
	change, found := planned.Change(original.Tenant, original.ID)
	if !found || change.Target.GatewayMode != network.ManagedGatewayMode || change.Original.GatewayMode != network.ManagedGatewayMode {
		t.Fatal("omitted mode silently downgraded original native target")
	}
	replayed, err := planned.PlanMetadataChange(f.c, "alice", original.Tenant, original.ID, "preserve-mode", original.Revision, target)
	if err != nil || !bytes.Equal(snapshotBytes(t, planned), snapshotBytes(t, replayed)) {
		t.Fatal("same original mode/target was rebound on replay", err)
	}
	definition.GatewayMode = "routed"
	if _, err := f.n.CreateTUN(f.c, quotas, "alice", 0, definition); err == nil || !bytes.Equal(before, snapshotBytes(t, legacy)) {
		t.Fatal("unapproved mode accepted or original state changed")
	}
}

func TestP0LogicalNetworkAtomicDeterministicReservationAndNativeProjection(t *testing.T) {
	f, q, d := logicalFixture(t)
	before := snapshotBytes(t, f.n)
	next, err := f.n.CreateTUN(f.c, q, "alice", 0, d)
	if err != nil {
		t.Fatal(err)
	}
	if next.Revision() != 1 || len(next.AllNetworks()) != 2 || !bytes.Equal(snapshotBytes(t, f.n), before) || q.ValidateNetworks(next) != nil {
		t.Fatal("not one atomic network reservation")
	}
	reversed := copyTUN(d)
	slices.Reverse(reversed.Members)
	same, err := f.n.CreateTUN(f.c, q, "alice", 0, reversed)
	if err != nil || !bytes.Equal(snapshotBytes(t, same), snapshotBytes(t, next)) {
		t.Fatal("member input order changes the shared state", err)
	}
	decoded, err := Decode(snapshotBytes(t, next))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := decoded.TUNSources("first", "services")
	if err != nil || len(rows) != 2 {
		t.Fatal("native projection", err)
	}
	topology := network.TunnelTopology{Tunnels: map[string]network.TunnelSpec{}}
	for _, row := range rows {
		v, ok := decoded.NamedNetwork("first", "services", row.Network.Node)
		if !ok || v.ID != row.Network.ID || v.Generation != 1 || row.Tunnel == nil || len(row.Tunnel.Routes) != 2 || row.Bridge.Network == row.Tunnel.Network {
			t.Fatal("logical/native/node identity lost")
		}
		topology.Tunnels[row.TunnelKey] = *row.Tunnel
		for _, p := range row.Bridge.Pools {
			topology.Pools = append(topology.Pools, network.RoutePool{Network: row.Tunnel.Network, Owner: row.Bridge.Owner, Prefix: p.Prefix})
		}
	}
	for _, row := range rows {
		peers, err := topology.Peers(row.TunnelKey)
		if err != nil || len(peers) != 1 {
			t.Fatal("existing routing algorithm cannot consume the projection", err)
		}
	}
	// Every returned view owns its slices, including new tunnel metadata.
	v, _ := next.NamedNetwork("first", "services", "node-a")
	v.TunnelAddresses[0] = netip.MustParsePrefix("10.99.0.1/32")
	v.Pools[0].MTU = 1400
	rows[0].Network.TunnelAddresses[0] = v.TunnelAddresses[0]
	if !bytes.Equal(snapshotBytes(t, next), snapshotBytes(t, decoded)) {
		t.Fatal("returned view mutates shared state")
	}
	if _, ok := next.NamedNetwork("second", "services", "node-a"); ok {
		t.Fatal("cross-tenant name fallback")
	}
	if _, ok := next.NamedNetwork("first", "services", "node-c"); ok {
		t.Fatal("node fallback")
	}
	if _, err := next.CreateTUN(f.c, q, "alice", 0, d); err == nil {
		t.Fatal("stale CAS accepted")
	}
	if _, err := next.CreateTUN(f.c, q, "alice", 1, d); err == nil {
		t.Fatal("same logical name recreated")
	}
	member, _ := next.NamedNetwork("first", "services", "node-b")
	draining, err := next.Drain(f.c, "alice", "first", member.ID, member.Revision)
	if err != nil {
		t.Fatal(err)
	}
	// A member leaving on its own closes admission only on its server.
	if _, ok := draining.NamedNetwork("first", "services", "node-b"); ok {
		t.Fatal("new admission through a draining member")
	}
	if _, ok := draining.NamedNetwork("first", "services", "node-a"); !ok {
		t.Fatal("a draining member closed admission on another server")
	}
	if len(draining.AllNetworks()) != 2 {
		t.Fatal("drain erased original ownership")
	}
}

func TestP0LogicalNetworkRejectsCounterexamplesWithoutPartialReservation(t *testing.T) {
	f, q, d := logicalFixture(t)
	before := snapshotBytes(t, f.n)
	cases := map[string]func(*TUNDefinition){
		"duplicate-node":  func(v *TUNDefinition) { v.Members[1].Node = "node-a" },
		"duplicate-owner": func(v *TUNDefinition) { v.Members[1].Owner = v.Members[0].Owner },
		"unknown-node":    func(v *TUNDefinition) { v.Members[1].Node = "node-c" },
		"missing-owner":   func(v *TUNDefinition) { v.Members[1].Owner = [32]byte{} },
		"cross-node-cidr": func(v *TUNDefinition) { v.Members[1].Pools = slices.Clone(v.Members[0].Pools) },
		"named-tunnel":    func(v *TUNDefinition) { v.Members[0].Addresses = []netip.Prefix{netip.MustParsePrefix("10.72.0.1/32")} },
		"other-server-tunnel": func(v *TUNDefinition) {
			v.Members[0].Addresses = []netip.Prefix{netip.MustParsePrefix("10.254.0.2/32")}
		},
		"mtu-disagreement": func(v *TUNDefinition) { v.Members[1].Pools[0].MTU = 1400 },
		"empty-members":    func(v *TUNDefinition) { v.Members = nil },
		"empty-pool":       func(v *TUNDefinition) { v.Members[1].Pools = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			bad := copyTUN(d)
			mutate(&bad)
			candidate, err := f.n.CreateTUN(f.c, q, "alice", 0, bad)
			if err == nil || !bytes.Equal(snapshotBytes(t, candidate), before) || !bytes.Equal(snapshotBytes(t, f.n), before) {
				t.Fatal("bad member left a partial reservation", err)
			}
		})
	}
	if _, err := f.n.CreateTUN(f.c, q, "bob", 0, d); err == nil {
		t.Fatal("other tenant manager admitted")
	}
	// The second member lacks its limit: the first member must not escape.
	q0, _ := NewQuotas(f.n.Cluster())
	for _, scope := range []string{"", "first"} {
		var err error
		q0, err = q0.Set(f.c, "admin", 0, NodeLimit{Tenant: scope, Node: "node-a", Owner: public(f.a), Networks: 1, Capacity: workload.Resources{CPU: 1, Memory: 1}}, f.n)
		if err != nil {
			t.Fatal(err)
		}
	}
	if rejected, err := f.n.CreateTUN(f.c, q0, "alice", 0, d); err == nil || !bytes.Equal(snapshotBytes(t, rejected), before) {
		t.Fatal("second-member quota failure partially committed")
	}
}

func TestP0LogicalNetworkGlobalHostReservationAndLegacyBytes(t *testing.T) {
	f, q, d := logicalFixture(t)
	legacy := create(t, f, definition("second", "plain", "node-a", "10.80.0.0/24", f.a)).n
	raw := snapshotBytes(t, legacy)
	if bytes.Contains(raw, []byte("Logical")) || bytes.Contains(raw, []byte("TunnelAddresses")) {
		t.Fatal("old schema1 bytes changed by empty new fields")
	}
	if decoded, err := Decode(raw); err != nil || !bytes.Equal(raw, snapshotBytes(t, decoded)) {
		t.Fatal("old snapshot no longer canonical", err)
	}
	next, err := legacy.CreateTUN(f.c, q, "alice", legacy.Revision(), d)
	if err != nil {
		t.Fatal(err)
	}
	for _, cidr := range []string{"10.254.240.0/24", "10.71.1.0/24"} {
		if _, err := next.Create(f.c, "admin", next.Revision(), definition("third", "overlap", "node-a", cidr, f.a)); err == nil {
			t.Fatal("later plain network reused a reserved host/pool", cidr)
		}
	}
	if _, err := next.Create(f.c, "admin", next.Revision(), definition("first", "services", "node-a", "10.81.0.0/24", f.a)); err == nil {
		t.Fatal("plain name masks logical network")
	}
	single := copyTUN(d)
	single.Name = "single"
	single.Members = single.Members[:1]
	standalone, err := f.n.CreateTUN(f.c, q, "alice", 0, single)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := standalone.TUNSources("first", "single")
	// A lone member has its TUN with no routes: a later join or leave only
	// rewrites route sets in place.
	if err != nil || len(rows) != 1 || rows[0].Tunnel == nil || rows[0].TunnelKey == "" || len(rows[0].Tunnel.Routes) != 0 {
		t.Fatal("single-node network fabricated a remote route", err)
	}
}
