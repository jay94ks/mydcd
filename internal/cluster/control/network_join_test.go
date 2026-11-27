// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"net/netip"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/tenancy"
)

func TestJoinTUNNetworkAddsAServerWithoutRewritingTheOthers(t *testing.T) {
	f, _, _ := managedDNSProjectionFixture(t)
	pool := func(prefix, gateway string) []tenancy.Subnet {
		return []tenancy.Subnet{{ID: "pool", Prefix: netip.MustParsePrefix(prefix), Gateway: netip.MustParseAddr(gateway), MTU: 1280}}
	}
	lone := tenancy.TUNDefinition{Tenant: "tenant", Name: "edge", Members: []tenancy.TUNNode{{Node: "node-a", Pools: pool("10.81.1.0/24", "10.81.1.1")}}}
	resources, _ := f.p.Resources(f.s)
	managedDNSChange(t, f, "edge-create", "create-tun-network", resources.Networks.Revision(), lone, state.Applied)
	bridgeA := (tenancy.SourceIdentity{Kind: "bridge", Tenant: "tenant", Network: "edge", Node: "node-a"}).Key()
	before := f.s.Objects(tenancy.ManagedNetworkSourcePrefix)
	resources, _ = f.p.Resources(f.s)
	join := NetworkJoin{Tenant: "tenant", Name: "edge", Member: tenancy.TUNNode{Node: "node-b", Pools: pool("10.81.2.0/24", "10.81.2.1")}}
	managedDNSChange(t, f, "edge-join", "join-tun-network", resources.Networks.Revision(), join, state.Applied)
	tunA := (tenancy.SourceIdentity{Kind: "tun", Tenant: "tenant", Network: "edge", Node: "node-a"}).Key()
	for key, old := range before {
		now := f.s.Object(key)
		if key == tunA {
			// The lone member's TUN gets the joiner's routes in place.
			if now.Generation != old.Generation || now.Revision <= old.Revision || !now.Present {
				t.Fatal("the existing TUN was replaced instead of rewritten", now, old)
			}
			continue
		}
		if now != old {
			t.Fatal("an existing source was rewritten", key)
		}
	}
	if !before[bridgeA].Present || !before[tunA].Present {
		t.Fatal("fixture has no lone bridge and TUN")
	}
	for _, s := range []tenancy.SourceIdentity{{Kind: "bridge", Node: "node-b"}, {Kind: "tun", Node: "node-a"}, {Kind: "tun", Node: "node-b"}} {
		s.Tenant, s.Network = "tenant", "edge"
		if !f.s.Object(s.Key()).Present {
			t.Fatal("missing source after join", s.Key())
		}
	}
	resources, _ = f.p.Resources(f.s)
	managedDNSChange(t, f, "edge-join-again", "join-tun-network", resources.Networks.Revision(), join, state.ConditionFailed)
}

func TestLeaveTUNNetworkRemovesOneServerAndRewritesOnlyTheOthersRoutes(t *testing.T) {
	f, b, _ := managedDNSProjectionFixture(t)
	pool := func(prefix, gateway string) []tenancy.Subnet {
		return []tenancy.Subnet{{ID: "pool", Prefix: netip.MustParsePrefix(prefix), Gateway: netip.MustParseAddr(gateway), MTU: 1280}}
	}
	lone := tenancy.TUNDefinition{Tenant: "tenant", Name: "edge", Members: []tenancy.TUNNode{{Node: "node-a", Pools: pool("10.81.1.0/24", "10.81.1.1")}}}
	r, _ := f.p.Resources(f.s)
	managedDNSChange(t, f, "edge-create", "create-tun-network", r.Networks.Revision(), lone, state.Applied)
	r, _ = f.p.Resources(f.s)
	managedDNSChange(t, f, "edge-join", "join-tun-network", r.Networks.Revision(), NetworkJoin{Tenant: "tenant", Name: "edge", Member: tenancy.TUNNode{Node: "node-b", Pools: pool("10.81.2.0/24", "10.81.2.1")}}, state.Applied)
	key := func(kind, node string) string {
		return (tenancy.SourceIdentity{Kind: kind, Tenant: "tenant", Network: "edge", Node: node}).Key()
	}
	bridgeA, tunA := f.s.Object(key("bridge", "node-a")), f.s.Object(key("tun", "node-a"))
	r, _ = f.p.Resources(f.s)
	leaving, _ := r.Networks.NamedNetwork("tenant", "edge", "node-b")
	managedDNSChange(t, f, "edge-drain-b", "drain-network", leaving.Revision, NetworkSelection{Tenant: "tenant", ID: leaving.ID}, state.Applied)
	r, _ = f.p.Resources(f.s)
	if _, ok := r.Networks.NamedNetwork("tenant", "edge", "node-a"); !ok {
		t.Fatal("a member leaving closed admission on the other server")
	}
	drained, _ := r.Networks.Network("tenant", leaving.ID)
	closure := tenancy.NetworkClosure{Cluster: f.p.Cluster, Tenant: "tenant", Network: leaving.ID, Node: "node-b", Owner: leaving.Owner, Generation: leaving.Generation, Revision: drained.Revision, NativeGone: true}
	closure.Signature = ed25519.Sign(b, tenancy.NetworkClosureBytes(closure))
	managedDNSChange(t, f, "edge-leave-b", "leave-tun-network", drained.Revision, closure, state.Applied)
	if f.s.Object(key("bridge", "node-a")) != bridgeA {
		t.Fatal("the staying member's bridge was rewritten")
	}
	now := f.s.Object(key("tun", "node-a"))
	if !now.Present || now.Generation != tunA.Generation || now.Revision <= tunA.Revision {
		t.Fatal("the staying member's TUN was replaced instead of rewritten in place")
	}
	view, err := f.p.ProjectResources(f.s)
	if err != nil {
		t.Fatal(err)
	}
	edge := 0
	for _, n := range view.Resources.Networks.AllNetworks() {
		if n.Logical == "edge" {
			edge++
		}
	}
	if edge != 1 {
		t.Fatal("edge members after leave", edge)
	}
	for _, kind := range []string{"bridge", "tun"} {
		source, found := view.ManagedSources[key(kind, "node-b")]
		if !found || source.Closed == nil || f.s.Object(key(kind, "node-b")).Present {
			t.Fatal("the leaving member's source is not a closed archive", kind)
		}
	}
	if tun := view.ManagedSources[key("tun", "node-a")].Tunnel; tun == nil || len(tun.Routes) != 0 {
		t.Fatal("the staying member kept routes to the server that left")
	}
}

// set-network-toggle changes only the network data: a local network refuses
// a join until the toggle is off, and no native source is rewritten.
func TestSetNetworkToggleGatesJoinWithoutTouchingSources(t *testing.T) {
	f, _, _ := managedDNSProjectionFixture(t)
	pool := func(prefix, gateway string) []tenancy.Subnet {
		return []tenancy.Subnet{{ID: "pool", Prefix: netip.MustParsePrefix(prefix), Gateway: netip.MustParseAddr(gateway), MTU: 1280}}
	}
	lone := tenancy.TUNDefinition{Tenant: "tenant", Name: "edge", Toggles: []tenancy.NetworkToggle{tenancy.ToggleLocal}, Members: []tenancy.TUNNode{{Node: "node-a", Pools: pool("10.81.1.0/24", "10.81.1.1")}}}
	r, _ := f.p.Resources(f.s)
	managedDNSChange(t, f, "edge-create", "create-tun-network", r.Networks.Revision(), lone, state.Applied)
	join := NetworkJoin{Tenant: "tenant", Name: "edge", Member: tenancy.TUNNode{Node: "node-b", Pools: pool("10.81.2.0/24", "10.81.2.1")}}
	r, _ = f.p.Resources(f.s)
	managedDNSChange(t, f, "edge-join-local", "join-tun-network", r.Networks.Revision(), join, state.ConditionFailed)
	before := f.s.Objects(tenancy.ManagedNetworkSourcePrefix)
	r, _ = f.p.Resources(f.s)
	managedDNSChange(t, f, "edge-cross", "set-network-toggle", r.Networks.Revision(), NetworkToggleSet{Tenant: "tenant", Name: "edge", Toggle: tenancy.ToggleLocal}, state.Applied)
	for key, old := range before {
		if f.s.Object(key) != old {
			t.Fatal("the toggle rewrote a native source", key)
		}
	}
	r, _ = f.p.Resources(f.s)
	managedDNSChange(t, f, "edge-join", "join-tun-network", r.Networks.Revision(), join, state.Applied)
	r, _ = f.p.Resources(f.s)
	managedDNSChange(t, f, "edge-local-two", "set-network-toggle", r.Networks.Revision(), NetworkToggleSet{Tenant: "tenant", Name: "edge", Toggle: tenancy.ToggleLocal, On: true}, state.ConditionFailed)
}

func TestLeaveTUNNetworkOfTheLastServerDeletesTheNetwork(t *testing.T) {
	f, _, _ := managedDNSProjectionFixture(t)
	lone := tenancy.TUNDefinition{Tenant: "tenant", Name: "edge", Members: []tenancy.TUNNode{{Node: "node-a", Pools: []tenancy.Subnet{{ID: "pool", Prefix: netip.MustParsePrefix("10.81.1.0/24"), Gateway: netip.MustParseAddr("10.81.1.1"), MTU: 1280}}}}}
	r, _ := f.p.Resources(f.s)
	managedDNSChange(t, f, "edge-create", "create-tun-network", r.Networks.Revision(), lone, state.Applied)
	r, _ = f.p.Resources(f.s)
	m, _ := r.Networks.NamedNetwork("tenant", "edge", "node-a")
	managedDNSChange(t, f, "edge-drain", "drain-network", m.Revision, NetworkSelection{Tenant: "tenant", ID: m.ID}, state.Applied)
	r, _ = f.p.Resources(f.s)
	drained, _ := r.Networks.Network("tenant", m.ID)
	closure := tenancy.NetworkClosure{Cluster: f.p.Cluster, Tenant: "tenant", Network: m.ID, Node: "node-a", Owner: m.Owner, Generation: m.Generation, Revision: drained.Revision, NativeGone: true}
	closure.Signature = ed25519.Sign(f.node, tenancy.NetworkClosureBytes(closure))
	managedDNSChange(t, f, "edge-leave", "leave-tun-network", drained.Revision, closure, state.Applied)
	r, _ = f.p.Resources(f.s)
	if _, ok := r.Networks.Network("tenant", m.ID); ok {
		t.Fatal("the network stayed after its last server left")
	}
	for _, kind := range []string{"bridge", "tun"} {
		if f.s.Object((tenancy.SourceIdentity{Kind: kind, Tenant: "tenant", Network: "edge", Node: "node-a"}).Key()).Present {
			t.Fatal("source kept after the last server left", kind)
		}
	}
	// The same addresses are free again.
	managedDNSChange(t, f, "edge-again", "create-tun-network", r.Networks.Revision(), lone, state.Applied)
}
