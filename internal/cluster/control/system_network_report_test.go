// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"net/netip"
	"slices"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/tenancy"
)

func systemReport(t *testing.T, f *backupCoreFixture, k ed25519.PrivateKey, node, action string, on bool, expected uint64, closure *tenancy.NetworkClosure, want state.Code) {
	t.Helper()
	r := SystemNetworkReport{Schema: 1, Cluster: f.p.Cluster, Reporter: [32]byte(k.Public().(ed25519.PublicKey)), Node: node, Action: action, On: on, Expected: expected, Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(ResourcesKey).Revision, Closure: closure}
	r.Signature = ed25519.Sign(k, SystemNetworkReportBytes(r))
	cmd, err := r.Command()
	if err != nil {
		t.Fatal(err)
	}
	next, result, err := state.ApplyTransactional(f.s, f.s.Index()+1, cmd, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
	if err != nil || result.Code != want {
		t.Fatal(node, action, on, result, want, err)
	}
	f.s = next
}

func systemSource(kind, node string) string {
	return (tenancy.SourceIdentity{Kind: kind, Network: tenancy.SystemNetwork, Node: node}).Key()
}

// The system network follows the servers' own reports: the first server to
// run cluster apps creates it, the others join, and once none uses it every
// member drains and leaves on its own closure.
func TestSystemNetworkFollowsTheServersOwnReports(t *testing.T) {
	f, b, _ := managedDNSProjectionFixture(t)
	networks := func() tenancy.Networks {
		r, err := f.p.Resources(f.s)
		if err != nil {
			t.Fatal(err)
		}
		return r.Networks
	}
	// a server cannot report for another
	systemReport(t, f, b, "node-a", "use", true, networks().Revision(), nil, state.Forbidden)
	// joining before anyone uses it
	systemReport(t, f, b, "node-b", "join", false, networks().Revision(), nil, state.ConditionFailed)

	systemReport(t, f, f.node, "node-a", "use", true, networks().Revision(), nil, state.Applied)
	n := networks()
	if got := n.SystemPolicy().Users; !slices.Equal(got, []string{"node-a"}) {
		t.Fatal("users", got)
	}
	members := n.SystemMembers()
	if len(members) != 1 || members[0].Node != "node-a" || members[0].TunnelAddresses[0].String() != "10.254.240.1/32" || members[0].Pools[0].Prefix.String() != "10.254.1.0/24" {
		t.Fatalf("first member: %+v", members)
	}
	for _, kind := range []string{"bridge", "tun"} {
		if !f.s.Object(systemSource(kind, "node-a")).Present {
			t.Fatal("no source", kind)
		}
	}
	systemReport(t, f, f.node, "node-a", "use", true, networks().Revision(), nil, state.ConditionFailed)

	systemReport(t, f, b, "node-b", "join", false, networks().Revision(), nil, state.Applied)
	systemReport(t, f, b, "node-b", "join", false, networks().Revision(), nil, state.ConditionFailed)
	if members = networks().SystemMembers(); len(members) != 2 || members[1].Pools[0].Prefix.String() != "10.254.2.0/24" {
		t.Fatalf("members: %+v", members)
	}
	// nobody drains while a server still uses it
	systemReport(t, f, b, "node-b", "drain", false, members[1].Revision, nil, state.ConditionFailed)
	systemReport(t, f, f.node, "node-a", "use", false, networks().Revision(), nil, state.Applied)
	if users := networks().SystemPolicy().Users; len(users) != 0 {
		t.Fatal("users after off", users)
	}
	// A server that left the cluster without reporting off keeps its
	// record, but it does not hold the network: the members still drain.
	r, err := f.p.Resources(f.s)
	if err != nil {
		t.Fatal(err)
	}
	if r.Networks, err = r.Networks.SetSystemUse("node-gone", true); err != nil {
		t.Fatal(err)
	}
	writes, code := f.p.resourceCheckpoint(f.s, r)
	if code != state.Applied {
		t.Fatal(code)
	}
	if f.s, _, err = state.ApplyReduced(f.s, f.s.Index()+1, state.Command{Kind: state.Module, Actor: "anchor", Epoch: 1, RequestID: "stale-user", Key: ResourcesKey, Value: "fixture"}, nil, func(state.State, state.Command) (map[string][]byte, state.Code) { return writes, state.Applied }); err != nil {
		t.Fatal(err)
	}
	if got := f.p.SystemNetworkUsers(f.s, networks()); len(got) != 0 {
		t.Fatal("a removed server holds the network", got)
	}

	drain := func(k ed25519.PrivateKey, node string) tenancy.Network {
		t.Helper()
		for _, v := range networks().SystemMembers() {
			if v.Node == node {
				systemReport(t, f, k, node, "drain", false, v.Revision, nil, state.Applied)
				drained, _ := networks().Network("", v.ID)
				return drained
			}
		}
		t.Fatal("not a member", node)
		return tenancy.Network{}
	}
	leaveDrained := func(k ed25519.PrivateKey, m tenancy.Network) {
		t.Helper()
		p := tenancy.NetworkClosure{Cluster: f.p.Cluster, Network: m.ID, Node: m.Node, Owner: m.Owner, Generation: m.Generation, Revision: m.Revision, NativeGone: true}
		p.Signature = ed25519.Sign(b, tenancy.NetworkClosureBytes(p))
		if m.Node == "node-a" {
			// another server's signature is refused
			systemReport(t, f, k, m.Node, "leave", false, m.Revision, &p, state.ConditionFailed)
			p.Signature = ed25519.Sign(k, tenancy.NetworkClosureBytes(p))
		}
		systemReport(t, f, k, m.Node, "leave", false, m.Revision, &p, state.Applied)
		for _, kind := range []string{"bridge", "tun"} {
			if f.s.Object(systemSource(kind, m.Node)).Present {
				t.Fatal("source kept after leave", m.Node, kind)
			}
		}
	}
	leave := func(k ed25519.PrivateKey, node string) { t.Helper(); leaveDrained(k, drain(k, node)) }
	leave(b, "node-b")
	if members = networks().SystemMembers(); len(members) != 1 || members[0].Node != "node-a" {
		t.Fatalf("after node-b left: %+v", members)
	}
	// node-b uses it again after node-a drained: node-a still
	// leaves, and node-b then makes it anew
	drainedA := drain(f.node, "node-a")
	systemReport(t, f, b, "node-b", "use", true, networks().Revision(), nil, state.Applied)
	leaveDrained(f.node, drainedA)
	systemReport(t, f, b, "node-b", "join", false, networks().Revision(), nil, state.Applied)
	if members = networks().SystemMembers(); len(members) != 1 || members[0].Node != "node-b" || members[0].Pools[0].Prefix.String() != "10.254.1.0/24" {
		t.Fatalf("made anew: %+v", members)
	}
	systemReport(t, f, b, "node-b", "use", false, networks().Revision(), nil, state.Applied)
	leave(b, "node-b")
	if members = networks().SystemMembers(); len(members) != 0 {
		t.Fatalf("the network stayed: %+v", members)
	}
	// using it again creates it again at the same addresses
	systemReport(t, f, f.node, "node-a", "use", true, networks().Revision(), nil, state.Applied)
	if members = networks().SystemMembers(); len(members) != 1 || members[0].Pools[0].Prefix.String() != "10.254.1.0/24" {
		t.Fatalf("again: %+v", members)
	}
}

// A workspace network in the system range is refused with its own reason.
func TestWorkspaceNetworkInTheSystemRangeHasItsOwnRefusal(t *testing.T) {
	f, _, _ := managedDNSProjectionFixture(t)
	r, _ := f.p.Resources(f.s)
	bad := tenancy.TUNDefinition{Tenant: "tenant", Name: "edge", Members: []tenancy.TUNNode{{Node: "node-a", Pools: []tenancy.Subnet{{ID: "pool", Prefix: netip.MustParsePrefix("10.254.9.0/24"), Gateway: netip.MustParseAddr("10.254.9.1"), MTU: 1280}}}}}
	_, result := managedDNSChange(t, f, "edge-system", "create-tun-network", r.Networks.Revision(), bad, state.NetworkSystemRange)
	if result.Reason != "system-range-overlap" {
		t.Fatal(result)
	}
	// The tunnel address is the server's own, inside the system range.
	bad.Members[0].Pools[0].Prefix, bad.Members[0].Pools[0].Gateway = netip.MustParsePrefix("10.81.1.0/24"), netip.MustParseAddr("10.81.1.1")
	managedDNSChange(t, f, "edge-ok", "create-tun-network", r.Networks.Revision(), bad, state.Applied)
	r, _ = f.p.Resources(f.s)
	edge, _ := r.Networks.NamedNetwork("tenant", "edge", "node-a")
	services, _ := r.Networks.NamedNetwork("tenant", "services", "node-a")
	if a, _ := r.Networks.NodeAddress("node-a"); edge.TunnelAddresses[0] != netip.PrefixFrom(a, 32) || services.TunnelAddresses[0] != edge.TunnelAddresses[0] || !network.ServerBlock.Contains(a) {
		t.Fatalf("tunnel %v / %v, server %v", edge.TunnelAddresses, services.TunnelAddresses, a)
	}
}

// A system network member's own server gets the native permit for its
// bridge and TUN: no tenant applies, only the current membership and the
// server-wide limit. A drained member gets none.
func TestSystemNetworkMemberGetsItsNativePermit(t *testing.T) {
	f, _, _ := managedDNSProjectionFixture(t)
	r, _ := f.p.Resources(f.s)
	systemReport(t, f, f.node, "node-a", "use", true, r.Networks.Revision(), nil, state.Applied)
	owner := [32]byte(f.node.Public().(ed25519.PublicKey))
	permit := func(kind string) (NativePermit, error) {
		key := systemSource(kind, "node-a")
		o := f.s.Object(key)
		request := NativeRequest{}
		request.Source.Key, request.Source.Generation, request.Source.Revision = key, o.Generation, o.Revision
		return f.p.NativePermit(f.s, owner, request)
	}
	for kind, want := range map[string]string{"bridge": "bridge", "tun": "tunnel"} {
		p, err := permit(kind)
		if err != nil || p.Kind != want || p.Consumers == nil || !p.Consumers.Valid() || p.Consumers.Scope.Tenant != tenancy.SystemScope || p.MaxConsumers < 1 {
			t.Fatalf("%s permit: %+v %v", kind, p, err)
		}
	}
	r, _ = f.p.Resources(f.s)
	m := r.Networks.SystemMembers()[0]
	systemReport(t, f, f.node, "node-a", "use", false, r.Networks.Revision(), nil, state.Applied)
	systemReport(t, f, f.node, "node-a", "drain", false, m.Revision, nil, state.Applied)
	if _, err := permit("bridge"); err == nil {
		t.Fatal("a drained member got a permit")
	}
}

func runReport(t *testing.T, f *backupCoreFixture, k ed25519.PrivateKey, node string, expected uint64, want state.Code) {
	t.Helper()
	r := SystemNetworkReport{Schema: 1, Cluster: f.p.Cluster, Reporter: [32]byte(k.Public().(ed25519.PublicKey)), Node: node, Action: "run", App: "web", Expected: expected, Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(ResourcesKey).Revision}
	r.Signature = ed25519.Sign(k, SystemNetworkReportBytes(r))
	cmd, err := r.Command()
	if err != nil {
		t.Fatal(err)
	}
	next, result, err := state.ApplyTransactional(f.s, f.s.Index()+1, cmd, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
	if err != nil || result.Code != want {
		t.Fatal(node, result, want, err)
	}
	f.s = next
}

// One server in the cluster runs a cluster app: the first to claim it.
// Another server's claim is refused while the runner uses the network.
// Its address is the cluster-wide one, and the other members' TUN sources
// route it to the runner, in place, as the runner changes.
func TestClusterAppRunsOnOneServerInTheCluster(t *testing.T) {
	f, b, _ := managedDNSProjectionFixture(t)
	networks := func() tenancy.Networks {
		r, err := f.p.Resources(f.s)
		if err != nil {
			t.Fatal(err)
		}
		return r.Networks
	}
	users := func() []string { return f.p.SystemNetworkUsers(f.s, networks()) }
	systemReport(t, f, f.node, "node-a", "use", true, networks().Revision(), nil, state.Applied)
	systemReport(t, f, b, "node-b", "use", true, networks().Revision(), nil, state.Applied)
	systemReport(t, f, b, "node-b", "join", false, networks().Revision(), nil, state.Applied)
	runReport(t, f, b, "node-a", networks().Revision(), state.Forbidden)
	runReport(t, f, f.node, "node-a", networks().Revision()+1, state.ConditionFailed)
	runReport(t, f, f.node, "node-a", networks().Revision(), state.Applied)
	runReport(t, f, b, "node-b", networks().Revision(), state.ConditionFailed)
	cluster := netip.MustParsePrefix("10.254.0.2/32")
	routesTo := func(runner string) {
		t.Helper()
		if node, addr, ok := networks().ClusterAppAddress("web", users()); !ok || node != runner || addr != cluster.Addr() {
			t.Fatal("address", node, addr, ok)
		}
		rows, err := networks().TUNSources("", tenancy.SystemNetwork)
		if err != nil || len(rows) != 2 {
			t.Fatal(rows, err)
		}
		for _, row := range rows {
			stored, err := network.DecodeTunnel(f.s.Object(row.TunnelKey).Value)
			if err != nil || slices.Contains(stored.Routes, cluster) == (row.Network.Node == runner) {
				t.Fatalf("%s TUN routes %v (%v)", row.Network.Node, stored.Routes, err)
			}
		}
	}
	routesTo("node-a")
	if _, addr, ok := networks().ClusterAppPoolAddress("web", users()); !ok || addr != netip.MustParseAddr("10.254.1.2") {
		t.Fatal("pool address", addr, ok)
	}
	// node-a stops running cluster apps: node-b may run it
	systemReport(t, f, f.node, "node-a", "use", false, networks().Revision(), nil, state.Applied)
	runReport(t, f, b, "node-b", networks().Revision(), state.Applied)
	routesTo("node-b")
}
