// SPDX-License-Identifier: Apache-2.0

package tenancy

import (
	"crypto/ed25519"
	"errors"
	"net/netip"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
)

// bridgeFixture: first/services on node-a and node-b, first/edge and
// second/lan on node-a.
func bridgeFixture(t *testing.T) (fixture, Quotas) {
	t.Helper()
	f, q, d := logicalFixture(t)
	n, err := f.n.CreateTUN(f.c, q, "alice", 0, d)
	if err != nil {
		t.Fatal(err)
	}
	one := func(tenant, name, pool, tunnel string) {
		t.Helper()
		p := netip.MustParsePrefix(pool)
		def := TUNDefinition{Tenant: tenant, Name: name, Members: []TUNNode{{Node: "node-a", Owner: public(f.a), Pools: []Subnet{{ID: "pool", Prefix: p, Gateway: p.Addr().Next(), MTU: 1500}}}}}
		if n, err = n.CreateTUN(f.c, q, "admin", n.Revision(), def); err != nil {
			t.Fatal(name, err)
		}
	}
	one("first", "edge", "10.73.1.0/24", "10.74.0.1/32")
	one("second", "lan", "10.75.1.0/24", "10.76.0.1/32")
	f.n = n
	return f, q
}

func closure(f fixture, b VirtualBridge, node string, k ed25519.PrivateKey) BridgeClosure {
	p := BridgeClosure{Cluster: f.n.Cluster(), Owner: b.A.Tenant, ID: b.ID, Generation: b.Generation, Node: node, Key: public(k)}
	p.Signature = ed25519.Sign(k, BridgeClosureBytes(p))
	return p
}

func roundTrip(t *testing.T, n Networks) Networks {
	t.Helper()
	back, err := Decode(snapshotBytes(t, n))
	if err != nil {
		t.Fatal("decode", err)
	}
	return back
}

func TestBridgeInOneTenantOpensAtOnceAndClosesOnEveryServersReport(t *testing.T) {
	f, _ := bridgeFixture(t)
	services, edge := BridgeEnd{"first", "services"}, BridgeEnd{"first", "edge"}
	if _, err := f.n.CreateBridge(f.c, "bob", f.n.Revision(), VirtualBridge{ID: "link", A: services, B: edge}); !errors.Is(err, access.ErrDenied) {
		t.Fatalf("another tenant's manager: %v", err)
	}
	for name, bad := range map[string]VirtualBridge{
		"same network":  {ID: "link", A: services, B: services},
		"ports for all": {ID: "link", A: services, B: edge, Ports: []Ports{{80, 80}}},
		"bad direction": {ID: "link", A: services, B: edge, Direction: "sideways"},
		"no network":    {ID: "link", A: services, B: BridgeEnd{"first", "nothing"}},
		"system":        {ID: "link", A: services, B: BridgeEnd{"first", SystemNetwork}},
		"plain network": {ID: "link", A: services, B: BridgeEnd{"first", "unused"}},
	} {
		if _, err := f.n.CreateBridge(f.c, "alice", f.n.Revision(), bad); !errors.Is(err, ErrPolicy) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	n, err := f.n.CreateBridge(f.c, "alice", f.n.Revision(), VirtualBridge{ID: "link", A: services, B: edge, Protocol: 6, Ports: []Ports{{80, 80}, {8000, 8100}}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := n.Bridge("first", "link")
	if b.Phase != BridgeOpen || b.Direction != BridgeBoth || len(b.Approvals) != 1 || b.Approvals[0].User != "alice" {
		t.Fatalf("created: %+v", b)
	}
	n = roundTrip(t, n)
	if _, err = n.CreateBridge(f.c, "alice", n.Revision(), VirtualBridge{ID: "other", A: edge, B: services}); !errors.Is(err, ErrBridgeExists) {
		t.Fatalf("second bridge between the same networks: %v", err)
	}
	if _, err = n.CreateBridge(f.c, "alice", n.Revision(), VirtualBridge{ID: "link", A: services, B: BridgeEnd{"second", "lan"}}); !errors.Is(err, access.ErrConflict) {
		t.Fatalf("same name: %v", err)
	}
	// the last member of a bridged network does not leave
	v, _ := n.Network("first", logicalMemberID("first", "edge", "node-a"))
	if n, err = n.Drain(f.c, "alice", "first", v.ID, v.Revision); err != nil {
		t.Fatal(err)
	}
	v, _ = n.Network("first", v.ID)
	leave := NetworkClosure{Cluster: n.Cluster(), Tenant: "first", Network: v.ID, Node: v.Node, Owner: v.Owner, Generation: v.Generation, Revision: v.Revision, NativeGone: true}
	leave.Signature = ed25519.Sign(f.a, NetworkClosureBytes(leave))
	if _, err = n.Retire(f.c, "alice", leave); !errors.Is(err, ErrBridgeAttached) {
		t.Fatalf("leave with a bridge: %v", err)
	}

	if n, err = n.CloseBridge(f.c, "alice", "first", "first", "link", b.Revision); err != nil {
		t.Fatal(err)
	}
	b, _ = n.Bridge("first", "link")
	if b.Phase != BridgeClosing || !slicesEqual(n.BridgeServers(b), []string{"node-a", "node-b"}) {
		t.Fatalf("closing: %+v %v", b, n.BridgeServers(b))
	}
	if _, err = n.CloseBridge(f.c, "alice", "first", "first", "link", b.Revision); !errors.Is(err, access.ErrConflict) {
		t.Fatalf("closed twice: %v", err)
	}
	if _, err = n.ObserveBridgeClosed(closure(f, b, "node-a", f.b)); !errors.Is(err, ErrPolicy) {
		t.Fatalf("another server's key: %v", err)
	}
	if n, err = n.ObserveBridgeClosed(closure(f, b, "node-a", f.a)); err != nil {
		t.Fatal(err)
	}
	n = roundTrip(t, n)
	if _, err = n.ObserveBridgeClosed(closure(f, b, "node-a", f.a)); !errors.Is(err, access.ErrConflict) {
		t.Fatalf("repeated report: %v", err)
	}
	if n, err = n.ObserveBridgeClosed(closure(f, b, "node-b", f.b)); err != nil {
		t.Fatal(err)
	}
	if _, ok := n.Bridge("first", "link"); ok {
		t.Fatal("the bridge stayed after every server reported")
	}
	// the drained member now leaves
	if _, err = n.Retire(f.c, "alice", leave); err != nil {
		t.Fatal("leave after the bridge closed:", err)
	}
}

func TestBridgeAcrossTenantsNeedsTheOtherSidesApproval(t *testing.T) {
	f, _ := bridgeFixture(t)
	services, lan := BridgeEnd{"first", "services"}, BridgeEnd{"second", "lan"}
	if _, err := f.n.CreateBridge(f.c, "alice", f.n.Revision(), VirtualBridge{ID: "link", A: services, B: lan}); !errors.Is(err, ErrPeerClosed) {
		t.Fatalf("to a network that does not take bridges: %v", err)
	}
	// a missing network of another tenant reads the same as a closed one
	if _, err := f.n.CreateBridge(f.c, "alice", f.n.Revision(), VirtualBridge{ID: "link", A: services, B: BridgeEnd{"second", "nope"}}); !errors.Is(err, ErrPeerClosed) {
		t.Fatalf("to a missing network: %v", err)
	}
	n, err := f.n.SetToggle(f.c, "bob", f.n.Revision(), "second", "lan", ToggleBridgeInbound, true)
	if err != nil {
		t.Fatal(err)
	}
	if n, err = n.CreateBridge(f.c, "alice", n.Revision(), VirtualBridge{ID: "link", A: services, B: lan, Direction: BridgeAToB}); err != nil {
		t.Fatal(err)
	}
	b, _ := n.Bridge("first", "link")
	if b.Phase != BridgePending || len(b.Approvals) != 1 {
		t.Fatalf("pending: %+v", b)
	}
	n = roundTrip(t, n)
	if _, err = n.ApproveBridge(f.c, "alice", "first", "first", "link", b.Revision); !errors.Is(err, ErrPolicy) {
		t.Fatalf("A approved its own: %v", err)
	}
	if _, err = n.ApproveBridge(f.c, "alice", "second", "first", "link", b.Revision); !errors.Is(err, access.ErrDenied) {
		t.Fatalf("A approved for B: %v", err)
	}
	// B stops taking bridges: the pending one cannot be approved
	closed, err := n.SetToggle(f.c, "bob", n.Revision(), "second", "lan", ToggleBridgeInbound, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = closed.ApproveBridge(f.c, "bob", "second", "first", "link", b.Revision); !errors.Is(err, ErrPeerClosed) {
		t.Fatalf("approved while closed: %v", err)
	}
	// either side removes a pending bridge at once
	if gone, err := closed.CloseBridge(f.c, "bob", "second", "first", "link", b.Revision); err != nil {
		t.Fatal(err)
	} else if _, ok := gone.Bridge("first", "link"); ok {
		t.Fatal("a pending bridge stayed after close")
	}
	if n, err = n.ApproveBridge(f.c, "bob", "second", "first", "link", b.Revision); err != nil {
		t.Fatal(err)
	}
	b, _ = n.Bridge("first", "link")
	if b.Phase != BridgeOpen || len(b.Approvals) != 2 || b.Approvals[1].User != "bob" {
		t.Fatalf("open: %+v", b)
	}
	// turning it off keeps the open bridge
	if n, err = n.SetToggle(f.c, "bob", n.Revision(), "second", "lan", ToggleBridgeInbound, false); err != nil {
		t.Fatal(err)
	}
	n = roundTrip(t, n)
	if b, _ = n.Bridge("first", "link"); b.Phase != BridgeOpen {
		t.Fatalf("after off: %+v", b)
	}
	if got := n.VisibleBridges(f.c, "bob"); len(got) != 1 {
		t.Fatalf("B's manager does not see it: %+v", got)
	}
	if got := n.VisibleBridges(f.c, "eve"); len(got) != 0 {
		t.Fatalf("an outsider sees it: %+v", got)
	}
	if _, err = n.CloseBridge(f.c, "eve", "second", "first", "link", b.Revision); !errors.Is(err, access.ErrDenied) {
		t.Fatalf("an outsider closed it: %v", err)
	}
	if n, err = n.CloseBridge(f.c, "bob", "second", "first", "link", b.Revision); err != nil {
		t.Fatal(err)
	}
	b, _ = n.Bridge("first", "link")
	for _, node := range []string{"node-a", "node-b"} {
		k := f.a
		if node == "node-b" {
			k = f.b
		}
		if n, err = n.ObserveBridgeClosed(closure(f, b, node, k)); err != nil {
			t.Fatal(node, err)
		}
	}
	if len(n.AllBridges()) != 0 {
		t.Fatal("not removed")
	}
}

func TestBridgeRefusedWhileANetworkChanges(t *testing.T) {
	f, _ := bridgeFixture(t)
	v, _ := f.n.Network("first", logicalMemberID("first", "services", "node-b"))
	n, err := f.n.Drain(f.c, "alice", "first", v.ID, v.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = n.CreateBridge(f.c, "alice", n.Revision(), VirtualBridge{ID: "link", A: BridgeEnd{"first", "edge"}, B: BridgeEnd{"first", "services"}}); !errors.Is(err, ErrNetworkChanging) {
		t.Fatalf("while a member drains: %v", err)
	}
}

// A server that leaves while a bridge closes owes no report.
func TestClosingBridgeDoesNotWaitForALeavingServer(t *testing.T) {
	f, _ := bridgeFixture(t)
	n, err := f.n.CreateBridge(f.c, "alice", f.n.Revision(), VirtualBridge{ID: "link", A: BridgeEnd{"first", "services"}, B: BridgeEnd{"first", "edge"}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := n.Bridge("first", "link")
	if n, err = n.CloseBridge(f.c, "alice", "first", "first", "link", b.Revision); err != nil {
		t.Fatal(err)
	}
	b, _ = n.Bridge("first", "link")
	if n, err = n.ObserveBridgeClosed(closure(f, b, "node-a", f.a)); err != nil {
		t.Fatal(err)
	}
	v, _ := n.Network("first", logicalMemberID("first", "services", "node-b"))
	if n, err = n.Drain(f.c, "alice", "first", v.ID, v.Revision); err != nil {
		t.Fatal(err)
	}
	v, _ = n.Network("first", v.ID)
	leave := NetworkClosure{Cluster: n.Cluster(), Tenant: "first", Network: v.ID, Node: v.Node, Owner: v.Owner, Generation: v.Generation, Revision: v.Revision, NativeGone: true}
	leave.Signature = ed25519.Sign(f.b, NetworkClosureBytes(leave))
	if n, err = n.Retire(f.c, "alice", leave); err != nil {
		t.Fatal(err)
	}
	if len(n.AllBridges()) != 0 {
		t.Fatal("the bridge waits for a server that left")
	}
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
