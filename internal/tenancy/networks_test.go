// SPDX-License-Identifier: Apache-2.0

package tenancy

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
)

type fixture struct {
	c    access.Catalog
	n    Networks
	a, b ed25519.PrivateKey
}

func private(v byte) ed25519.PrivateKey {
	seed := make([]byte, 32)
	seed[0] = v
	return ed25519.NewKeyFromSeed(seed)
}
func public(k ed25519.PrivateKey) [32]byte { return [32]byte(k.Public().(ed25519.PublicKey)) }
func account(id string, admin bool) access.User {
	return access.User{ID: id, Username: id, Enabled: true, SystemAdmin: admin, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: public(private(id[0])), Enabled: true}}}
}
func newFixture(t *testing.T) fixture {
	t.Helper()
	a, b := private(1), private(2)
	c, err := access.New(public(a))
	if err != nil {
		t.Fatal(err)
	}
	c, err = c.Enroll(public(a), account("admin", true))
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"alice", "bob", "eve"} {
		c, err = c.PutUser("admin", 0, account(id, false))
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"first", "second", "third"} {
		c, err = c.CreateTenant("admin", id, 0)
		if err != nil {
			t.Fatal(err)
		}
		v, _ := c.Tenant(id)
		c, err = c.SetNodes("admin", id, v.Revision, []string{"node-a", "node-b"})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, m := range []access.Membership{{Tenant: "first", User: "alice", Role: access.Manager, Enabled: true}, {Tenant: "second", User: "bob", Role: access.Manager, Enabled: true}} {
		c, err = c.SetMembership("admin", 0, m)
		if err != nil {
			t.Fatal(err)
		}
	}
	n, err := New([32]byte{9})
	if err != nil {
		t.Fatal(err)
	}
	return fixture{c, n, a, b}
}
func definition(tenant, id, node, cidr string, k ed25519.PrivateKey) Network {
	p := netip.MustParsePrefix(cidr)
	return Network{Tenant: tenant, ID: id, Node: node, Owner: public(k), Pools: []Subnet{{ID: "pool", Prefix: p, Gateway: p.Addr().Next(), MTU: 1500}}}
}
func create(t *testing.T, f fixture, v Network) fixture {
	t.Helper()
	n, err := f.n.Create(f.c, "admin", f.n.Revision(), v)
	if err != nil {
		t.Fatal(err)
	}
	f.n = n
	return f
}
func two(t *testing.T) fixture {
	t.Helper()
	f := newFixture(t)
	f = create(t, f, definition("first", "lan", "node-a", "10.1.0.0/24", f.a))
	return create(t, f, definition("second", "lan", "node-b", "10.2.0.0/24", f.b))
}
func snapshotBytes(t *testing.T, n Networks) []byte {
	t.Helper()
	b, err := n.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func routeDefinition(t *testing.T, n Networks) Route {
	t.Helper()
	a, err := n.Bind("first", "lan", netip.MustParsePrefix("10.1.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := n.Bind("second", "lan", netip.MustParsePrefix("10.2.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	return Route{ID: "sql", Source: a, Destination: b, Protocol: 6, Ports: []Ports{{3306, 3306}}}
}
func propose(t *testing.T, f fixture) fixture {
	t.Helper()
	n, err := f.n.Propose(f.c, "alice", f.n.Revision(), routeDefinition(t, f.n))
	if err != nil {
		t.Fatal(err)
	}
	f.n = n
	return f
}
func approve(t *testing.T, f fixture, actor, side string) fixture {
	t.Helper()
	r, _ := f.n.Route("first", "sql")
	n, err := f.n.Approve(f.c, actor, "first", "sql", side, r.Revision)
	if err != nil {
		t.Fatal(err)
	}
	f.n = n
	return f
}
func active(t *testing.T) fixture {
	return approve(t, approve(t, propose(t, two(t)), "alice", "first"), "bob", "second")
}
func allows(f fixture) bool {
	return f.n.AllowsNewFlow(f.c, "first", "sql", netip.MustParseAddr("10.1.0.10"), netip.MustParseAddr("10.2.0.10"), 6, 3306)
}
func withdraw(t *testing.T, f fixture) fixture {
	t.Helper()
	r, _ := f.n.Route("first", "sql")
	n, err := f.n.Withdraw(f.c, "bob", "first", "sql", "second", r.Revision)
	if err != nil {
		t.Fatal(err)
	}
	f.n = n
	return f
}
func routeProof(f fixture, side string) RouteClosure {
	r, _ := f.n.Route("first", "sql")
	b, k := r.Source, f.a
	if side == r.Destination.Tenant {
		b, k = r.Destination, f.b
	}
	p := RouteClosure{Cluster: f.n.cluster, SourceTenant: "first", Route: r.ID, Tenant: side, Node: b.Node, Owner: b.Owner, Generation: r.Generation, Revision: r.Revision, NativeGone: true}
	p.Signature = ed25519.Sign(k, RouteClosureBytes(p))
	return p
}
func networkProof(f fixture, tenant string) NetworkClosure {
	v, _ := f.n.Network(tenant, "lan")
	k := f.a
	if tenant == "second" {
		k = f.b
	}
	p := NetworkClosure{Cluster: f.n.cluster, Tenant: tenant, Network: v.ID, Node: v.Node, Owner: v.Owner, Generation: v.Generation, Revision: v.Revision, NativeGone: true}
	p.Signature = ed25519.Sign(k, NetworkClosureBytes(p))
	return p
}

func TestGlobalCIDRAtomicCompetitionAndDualStack(t *testing.T) {
	f := two(t)
	before := snapshotBytes(t, f.n)
	for _, cidr := range []string{"10.1.0.0/24", "10.1.0.128/25", "10.0.0.0/8"} {
		v := definition("third", "other", "node-b", cidr, f.b)
		n, err := f.n.Create(f.c, "admin", f.n.Revision(), v)
		if err == nil || !bytes.Equal(before, snapshotBytes(t, n)) {
			t.Fatalf("overlap %s changed state", cidr)
		}
	}
	v := definition("third", "other", "node-b", "10.3.0.0/24", f.b)
	v.Pools = append(v.Pools, Subnet{ID: "z-conflict", Prefix: netip.MustParsePrefix("10.2.0.0/25"), Gateway: netip.MustParseAddr("10.2.0.1"), MTU: 1500})
	n, err := f.n.Create(f.c, "admin", f.n.Revision(), v)
	if err == nil || !bytes.Equal(before, snapshotBytes(t, n)) {
		t.Fatal("partial pool commit")
	}
	f = create(t, f, definition("first", "v6", "node-a", "fd00:1::/64", f.a))
	v = definition("second", "v6", "node-b", "fd00:1::/80", f.b)
	if _, err = f.n.Create(f.c, "admin", f.n.Revision(), v); err == nil {
		t.Fatal("IPv6 overlap")
	}
	if _, err = f.n.Create(f.c, "admin", 0, definition("third", "fresh", "node-b", "10.4.0.0/24", f.b)); err != access.ErrConflict {
		t.Fatal("stale CAS", err)
	}
}
func TestNetworkOwnershipFiltersAndImmutableValues(t *testing.T) {
	f := two(t)
	v := definition("second", "other", "node-b", "10.3.0.0/24", f.b)
	if _, err := f.n.Create(f.c, "alice", f.n.Revision(), v); err != access.ErrDenied {
		t.Fatal("other tenant creation", err)
	}
	v.Tenant = "first"
	v.Node = "forbidden"
	if _, err := f.n.Create(f.c, "alice", f.n.Revision(), v); err != access.ErrDenied {
		t.Fatal("ungranted node", err)
	}
	if len(f.n.VisibleNetworks(f.c, "alice")) != 1 || len(f.n.VisibleNetworks(f.c, "admin")) != 2 || len(f.n.VisibleNetworks(f.c, "eve")) != 0 {
		t.Fatal("network view leaked")
	}
	old := snapshotBytes(t, f.n)
	got, _ := f.n.Network("first", "lan")
	got.Pools[0].MTU = 2
	view := f.n.VisibleNetworks(f.c, "alice")
	view[0].Pools[0].ID = "evil"
	if !bytes.Equal(old, snapshotBytes(t, f.n)) {
		t.Fatal("getter alias")
	}
}
func TestDrainReservesCIDRUntilOriginalOwnerClosure(t *testing.T) {
	f := two(t)
	v, _ := f.n.Network("first", "lan")
	n, err := f.n.Drain(f.c, "alice", "first", "lan", v.Revision)
	if err != nil {
		t.Fatal(err)
	}
	f.n = n
	plan, err := n.AddressPlan(8)
	if err != nil {
		t.Fatal(err)
	}
	owner := public(f.a)
	if _, _, err = plan.Reserve("e", hex.EncodeToString(owner[:]), "first/lan", "", 1, netip.Addr{}); err == nil {
		t.Fatal("draining allocation accepted")
	}
	if _, err = f.n.Create(f.c, "admin", f.n.Revision(), definition("third", "lan", "node-b", "10.1.0.0/24", f.b)); err == nil {
		t.Fatal("Drain freed CIDR")
	}
	p := networkProof(f, "first")
	bad := p
	bad.PendingPins = 1
	bad.Signature = ed25519.Sign(f.a, NetworkClosureBytes(bad))
	if _, err = f.n.Retire(f.c, "alice", bad); err == nil {
		t.Fatal("live pin retired")
	}
	bad = p
	bad.Signature = ed25519.Sign(f.b, NetworkClosureBytes(bad))
	if _, err = f.n.Retire(f.c, "alice", bad); err == nil {
		t.Fatal("wrong owner")
	}
	bad = p
	bad.Revision--
	bad.Signature = ed25519.Sign(f.a, NetworkClosureBytes(bad))
	if _, err = f.n.Retire(f.c, "alice", bad); err == nil {
		t.Fatal("old revision")
	}
	tenant, _ := f.c.Tenant("first")
	f.c, err = f.c.SetNodes("admin", "first", tenant.Revision, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.n, err = f.n.Retire(f.c, "alice", p)
	if err != nil {
		t.Fatal("node grant loss prevented cleanup", err)
	}
	f = create(t, f, definition("third", "lan", "node-b", "10.1.0.0/24", f.b))
	if _, err = f.n.Retire(f.c, "admin", p); err == nil {
		t.Fatal("old receipt reused")
	}
}
func TestRouteRequiresBothExplicitApprovalsAndExactBindings(t *testing.T) {
	f := propose(t, two(t))
	if allows(f) {
		t.Fatal("proposal implies consent")
	}
	f = approve(t, f, "alice", "first")
	if allows(f) {
		t.Fatal("unilateral route")
	}
	r, _ := f.n.Route("first", "sql")
	if _, err := f.n.Approve(f.c, "alice", "first", "sql", "second", r.Revision); err != access.ErrDenied {
		t.Fatal("self-approved other tenant", err)
	}
	f = approve(t, f, "bob", "second")
	if !allows(f) {
		t.Fatal("bilateral route unavailable")
	}
	for _, tc := range []struct {
		src, dst string
		proto    uint8
		port     uint16
	}{{"10.2.0.10", "10.1.0.10", 6, 3306}, {"10.1.0.10", "10.3.0.10", 6, 3306}, {"10.1.0.10", "10.2.0.10", 17, 3306}, {"10.1.0.10", "10.2.0.10", 6, 3307}} {
		if f.n.AllowsNewFlow(f.c, "first", "sql", netip.MustParseAddr(tc.src), netip.MustParseAddr(tc.dst), tc.proto, tc.port) {
			t.Fatal("reverse/transit/port bypass", tc)
		}
	}
	if len(f.n.VisibleRoutes(f.c, "alice")) != 1 || len(f.n.VisibleRoutes(f.c, "bob")) != 1 || len(f.n.VisibleRoutes(f.c, "eve")) != 0 {
		t.Fatal("route view leaked")
	}
	r = routeDefinition(t, f.n)
	r.ID = "wide"
	r.Source.Prefix = netip.MustParsePrefix("0.0.0.0/0")
	if _, err := f.n.Propose(f.c, "alice", f.n.Revision(), r); err == nil {
		t.Fatal("default route")
	}
}
func TestRouteCurrentGrantsAndExplicitAdminSides(t *testing.T) {
	f := active(t)
	m, _ := f.c.Membership("second", "bob")
	m.Enabled = false
	m.Revision = 0
	c, err := f.c.SetMembership("admin", mustMembership(t, f.c, "second", "bob"), m)
	if err != nil {
		t.Fatal(err)
	}
	f.c = c
	if allows(f) {
		t.Fatal("revoked membership still allowed")
	}
	f = propose(t, two(t))
	f = approve(t, f, "admin", "first")
	if allows(f) {
		t.Fatal("admin implicit second approval")
	}
	f = approve(t, f, "admin", "second")
	if !allows(f) {
		t.Fatal("admin bilateral approval")
	}
	v, _ := f.c.Tenant("second")
	f.c, err = f.c.SetNodes("admin", "second", v.Revision, nil)
	if err != nil {
		t.Fatal(err)
	}
	if allows(f) {
		t.Fatal("withdrawn node grant")
	}
}
func mustMembership(t *testing.T, c access.Catalog, tenant, user string) uint64 {
	t.Helper()
	m, ok := c.Membership(tenant, user)
	if !ok {
		t.Fatal("missing fixture membership")
	}
	return m.Revision
}
func TestRevocationPreservesBindingsUntilBothOwnersSettle(t *testing.T) {
	f := active(t)
	activeRoute, _ := f.n.Route("first", "sql")
	f = withdraw(t, f)
	if allows(f) {
		t.Fatal("withdrawal admits new flow")
	}
	if _, err := f.n.Approve(f.c, "alice", "first", "sql", "first", activeRoute.Revision); err == nil {
		t.Fatal("late approval reopened route")
	}
	p := routeProof(f, "first")
	bad := p
	bad.PendingFlows = 1
	bad.Signature = ed25519.Sign(f.a, RouteClosureBytes(bad))
	if _, err := f.n.ObserveRetired(bad); err == nil {
		t.Fatal("live flow released")
	}
	bad = p
	bad.Cluster[0]++
	bad.Signature = ed25519.Sign(f.a, RouteClosureBytes(bad))
	if _, err := f.n.ObserveRetired(bad); err == nil {
		t.Fatal("cross cluster")
	}
	var err error
	f.n, err = f.n.ObserveRetired(p)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := f.n.Route("first", "sql")
	if r.Phase != Revoking || len(r.Closures) != 1 {
		t.Fatal("one owner prematurely settled")
	}
	f.n, err = Decode(snapshotBytes(t, f.n))
	if err != nil {
		t.Fatal(err)
	}
	f.n, err = f.n.ObserveRetired(routeProof(f, "second"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.n.Route("first", "sql"); ok {
		t.Fatal("both owners did not settle")
	}
	f = propose(t, f)
	newRoute, _ := f.n.Route("first", "sql")
	if newRoute.Generation <= activeRoute.Generation {
		t.Fatal("generation reuse")
	}
	if _, err = f.n.ObserveRetired(p); err == nil {
		t.Fatal("old closure hit recreated route")
	}
}
func TestNetworkDrainRevokesRouteAndRequiresRouteRetirement(t *testing.T) {
	f := active(t)
	v, _ := f.n.Network("first", "lan")
	n, err := f.n.Drain(f.c, "alice", "first", "lan", v.Revision)
	if err != nil {
		t.Fatal(err)
	}
	f.n = n
	if allows(f) {
		t.Fatal("draining network still admits route")
	}
	r, _ := f.n.Route("first", "sql")
	if r.Phase != Revoking {
		t.Fatal("route cleanup not requested")
	}
	p := networkProof(f, "first")
	if _, err = f.n.Retire(f.c, "alice", p); err == nil {
		t.Fatal("route reference ignored")
	}
	for _, side := range []string{"second", "first"} {
		proof := routeProof(f, side)
		f.n, err = f.n.ObserveRetired(proof)
		if err != nil {
			t.Fatal(err)
		}
	}
	f.n, err = f.n.Retire(f.c, "alice", p)
	if err != nil {
		t.Fatal(err)
	}
	f = create(t, f, definition("first", "lan", "node-a", "10.1.0.0/24", f.a))
	fresh, _ := f.n.Network("first", "lan")
	if fresh.Generation <= v.Generation {
		t.Fatal("reused network generation")
	}
}
func TestNetworkPolicyCanonicalSnapshotAndRejectedCandidates(t *testing.T) {
	f := active(t)
	before := snapshotBytes(t, f.n)
	restored, err := Decode(before)
	if err != nil || !bytes.Equal(before, snapshotBytes(t, restored)) {
		t.Fatal("roundtrip", err)
	}
	r, _ := f.n.Route("first", "sql")
	r.Ports[0].Last = 65535
	r.Approvals[0].User = "eve"
	if !bytes.Equal(before, snapshotBytes(t, f.n)) {
		t.Fatal("route getter alias")
	}
	var s snapshot
	if err = json.Unmarshal(before, &s); err != nil {
		t.Fatal(err)
	}
	s.Networks = append(s.Networks, s.Networks[0])
	bad, _ := json.Marshal(s)
	if _, err = Decode(bad); err == nil {
		t.Fatal("duplicate network snapshot")
	}
	json.Unmarshal(before, &s)
	s.Routes[0].Source.Owner = public(f.b)
	bad, _ = json.Marshal(s)
	if _, err = Decode(bad); err == nil {
		t.Fatal("forged owner snapshot")
	}
	json.Unmarshal(before, &s)
	s.Routes[0].Ports[0] = Ports{0, 0}
	bad, _ = json.Marshal(s)
	if _, err = Decode(bad); err == nil {
		t.Fatal("invalid ports")
	}
	if _, err = Decode(append(before, ' ')); err == nil {
		t.Fatal("noncanonical bytes")
	}
}

func TestTenantRetirementBlocksNewPolicyAndPreservesOriginalSettlement(t *testing.T) {
	f := active(t)
	v, _ := f.n.Network("first", "lan")
	r, _ := f.n.Route("first", "sql")
	tenant, _ := f.c.Tenant("first")
	inventory := []access.RetirementTarget{
		{Tenant: "first", Kind: "network", ID: v.ID, Node: v.Node, Owner: v.Owner, Generation: v.Generation},
		{Tenant: "first", Kind: "route", ID: r.ID, Node: r.Source.Node, Owner: r.Source.Owner, Generation: r.Generation},
		{Tenant: "first", Kind: "route", ID: r.ID, Node: r.Destination.Node, Owner: r.Destination.Owner, Generation: r.Generation},
	}
	var err error
	f.c, err = f.c.BeginTenantRetirement("admin", "first", "remove-tenant", f.n.cluster, tenant.Revision, inventory)
	if err != nil {
		t.Fatal(err)
	}
	if allows(f) {
		t.Fatal("retiring tenant still admits cross-tenant flows")
	}
	if _, err = f.n.Create(f.c, "admin", f.n.Revision(), definition("first", "fresh", "node-a", "10.3.0.0/24", f.a)); err != access.ErrDenied {
		t.Fatal("retirement allowed new network", err)
	}
	route := routeDefinition(t, f.n)
	route.ID = "new-route"
	if _, err = f.n.Propose(f.c, "alice", f.n.Revision(), route); err != access.ErrDenied {
		t.Fatal("retirement allowed new route", err)
	}
	f.n, err = f.n.Withdraw(f.c, "alice", "first", "sql", "first", r.Revision)
	if err != nil {
		t.Fatal("original route cleanup blocked", err)
	}
	f.n, err = f.n.Drain(f.c, "alice", "first", "lan", v.Revision)
	if err != nil {
		t.Fatal("original network cleanup blocked", err)
	}
	for _, side := range []string{"second", "first"} {
		f.n, err = f.n.ObserveRetired(routeProof(f, side))
		if err != nil {
			t.Fatal(err)
		}
	}
	f.n, err = f.n.Retire(f.c, "alice", networkProof(f, "first"))
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ = f.c.Tenant("first")
	ret := tenant.Retirement
	for _, owner := range ret.Owners {
		p := access.TenantReport{Cluster: ret.Cluster, Tenant: "first", Operation: ret.Operation, Node: owner.Node, Owner: owner.Key, StartedRevision: ret.StartedRevision, Sequence: 1, InventoryHash: ret.InventoryHash, OwnersHash: ret.OwnersHash, Quiesced: true}
		k := f.a
		if owner.Node == "node-b" {
			k = f.b
		}
		p.Signature = ed25519.Sign(k, access.TenantReportBytes(p))
		f.c, err = f.c.ObserveTenantRetirement(p)
		if err != nil {
			t.Fatal(err)
		}
	}
	tenant, _ = f.c.Tenant("first")
	f.c, err = f.c.FinishTenantRetirement("admin", "first", "remove-tenant", tenant.Revision, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.n.Network("second", "lan"); !ok {
		t.Fatal("other tenant resource removed")
	}
	if len(f.n.VisibleNetworks(f.c, "alice")) != 0 || len(f.n.VisibleNetworks(f.c, "bob")) != 1 {
		t.Fatal("deleted tenant visibility leaked")
	}
}
