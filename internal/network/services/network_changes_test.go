// SPDX-License-Identifier: Apache-2.0

package services

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/tenancy"
)

func networkChangeFixture(t *testing.T, sameCIDR bool) (networkFixture, tenancy.Network) {
	t.Helper()
	f := fixture(t)
	tenant, _ := f.c.Tenant("first")
	var e error
	f.c, e = f.c.SetNodes("admin", "first", tenant.Revision, []string{"node-a", "node-b"})
	if e != nil {
		t.Fatal(e)
	}
	prefix := netip.MustParsePrefix("10.45.0.0/24")
	if sameCIDR {
		prefix = netip.MustParsePrefix("10.42.0.0/24")
	}
	target := tenancy.Network{Tenant: "first", ID: "lan", Node: "node-b", Owner: pub(private(32)), Pools: []tenancy.Subnet{{ID: "pool", Prefix: prefix, Gateway: prefix.Addr().Next(), MTU: 1500}}}
	old, _ := f.n.Network("first", "lan")
	f.n, e = f.n.PlanChange(f.c, "admin", "first", "lan", "change", old.Revision, target)
	if e != nil {
		t.Fatal(e)
	}
	return f, target
}
func changeDrain(t *testing.T, f networkFixture) networkFixture {
	t.Helper()
	ch, _ := f.n.Change("first", "lan")
	var e error
	f.a, f.n, e = f.a.BeginNetworkChangeDrain(f.c, f.n, "admin", "first", "lan", ch.Generation, ch.Revision)
	if e != nil {
		t.Fatal(e)
	}
	return f
}
func sourceClosure(f networkFixture) tenancy.NetworkClosure {
	v, _ := f.n.Network("first", "lan")
	p := tenancy.NetworkClosure{Cluster: f.n.Cluster(), Tenant: v.Tenant, Network: v.ID, Node: v.Node, Owner: v.Owner, Generation: v.Generation, Revision: v.Revision, NativeGone: true}
	p.Signature = ed25519.Sign(f.key, tenancy.NetworkClosureBytes(p))
	return p
}
func sourceFence(t *testing.T, f networkFixture) networkFixture {
	t.Helper()
	ch, _ := f.n.Change("first", "lan")
	var e error
	f.a, f.n, e = f.a.FenceNetworkChange(f.c, f.n, "admin", "first", "lan", ch.Generation, ch.Revision, sourceClosure(f))
	if e != nil {
		t.Fatal(e)
	}
	return f
}
func changeCommit(t *testing.T, f networkFixture) networkFixture {
	t.Helper()
	ch, _ := f.n.Change("first", "lan")
	var e error
	f.a, f.n, e = f.a.CommitNetworkChange(f.c, f.n, "admin", "first", "lan", ch.Generation, ch.Revision)
	if e != nil {
		t.Fatal(e)
	}
	return f
}
func candidateGone(f networkFixture, ch tenancy.NetworkChange, key ed25519.PrivateKey) tenancy.ChangeCandidateClose {
	p := tenancy.ChangeCandidateClose{Cluster: f.n.Cluster(), Change: ch.ID, Generation: ch.Generation, TargetRevision: ch.TargetRevision, Target: tenancy.ChangeTargetHash(ch.Target), Owner: ch.Target.Owner, Boot: [32]byte{9}, Native: tenancy.CandidateNativeID(ch), Fenced: true, Gone: true, NoPending: true}
	p.Signature = ed25519.Sign(key, tenancy.ChangeCandidateBytes(p))
	return p
}
func netBytes(t *testing.T, n tenancy.Networks) []byte {
	t.Helper()
	raw, e := n.Encode()
	if e != nil {
		t.Fatal(e)
	}
	return raw
}

func TestNetworkChangeDrainKeepsStaticAddressUntilOriginalReferencesAndNativeClose(t *testing.T) {
	f, _ := networkChangeFixture(t, true)
	owner := poolOwner(Source{Owner: pub(f.key)})
	var err error
	var allocation network.Allocation
	f.a, allocation, err = f.a.ReserveStatic("task", owner, "first/lan", "first/lan/pool", 1, addr("10.42.0.10"))
	if err != nil {
		t.Fatal(err)
	}
	f = changeDrain(t, f)
	ch, _ := f.n.Change("first", "lan")
	if _, _, err = f.a.FenceNetworkChange(f.c, f.n, "admin", "first", "lan", ch.Generation, ch.Revision, sourceClosure(f)); err == nil {
		t.Fatal("live static endpoint passed source fence")
	}
	if _, _, err = f.a.ReserveStatic("late", owner, "first/lan", allocation.Pool, 2, addr("10.42.0.11")); err == nil {
		t.Fatal("Drain admitted a new endpoint")
	}
	f.a, err = f.a.BeginStaticRetirement(f.c, f.n, "admin", f.a.Revision(), allocation, 200)
	if err != nil {
		t.Fatal(err)
	}
	retirement, _ := f.a.AddressRetirement(allocation)
	f.a, err = f.a.ReleaseStatic(allocation, staticOwnerProof(t, dnsFixture{f: f}, retirement, 201), 201)
	if err != nil {
		t.Fatal(err)
	}
	f = changeCommit(t, sourceFence(t, f))
	now, _ := f.n.Network("first", "lan")
	if now.Owner == pub(f.key) || now.Draining {
		t.Fatal("owner transition did not commit")
	}
	newOwner := poolOwner(Source{Owner: now.Owner})
	if _, _, err = f.a.ReserveStatic("task", newOwner, "first/lan", allocation.Pool, allocation.Generation, allocation.Address); err == nil {
		t.Fatal("owner change reset address generation floor")
	}
	if _, _, err = f.a.ReserveStatic("task", newOwner, "first/lan", allocation.Pool, allocation.Generation+1, allocation.Address); err != nil {
		t.Fatal("explicit new owner/generation rejected", err)
	}
	if _, err = DecodeAuthority(encode(t, f.a)); err != nil {
		t.Fatal(err)
	}
}

func TestNetworkChangeArchiveRetainsCIDRClosureAndRejectsLegacyDHCPPayload(t *testing.T) {
	f, _ := networkChangeFixture(t, false)
	old, _ := f.n.Network("first", "lan")
	f = changeCommit(t, sourceFence(t, changeDrain(t, f)))
	archived, found := f.a.RetiredNetwork("first", "lan", old.Generation)
	if !found || archived.Network.Owner != old.Owner || !archived.Closed.NativeGone {
		t.Fatal("original CIDR closure lost")
	}
	raw := encode(t, f.a)
	for _, mutate := range []func(*authoritySnapshot){
		func(s *authoritySnapshot) { s.Archives[0].Closed.Signature = nil },
		func(s *authoritySnapshot) { s.Archives[0].Network.Generation++ },
		func(s *authoritySnapshot) {
			s.Archives[0].Services = []json.RawMessage{json.RawMessage(`{"legacy":"dhcp"}`)}
		},
	} {
		var s authoritySnapshot
		if err := json.Unmarshal(raw, &s); err != nil {
			t.Fatal(err)
		}
		mutate(&s)
		bad, _ := json.Marshal(s)
		if _, err := DecodeAuthority(bad); err == nil {
			t.Fatal("forged closure or operational legacy state accepted")
		}
	}
}

func TestNetworkChangeGlobalDNSReferenceBlocksSourceEvenWithoutAddresses(t *testing.T) {
	f, _ := networkChangeFixture(t, false)
	m, e := NewDNSManager(f.a.cluster, pub(f.key), []string{"sfc.test."}, 8, 8)
	if e != nil {
		t.Fatal(e)
	}
	cfg := DNSConfig{Tenant: "first", ID: "dns", Network: "lan", Pool: "pool", Source: 100, Serial: 1, Enabled: true, Zone: "app.sfc.test.", ClientZone: "clients.app.sfc.test.", TTL: 30, NegativeTTL: 5, QuerySeconds: 2, MaxQueries: 2, MaxCacheEntries: 2, MaxResponseBytes: 4096}
	d := publishDNS(t, dnsFixture{f: f, m: m, cfg: cfg}, cfg, 190)
	consumer := dnsConsumer(t, d)
	f = changeDrain(t, d.f)
	ch, _ := f.n.Change("first", "lan")
	if _, _, e = f.a.FenceNetworkChange(f.c, f.n, "admin", "first", "lan", ch.Generation, ch.Revision, sourceClosure(f)); e == nil {
		t.Fatal("active DNS instance omitted from network fence")
	}
	d.f = f
	old := d.m.current["first/dns"]
	d.m, e = d.m.RetireCurrent("first", "dns", 100, d.clock(200))
	if e != nil {
		t.Fatal(e)
	}
	d.m, e = d.m.Collect(old, d.clock(230))
	if e != nil {
		t.Fatal(e)
	}
	d.m, e = d.m.MarkReferenceClosed(d.f.a, consumer.ID)
	if e != nil {
		t.Fatal(e)
	}
	p := nativeReferenceProof(t, d, consumer, [32]byte{}, 230)
	d.f.a, e = d.f.a.ObserveReferenceClose(p, 230)
	if e != nil {
		t.Fatal(e)
	}
	f = sourceFence(t, d.f)
	f = changeCommit(t, f)
	encode(t, f.a)
}
func TestNetworkChangeIrreversibleRecoveryReturnsToOriginalOwnerOnlyAsNewGeneration(t *testing.T) {
	f, _ := networkChangeFixture(t, false)
	old, _ := f.n.Network("first", "lan")
	f = sourceFence(t, changeDrain(t, f))
	ch, _ := f.n.Change("first", "lan")
	p := candidateGone(f, ch, private(32))
	target := ch.Original
	target.Generation = 0
	target.Revision = 0
	target.Draining = false
	bad := p
	bad.NoPending = false
	bad.Signature = ed25519.Sign(private(32), tenancy.ChangeCandidateBytes(bad))
	before := netBytes(t, f.n)
	if got, e := f.n.RecoverChange(f.c, "admin", "first", "lan", ch.Generation, ch.Revision, target, bad); e == nil || !bytes.Equal(before, netBytes(t, got)) {
		t.Fatal("unknown candidate discarded")
	}
	var e error
	f.n, e = f.n.RecoverChange(f.c, "admin", "first", "lan", ch.Generation, ch.Revision, target, p)
	if e != nil {
		t.Fatal(e)
	}
	f = changeCommit(t, f)
	now, _ := f.n.Network("first", "lan")
	if now.Owner != old.Owner || now.Generation <= old.Generation || now.Draining {
		t.Fatal("recovery rolled back old generation")
	}
	encode(t, f.a)
}
func TestNetworkChangeTargetGrantRevocationCannotPartiallyPublishOwnerOrArchive(t *testing.T) {
	f, _ := networkChangeFixture(t, false)
	f = sourceFence(t, changeDrain(t, f))
	ch, _ := f.n.Change("first", "lan")
	tenant, _ := f.c.Tenant("first")
	var e error
	f.c, e = f.c.SetNodes("admin", "first", tenant.Revision, []string{"node-a"})
	if e != nil {
		t.Fatal(e)
	}
	beforeA, beforeN := encode(t, f.a), netBytes(t, f.n)
	a, n, e := f.a.CommitNetworkChange(f.c, f.n, "admin", "first", "lan", ch.Generation, ch.Revision)
	if e == nil || !bytes.Equal(beforeA, encode(t, a)) || !bytes.Equal(beforeN, netBytes(t, n)) {
		t.Fatal("failed owner CAS partially published")
	}
	tenant, _ = f.c.Tenant("first")
	f.c, e = f.c.SetNodes("admin", "first", tenant.Revision, []string{"node-a", "node-b"})
	if e != nil {
		t.Fatal(e)
	}
	f = changeCommit(t, f)
	encode(t, f.a)
}
func TestNetworkChangeDeleteRetainsHistoryAndAllowsExplicitFreshCIDRReservation(t *testing.T) {
	f := fixture(t)
	old, _ := f.n.Network("first", "lan")
	var e error
	f.n, e = f.n.Drain(f.c, "admin", "first", "lan", old.Revision)
	if e != nil {
		t.Fatal(e)
	}
	f.a, e = f.a.SyncPools(f.n)
	if e != nil {
		t.Fatal(e)
	}
	f.a, f.n, e = f.a.RetireNetwork(f.c, f.n, "admin", sourceClosure(f))
	if e != nil {
		t.Fatal(e)
	}
	if _, ok := f.a.RetiredNetwork("first", "lan", old.Generation); !ok {
		t.Fatal("delete erased original CIDR ownership record")
	}
	next := old
	next.Generation = 0
	next.Revision = 0
	next.Draining = false
	f.n, e = f.n.Create(f.c, "admin", f.n.Revision(), next)
	if e != nil {
		t.Fatal(e)
	}
	f.a, e = f.a.SyncPools(f.n)
	if e != nil {
		t.Fatal(e)
	}
	now, _ := f.n.Network("first", "lan")
	if now.Generation <= old.Generation {
		t.Fatal("recreated old generation")
	}
	encode(t, f.a)
}
