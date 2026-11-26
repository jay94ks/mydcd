// SPDX-License-Identifier: Apache-2.0

package services

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"
)

func dnsConsumer(t *testing.T, d dnsFixture) ReferenceConsumer {
	t.Helper()
	local, ok := source(d.f.n, d.f.a.cluster, d.cfg.Tenant, d.cfg.Network, d.cfg.Pool)
	if !ok {
		t.Fatal("source")
	}
	c, ok := d.f.a.DNSReference(d.cfg.Tenant, d.cfg.ID, local)
	if !ok {
		t.Fatal("consumer")
	}
	return c
}
func ownerKey(t *testing.T, owner [32]byte) ed25519.PrivateKey {
	t.Helper()
	for _, n := range []byte{31, 32} {
		key := private(n)
		if pub(key) == owner {
			return key
		}
	}
	t.Fatal("unknown fixture owner")
	return nil
}
func staticOwnerProof(t *testing.T, d dnsFixture, f ReferenceRetirement, at int64) AddressOwnerClose {
	t.Helper()
	p := AddressOwnerClose{Cluster: d.f.a.cluster, Target: f.ID, Epoch: f.Epoch, Owner: f.Target.Source.Owner, Boot: d.f.boot, At: at, Native: "original-task", Fenced: true, Stopped: true}
	p.Signature = ed25519.Sign(ownerKey(t, p.Owner), AddressOwnerCloseBytes(p))
	return p
}
func nativeReferenceProof(t *testing.T, d dnsFixture, c ReferenceConsumer, target [32]byte, at int64) ReferenceClose {
	t.Helper()
	p, e := d.m.ReferenceFacts(d.f.a, c.ID, target, d.clock(at))
	if e != nil {
		t.Fatal("reference facts", e)
	}
	// Fake native collector: positive inspection of the original instance found
	// no executing/unknown socket work. Product templates never assert this.
	p.Settled = true
	p.Signature = ed25519.Sign(ownerKey(t, p.Owner), ReferenceCloseBytes(p))
	return p
}
func twoDNSOwners(t *testing.T) (dnsFixture, dnsFixture) {
	t.Helper()
	a := newDNSFixture(t)
	a = publishDNS(t, a, a.cfg, 190)
	b := a
	var e error
	b.m, e = NewDNSManager(a.f.a.cluster, pub(private(32)), []string{"mydc.test."}, 8, 8)
	if e != nil {
		t.Fatal(e)
	}
	b.cfg = ownDNSConfig(a.cfg)
	b.cfg.Network, b.cfg.Pool = "remote", "four"
	b.cfg.Members = []string{"lan"}
	b = publishDNS(t, b, b.cfg, 190)
	a.f.a = b.f.a
	return a, b
}
func closeTargetViews(t *testing.T, d dnsFixture, target ReferenceRetirement, at int64) dnsFixture {
	t.Helper()
	c := dnsConsumer(t, d)
	var e error
	d.m, e = d.m.SyncReferenceFence(d.f.a, c.ID, target.ID)
	if e != nil {
		t.Fatal(e)
	}
	old := d.m.current[dnsKey(d.cfg.Tenant, d.cfg.ID)]
	cfg := ownDNSConfig(d.cfg)
	cfg.Source++
	cfg.Serial++
	cfg.Names = []DNSName{{"web", "web-six", 3}}
	cfg.Leases = nil
	d = publishDNS(t, d, cfg, at)
	d.cfg = cfg
	d.m, e = d.m.Collect(old, d.clock(at+30))
	if e != nil {
		t.Fatal("old view collect", e)
	}
	return d
}

func TestReferencesAddressWaitsForEveryDNSOwnerAndOriginalNative(t *testing.T) {
	a, b := twoDNSOwners(t)
	target, _ := a.f.a.book.Allocation("web-four")
	var e error
	a.f.a, e = a.f.a.BeginStaticRetirement(a.f.c, a.f.n, "admin", a.f.a.Revision(), target, 200)
	if e != nil {
		t.Fatal(e)
	}
	f, ok := a.f.a.AddressRetirement(target)
	if !ok || len(f.Required) != 2 {
		t.Fatal("incomplete owner set", f)
	}
	owner := staticOwnerProof(t, a, f, 232)
	if _, e = a.f.a.ReleaseStatic(target, owner, 232); e == nil {
		t.Fatal("native owner0 bypassed DNS owners")
	}
	a = closeTargetViews(t, a, f, 201)
	ca := dnsConsumer(t, a)
	pa := nativeReferenceProof(t, a, ca, f.ID, 231)
	a.f.a, e = a.f.a.ObserveReferenceClose(pa, 231)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.f.a.ReleaseStatic(target, owner, 232); e == nil {
		t.Fatal("one owner's0 covered remote consumer")
	}
	b.f.a = a.f.a
	b = closeTargetViews(t, b, f, 232)
	cb := dnsConsumer(t, b)
	pb := nativeReferenceProof(t, b, cb, f.ID, 262)
	b.f.a, e = b.f.a.ObserveReferenceClose(pb, 262)
	if e != nil {
		t.Fatal(e)
	}
	bad := owner
	bad.PendingFlows = 1
	bad.Signature = ed25519.Sign(ownerKey(t, bad.Owner), AddressOwnerCloseBytes(bad))
	if _, e = b.f.a.ReleaseStatic(target, bad, 263); e == nil {
		t.Fatal("all DNS closed bypassed native flow")
	}
	b.f.a, e = b.f.a.ReleaseStatic(target, owner, 263)
	if e != nil {
		t.Fatal(e)
	}
	if _, held := b.f.a.book.Allocation(target.Endpoint); held {
		t.Fatal("address not returned")
	}
	encode(t, b.f.a)
}

func TestReferencesRequiredSetCannotBeErasedOrRetaggedInSnapshot(t *testing.T) {
	a, _ := twoDNSOwners(t)
	target, _ := a.f.a.book.Allocation("web-four")
	var e error
	a.f.a, e = a.f.a.BeginStaticRetirement(a.f.c, a.f.n, "admin", a.f.a.Revision(), target, 200)
	if e != nil {
		t.Fatal(e)
	}
	raw := encode(t, a.f.a)
	copy, e := DecodeAuthority(raw)
	if e != nil || !bytes.Equal(raw, encode(t, copy)) {
		t.Fatal(e)
	}
	for _, mutate := range []func(*authoritySnapshot){func(s *authoritySnapshot) { s.References = nil }, func(s *authoritySnapshot) { s.References.Fences[0].Required = s.References.Fences[0].Required[:1] }, func(s *authoritySnapshot) { s.References.Consumers[0].Lifetime.Token++ }, func(s *authoritySnapshot) { s.References.Fences[0].Epoch++ }, func(s *authoritySnapshot) { s.References.Consumers[0].Members[0].Since = s.Revision + 1 }, func(s *authoritySnapshot) { s.References.Pins.Active = nil }} {
		var snap authoritySnapshot
		_ = json.Unmarshal(raw, &snap)
		mutate(&snap)
		bad, _ := json.Marshal(snap)
		if _, e = DecodeAuthority(bad); e == nil {
			t.Fatal("reference ownership erased/retagged")
		}
	}
}

func TestReferencesNewInstanceUnderFenceCannotAdmitOriginalOrigin(t *testing.T) {
	d := newDNSFixture(t)
	d.cfg.Names = []DNSName{{"origin", "origin", 1}}
	d = publishDNS(t, d, d.cfg, 190)
	target, _ := d.f.a.book.Allocation("web-four")
	var e error
	d.f.a, e = d.f.a.BeginStaticRetirement(d.f.c, d.f.n, "admin", d.f.a.Revision(), target, 200)
	if e != nil {
		t.Fatal(e)
	}
	f, _ := d.f.a.AddressRetirement(target)
	cfg := ownDNSConfig(d.cfg)
	cfg.ID = "new-dns"
	cfg.Source = 101
	d = grantDNS(t, d, cfg)
	local, _ := source(d.f.n, d.f.a.cluster, cfg.Tenant, cfg.Network, cfg.Pool)
	newConsumer, _ := d.f.a.DNSReference(cfg.Tenant, cfg.ID, local)
	for _, need := range f.Required {
		if need.Consumer == newConsumer.ID {
			t.Fatal("new instance incorrectly rewrote frozen set")
		}
	}
	m, e := NewDNSManager(d.f.a.cluster, pub(d.f.key), []string{"mydc.test."}, 8, 8)
	if e != nil {
		t.Fatal(e)
	}
	d.m = m
	d.cfg = cfg
	d = publishDNS(t, d, cfg, 201)
	if _, _, e = d.m.Acquire(d.f.c, d.f.n, d.f.a, cfg.Tenant, cfg.ID, target, dnsWire("origin.app.mydc.test.", 1), d.clock(202)); e == nil {
		t.Fatal("new instance under fence admitted original address")
	}
	encode(t, d.f.a)
	encodeDNS(t, d.m)
}

func TestReferencesCoverageEpochDistinguishesPreFenceAndLaterExtension(t *testing.T) {
	d := newDNSFixture(t)
	d.cfg.Members = nil
	d.cfg.Names = []DNSName{{"origin", "origin", 1}}
	d = publishDNS(t, d, d.cfg, 190)
	target, _ := d.f.a.book.Allocation("web-four")
	var e error
	d.f.a, e = d.f.a.BeginStaticRetirement(d.f.c, d.f.n, "admin", d.f.a.Revision(), target, 200)
	if e != nil {
		t.Fatal(e)
	}
	f, _ := d.f.a.AddressRetirement(target)
	if len(f.Required) != 0 {
		t.Fatal("unrelated coverage captured")
	}
	cfg := ownDNSConfig(d.cfg)
	cfg.Members = []string{"remote"}
	cfg.Source++
	cfg.Serial++
	d = grantDNS(t, d, cfg)
	c := dnsConsumer(t, d)
	if !consumerCovers(c, f.Target.Source, 0) || consumerCovers(c, f.Target.Source, f.Epoch) {
		t.Fatal("coverage epoch lost")
	}
	d = publishDNS(t, d, cfg, 201)
	if _, _, e = d.m.Acquire(d.f.c, d.f.n, d.f.a, "first", "dns", target, dnsWire("origin.app.mydc.test.", 1), d.clock(202)); e == nil {
		t.Fatal("coverage extension bypassed existing fence")
	}
	encode(t, d.f.a)
}

func TestReferencesFenceSurvivesLocalRecoveryAndSafeHistoryCompaction(t *testing.T) {
	d := newDNSFixture(t)
	d = publishDNS(t, d, d.cfg, 190)
	target, _ := d.f.a.book.Allocation("web-four")
	var e error
	d.f.a, e = d.f.a.BeginStaticRetirement(d.f.c, d.f.n, "admin", d.f.a.Revision(), target, 200)
	if e != nil {
		t.Fatal(e)
	}
	f, _ := d.f.a.AddressRetirement(target)
	stale := d.f.a
	d = closeTargetViews(t, d, f, 201)
	c := dnsConsumer(t, d)
	localRaw := encodeDNS(t, d.m)
	d.m, e = DecodeDNSManager(localRaw)
	if e != nil {
		t.Fatal(e)
	}
	p := nativeReferenceProof(t, d, c, f.ID, 231)
	d.f.a, e = d.f.a.ObserveReferenceClose(p, 231)
	if e != nil {
		t.Fatal(e)
	}
	owner := staticOwnerProof(t, d, f, 232)
	d.f.a, e = d.f.a.ReleaseStatic(target, owner, 232)
	if e != nil {
		t.Fatal(e)
	}
	d.f.a, e = d.f.a.CompactReferences()
	if e != nil {
		t.Fatal(e)
	}
	d.m, e = d.m.SyncReferenceState(d.f.a)
	if e != nil {
		t.Fatal(e)
	}
	if len(d.m.fenced) != 0 {
		t.Fatal("finished local fence not compacted")
	}
	raw := dnsWire("web.app.mydc.test.", 1)
	if _, _, e = d.m.Acquire(d.f.c, d.f.n, stale, "first", "dns", d.origin, raw, d.clock(233)); e == nil {
		t.Fatal("pre-compaction root revived admission")
	}
	d.m, e = DecodeDNSManager(encodeDNS(t, d.m))
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = d.m.Acquire(d.f.c, d.f.n, stale, "first", "dns", d.origin, raw, d.clock(233)); e == nil {
		t.Fatal("restored floor lost stale-root protection")
	}
	encode(t, d.f.a)
}

func TestReferencesWholeClosureIsPermanentAndRequiresNativeCollector(t *testing.T) {
	d := newDNSFixture(t)
	d = publishDNS(t, d, d.cfg, 190)
	c := dnsConsumer(t, d)
	var e error
	if _, e = d.m.MarkReferenceClosed(d.f.a, c.ID); e == nil {
		t.Fatal("live view marked permanently closed")
	}
	old := d.m.current["first/dns"]
	d.m, e = d.m.RetireCurrent("first", "dns", 100, d.clock(200))
	if e != nil {
		t.Fatal(e)
	}
	d.m, e = d.m.Collect(old, d.clock(230))
	if e != nil {
		t.Fatal(e)
	}
	d.m, e = d.m.MarkReferenceClosed(d.f.a, c.ID)
	if e != nil {
		t.Fatal(e)
	}
	facts, e := d.m.ReferenceFacts(d.f.a, c.ID, [32]byte{}, d.clock(231))
	if e != nil {
		t.Fatal(e)
	}
	facts.Signature = ed25519.Sign(d.f.key, ReferenceCloseBytes(facts))
	if _, e = d.f.a.ObserveReferenceClose(facts, 231); e == nil {
		t.Fatal("metadata0 template pretended native stop")
	}
	p := nativeReferenceProof(t, d, c, [32]byte{}, 231)
	d.f.a, e = d.f.a.ObserveReferenceClose(p, 231)
	if e != nil {
		t.Fatal(e)
	}
	d.f.a, e = d.f.a.CompactReferences()
	if e != nil {
		t.Fatal(e)
	}
	d.m, e = d.m.SyncReferenceState(d.f.a)
	if e != nil {
		t.Fatal(e)
	}
	cfg := ownDNSConfig(d.cfg)
	cfg.Source++
	cfg.Serial++
	d = publishDNS(t, d, cfg, 232)
	next := dnsConsumer(t, d)
	if next.ID == c.ID || next.Generation <= c.Generation || next.Lifetime.Token <= c.Lifetime.Token {
		t.Fatal("closed instance lifetime reused")
	}
	encode(t, d.f.a)
	encodeDNS(t, d.m)
}

func TestReferencesStaticOriginRetirementWaitsForQueryAndNativeClose(t *testing.T) {
	d := newDNSFixture(t)
	d = publishDNS(t, d, d.cfg, 190)
	c := dnsConsumer(t, d)
	raw := dnsWire("web.app.mydc.test.", 1)
	rootBefore := encode(t, d.f.a)
	var h DNSQuery
	var err error
	d.m, h, err = d.m.Acquire(d.f.c, d.f.n, d.f.a, "first", "dns", d.origin, raw, d.clock(200))
	if err != nil || !bytes.Equal(rootBefore, encode(t, d.f.a)) {
		t.Fatal("query changed shared address authority", err)
	}
	d.f.a, err = d.f.a.BeginStaticRetirement(d.f.c, d.f.n, "admin", d.f.a.Revision(), d.origin, 201)
	if err != nil {
		t.Fatal(err)
	}
	f, _ := d.f.a.AddressRetirement(d.origin)
	d.m, err = d.m.SyncReferenceFence(d.f.a, c.ID, f.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.m.ReferenceFacts(d.f.a, c.ID, f.ID, d.clock(201)); err == nil {
		t.Fatal("original origin query was not held")
	}
	if _, err = d.f.a.ReleaseStatic(d.origin, staticOwnerProof(t, d, f, 202), 202); err == nil {
		t.Fatal("native owner proof bypassed DNS reader")
	}
	d.m, err = d.m.Release(h, d.clock(202))
	if err != nil {
		t.Fatal(err)
	}
	p := nativeReferenceProof(t, d, c, f.ID, 202)
	d.f.a, err = d.f.a.ObserveReferenceClose(p, 202)
	if err != nil {
		t.Fatal(err)
	}
	d.f.a, err = d.f.a.ReleaseStatic(d.origin, staticOwnerProof(t, d, f, 202), 202)
	if err != nil {
		t.Fatal(err)
	}
	encode(t, d.f.a)
}

func TestReferencesClosureCannotCrossOwnerTargetEpochOrLifetime(t *testing.T) {
	d := newDNSFixture(t)
	d = publishDNS(t, d, d.cfg, 190)
	target, _ := d.f.a.book.Allocation("web-four")
	var e error
	d.f.a, e = d.f.a.BeginStaticRetirement(d.f.c, d.f.n, "admin", d.f.a.Revision(), target, 200)
	if e != nil {
		t.Fatal(e)
	}
	f, _ := d.f.a.AddressRetirement(target)
	d = closeTargetViews(t, d, f, 201)
	c := dnsConsumer(t, d)
	p := nativeReferenceProof(t, d, c, f.ID, 231)
	for _, mutate := range []func(*ReferenceClose){func(p *ReferenceClose) { p.Epoch++ }, func(p *ReferenceClose) { p.Lifetime.Token++ }, func(p *ReferenceClose) { p.Target = [32]byte{9} }, func(p *ReferenceClose) { p.Owner = pub(private(32)) }, func(p *ReferenceClose) { p.PendingQueries = 1 }, func(p *ReferenceClose) { p.Fenced = false }, func(p *ReferenceClose) { p.TTLExpired = false }} {
		bad := p
		mutate(&bad)
		bad.Signature = ed25519.Sign(d.f.key, ReferenceCloseBytes(bad))
		if _, e = d.f.a.ObserveReferenceClose(bad, 231); e == nil {
			t.Fatal("wrong closure accepted")
		}
	}
	if _, e = d.f.a.ReleaseStatic(target, AddressOwnerClose{}, 231); e == nil {
		t.Fatal("unsigned native absence")
	}
}
