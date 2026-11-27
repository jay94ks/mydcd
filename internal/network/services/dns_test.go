// SPDX-License-Identifier: Apache-2.0

package services

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"testing"

	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/miekg/dns"
)

type dnsFixture struct {
	f      networkFixture
	m      DNSManager
	cfg    DNSConfig
	origin network.Allocation
}

func newDNSFixture(t *testing.T) dnsFixture {
	t.Helper()
	f := fixture(t)
	tenant, _ := f.c.Tenant("first")
	var e error
	f.c, e = f.c.SetNodes("admin", "first", tenant.Revision, []string{"node-a", "node-b"})
	if e != nil {
		t.Fatal(e)
	}
	f.n, e = f.n.Create(f.c, "admin", f.n.Revision(), tenancy.Network{Tenant: "first", ID: "remote", Node: "node-b", Owner: pub(private(32)), Pools: []tenancy.Subnet{{ID: "four", Prefix: netip.MustParsePrefix("10.43.0.0/24"), Gateway: addr("10.43.0.1"), MTU: 1500}, {ID: "six", Prefix: netip.MustParsePrefix("2001:db8:43::/64"), Gateway: addr("2001:db8:43::1"), MTU: 1500}}})
	if e != nil {
		t.Fatal(e)
	}
	f.c, e = f.c.CreateTenant("admin", "second", 0)
	if e != nil {
		t.Fatal(e)
	}
	other, _ := f.c.Tenant("second")
	f.c, e = f.c.SetNodes("admin", "second", other.Revision, []string{"node-a"})
	if e != nil {
		t.Fatal(e)
	}
	f.n, e = f.n.Create(f.c, "admin", f.n.Revision(), tenancy.Network{Tenant: "second", ID: "private", Node: "node-a", Owner: pub(f.key), Pools: []tenancy.Subnet{{ID: "pool", Prefix: netip.MustParsePrefix("10.44.0.0/24"), Gateway: addr("10.44.0.1"), MTU: 1500}}})
	if e != nil {
		t.Fatal(e)
	}
	f.a, e = f.a.SyncPools(f.n)
	if e != nil {
		t.Fatal(e)
	}
	f.a, e = f.a.ResizeAddresses(128)
	if e != nil {
		t.Fatal(e)
	}
	var origin network.Allocation
	for _, item := range []struct {
		endpoint, owner, network, pool, address string
		generation                              uint64
	}{{"origin", poolOwner(Source{Owner: pub(f.key)}), "first/lan", "first/lan/pool", "10.42.0.10", 1}, {"web-four", poolOwner(Source{Owner: pub(private(32))}), "first/remote", "first/remote/four", "10.43.0.10", 2}, {"web-six", poolOwner(Source{Owner: pub(private(32))}), "first/remote", "first/remote/six", "2001:db8:43::10", 3}, {"private", poolOwner(Source{Owner: pub(f.key)}), "second/private", "second/private/pool", "10.44.0.10", 4}} {
		var alloc network.Allocation
		f.a, alloc, e = f.a.ReserveStatic(item.endpoint, item.owner, item.network, item.pool, item.generation, addr(item.address))
		if e != nil {
			t.Fatal(e)
		}
		if item.endpoint == "origin" {
			origin = alloc
		}
	}
	m, e := NewDNSManager(f.n.Cluster(), pub(f.key), []string{"sfc.test."}, 8, 8)
	if e != nil {
		t.Fatal(e)
	}
	cfg := DNSConfig{Tenant: "first", ID: "dns", Network: "lan", Pool: "pool", Source: 100, Serial: 1, Enabled: true, Reverse: true, Zone: "app.sfc.test.", ClientZone: "clients.app.sfc.test.", TTL: 30, NegativeTTL: 5, QuerySeconds: 2, MaxQueries: 2, MaxCacheEntries: 2, MaxResponseBytes: 4096, Members: []string{"remote"}, Names: []DNSName{{"web", "web-four", 2}, {"web", "web-six", 3}, {"deep.child", "web-four", 2}}, Upstreams: []netip.AddrPort{netip.MustParseAddrPort("9.9.9.9:53")}}
	return dnsFixture{f, m, cfg, origin}
}
func (d dnsFixture) clock(at int64) Clock {
	return Clock{Boot: d.f.boot, Wall: at, Mono: at, Certain: true}
}
func dnsWire(name string, kind uint16) []byte {
	m := new(dns.Msg)
	m.SetQuestion(name, kind)
	m.Id = 77
	raw, _ := m.Pack()
	return raw
}
func encodeDNS(t *testing.T, m DNSManager) []byte {
	t.Helper()
	raw, e := m.Encode()
	if e != nil {
		t.Fatal("invalid DNS candidate", e)
	}
	return raw
}
func publishDNS(t *testing.T, d dnsFixture, cfg DNSConfig, at int64) dnsFixture {
	t.Helper()
	d = grantDNS(t, d, cfg)
	var e error
	expected := d.m.floors[dnsKey(cfg.Tenant, cfg.ID)].Source
	d.m, e = d.m.Prepare(d.f.c, d.f.n, d.f.a, "admin", expected, cfg)
	if e != nil {
		t.Fatal("prepare", e)
	}
	d.m, e = d.m.Publish(d.f.c, d.f.n, d.f.a, cfg.Tenant, cfg.ID, cfg.Source, d.clock(at))
	if e != nil {
		t.Fatal("publish", e)
	}
	return d
}
func grantDNS(t *testing.T, d dnsFixture, cfg DNSConfig) dnsFixture {
	t.Helper()
	local, ok := source(d.f.n, d.f.a.cluster, cfg.Tenant, cfg.Network, cfg.Pool)
	if !ok {
		t.Fatal("grant source")
	}
	var e error
	d.f.a, _, e = d.f.a.GrantDNSInstance(d.f.c, d.f.n, "admin", d.f.a.DNSReferenceGeneration(cfg.Tenant, cfg.ID, local), cfg)
	if e != nil {
		t.Fatal("grant", e)
	}
	return d
}
func startDNS(t *testing.T, d dnsFixture, name string, kind uint16, at int64) (dnsFixture, DNSQuery, []byte) {
	t.Helper()
	raw := dnsWire(name, kind)
	m, h, e := d.m.Acquire(d.f.c, d.f.n, d.f.a, d.cfg.Tenant, d.cfg.ID, d.origin, raw, d.clock(at))
	if e != nil {
		t.Fatal("acquire", e)
	}
	d.m = m
	return d, h, raw
}
func askDNS(t *testing.T, d dnsFixture, name string, kind uint16, at int64) (dnsFixture, DNSResult) {
	t.Helper()
	d, h, raw := startDNS(t, d, name, kind, at)
	answer, e := d.m.Answer(d.f.c, d.f.n, d.f.a, h, raw, d.clock(at))
	if e != nil {
		t.Fatal("answer", e)
	}
	d.m, e = d.m.Release(h, d.clock(at))
	if e != nil {
		t.Fatal("release", e)
	}
	return d, answer
}

func TestDNSProjectionCommittedAddressesTwoOwnersAndRecordKinds(t *testing.T) {
	d := newDNSFixture(t)
	d = publishDNS(t, d, d.cfg, 190)
	for _, item := range []struct {
		name  string
		kind  uint16
		count int
		code  int
	}{{"WEB.App.SFC.test.", dns.TypeA, 1, dns.RcodeSuccess}, {"web.app.sfc.test.", dns.TypeAAAA, 1, dns.RcodeSuccess}, {"10.0.42.10.in-addr.arpa.", dns.TypePTR, 0, dns.RcodeNameError}, {"app.sfc.test.", dns.TypeSOA, 1, dns.RcodeSuccess}, {"app.sfc.test.", dns.TypeNS, 1, dns.RcodeSuccess}, {"ns.app.sfc.test.", dns.TypeA, 2, dns.RcodeSuccess}, {"ns.app.sfc.test.", dns.TypeAAAA, 1, dns.RcodeSuccess}, {"child.app.sfc.test.", dns.TypeA, 0, dns.RcodeSuccess}, {"web.app.sfc.test.", dns.TypeMX, 0, dns.RcodeSuccess}, {"missing.app.sfc.test.", dns.TypeA, 0, dns.RcodeNameError}} {
		var out DNSResult
		d, out = askDNS(t, d, item.name, item.kind, 200)
		if out.Response == nil || !out.Response.Authoritative || out.Response.Rcode != item.code || len(out.Response.Answer) != item.count || out.Forward != nil {
			t.Fatal(item, out)
		}
		if item.count == 0 && (len(out.Response.Ns) != 1 || out.Response.Ns[0].Header().Ttl != 5) {
			t.Fatal("negative SOA missing")
		}
	}
	// The other node consumes the same logical view/serial and sees the same
	// remote A/AAAA and server RRsets; its local reverse scope is different.
	remote := d
	var e error
	remote.m, e = NewDNSManager(d.f.n.Cluster(), pub(private(32)), []string{"sfc.test."}, 8, 8)
	if e != nil {
		t.Fatal(e)
	}
	remote.cfg.Network, remote.cfg.Pool = "remote", "four"
	remote.cfg.Members = []string{"lan"}
	remote.origin, _ = d.f.a.book.Allocation("web-four")
	remote = publishDNS(t, remote, remote.cfg, 190)
	var result DNSResult
	remote, result = askDNS(t, remote, "10.0.43.10.in-addr.arpa.", dns.TypePTR, 200)
	if len(result.Response.Answer) != 2 {
		t.Fatal("remote reverse aliases missing", result.Response)
	}
	_, a := askDNS(t, d, "ns.app.sfc.test.", dns.TypeA, 200)
	_, b := askDNS(t, remote, "ns.app.sfc.test.", dns.TypeA, 200)
	if fmt.Sprint(a.Response.Answer) != fmt.Sprint(b.Response.Answer) {
		t.Fatal("same zone differs by serving node")
	}
	encodeDNS(t, d.m)
	encodeDNS(t, remote.m)
}

func TestDNSProjectionRejectsForeignMissingGenerationsAndClientNamespace(t *testing.T) {
	d := newDNSFixture(t)
	before := encodeDNS(t, d.m)
	for _, mutate := range []func(*DNSConfig){func(c *DNSConfig) { c.Names = []DNSName{{"stolen", "private", 4}} }, func(c *DNSConfig) { c.Names[0].Generation++ }, func(c *DNSConfig) { c.Names[0].Endpoint = "missing" }, func(c *DNSConfig) { c.Names[0].Name = "spoof.clients.app.sfc.test." }, func(c *DNSConfig) { c.Names[0].Name = "outside.example." }, func(c *DNSConfig) { c.Names = append(c.Names, c.Names[0]) }, func(c *DNSConfig) { c.Upstreams = []netip.AddrPort{netip.MustParseAddrPort("10.42.0.1:53")} }, func(c *DNSConfig) { c.Members = []string{"private"} }, func(c *DNSConfig) { c.Source = 0 }} {
		cfg := ownDNSConfig(d.cfg)
		mutate(&cfg)
		q, e := d.m.Prepare(d.f.c, d.f.n, d.f.a, "admin", 0, cfg)
		if e == nil || !bytes.Equal(before, encodeDNS(t, q)) {
			t.Fatal("invalid projection partly published")
		}
	}
	for _, prefix := range []string{"10.42.0.0/25", "2001:db8::/63"} {
		if _, e := reverseZone(netip.MustParsePrefix(prefix)); e == nil {
			t.Fatal("unsupported reverse ownership")
		}
	}
	if z, e := reverseZone(netip.MustParsePrefix("2001:db8:43::/64")); e != nil || z != "0.0.0.0.3.4.0.0.8.b.d.0.1.0.0.2.ip6.arpa." {
		t.Fatal("IPv6 nibble reverse", z, e)
	}
}

func TestDNSViewCASStagesFullCandidateAndRechecksAddressBeforePublish(t *testing.T) {
	d := newDNSFixture(t)
	d = publishDNS(t, d, d.cfg, 190)
	original := encodeDNS(t, d.m)
	cfg := ownDNSConfig(d.cfg)
	cfg.Source++
	cfg.Serial++
	cfg.Names = []DNSName{{"only-six", "web-six", 3}}
	var e error
	d = grantDNS(t, d, cfg)
	d.m, e = d.m.Prepare(d.f.c, d.f.n, d.f.a, "admin", 100, cfg)
	if e != nil {
		t.Fatal(e)
	}
	_, out := askDNS(t, d, "web.app.sfc.test.", dns.TypeA, 200)
	if len(out.Response.Answer) != 1 {
		t.Fatal("pending source replaced LKG")
	}
	if _, e = d.m.Prepare(d.f.c, d.f.n, d.f.a, "admin", 100, cfg); e == nil {
		t.Fatal("pending source overwritten")
	}
	if _, e = d.m.Publish(d.f.c, d.f.n, d.f.a, "first", "dns", 100, d.clock(201)); e == nil {
		t.Fatal("late source accepted")
	}
	removed, _ := d.f.a.book.Allocation("web-six")
	changed, e := d.f.a.BeginStaticRetirement(d.f.c, d.f.n, "admin", d.f.a.Revision(), removed, 201)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = d.m.Publish(d.f.c, d.f.n, changed, "first", "dns", 101, d.clock(201)); e == nil {
		t.Fatal("address fenced after staging but view published")
	}
	d.m, e = d.m.Discard("first", "dns", 101)
	if e != nil {
		t.Fatal(e)
	}
	if d.m.Applied("first", "dns") != 100 {
		t.Fatal("discard lost LKG")
	}
	if bytes.Equal(original, encodeDNS(t, d.m)) {
		t.Fatal("discard erased desired source floor")
	}
}

func TestDNSViewOldRequestPinsAndHoldStartAfterLastCompletion(t *testing.T) {
	d := newDNSFixture(t)
	d.cfg.QuerySeconds = 60
	d = publishDNS(t, d, d.cfg, 190)
	old := d.m.current["first/dns"]
	d, h, raw := startDNS(t, d, "web.app.sfc.test.", dns.TypeA, 219)
	cfg := ownDNSConfig(d.cfg)
	cfg.Source++
	cfg.Serial++
	cfg.Names = []DNSName{{"web", "web-six", 3}}
	d = publishDNS(t, d, cfg, 220)
	out, e := d.m.Answer(d.f.c, d.f.n, d.f.a, h, raw, d.clock(250))
	if e != nil || len(out.Response.Answer) != 1 {
		t.Fatal("old query lost original view", e)
	}
	if _, e = d.m.Answer(d.f.c, d.f.n, d.f.a, h, dnsWire("different.app.sfc.test.", dns.TypeA), d.clock(250)); e == nil {
		t.Fatal("old pin accepted a new request")
	}
	alloc, _ := d.f.a.book.Allocation("web-four")
	if d.m.CanReleaseAddress(alloc) {
		t.Fatal("old query/address ref lost")
	}
	if _, e = d.m.Collect(old, d.clock(251)); e == nil {
		t.Fatal("active query discarded")
	}
	d.m, e = d.m.Release(h, d.clock(250))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = d.m.Collect(old, d.clock(251)); e == nil {
		t.Fatal("hold started at view switch, before last answer TTL")
	}
	if _, e = d.m.Release(h, d.clock(251)); e == nil {
		t.Fatal("late duplicate release")
	}
	d.m, e = d.m.Collect(old, d.clock(280))
	if e != nil {
		t.Fatal(e)
	}
	if !d.m.CanReleaseAddress(alloc) {
		t.Fatal("settled old address held forever")
	}
	encodeDNS(t, d.m)
}

func TestDNSViewRecoveryPreservesOriginalQueriesAndRejectsErasure(t *testing.T) {
	d := newDNSFixture(t)
	d = publishDNS(t, d, d.cfg, 190)
	d, h, _ := startDNS(t, d, "web.app.sfc.test.", dns.TypeA, 200)
	cfg := ownDNSConfig(d.cfg)
	cfg.Source++
	cfg.Serial++
	cfg.Names = []DNSName{{"web", "web-six", 3}}
	d = publishDNS(t, d, cfg, 201)
	raw := encodeDNS(t, d.m)
	m, e := DecodeDNSManager(raw)
	if e != nil || !bytes.Equal(raw, encodeDNS(t, m)) || len(m.Queries()) != 1 || m.Queries()[0].ID() != h.ID() {
		t.Fatal("lost original query", e)
	}
	if _, e = json.Marshal(h); e == nil {
		t.Fatal("opaque query silently encoded as empty JSON")
	}
	for _, mutate := range []func(*dnsSnapshot){func(s *dnsSnapshot) {
		for i := range s.Views {
			if len(s.Views[i].Origins) > 0 {
				s.Views[i].Origins = nil
			}
		}
	}, func(s *dnsSnapshot) { s.Views[0].Projection.Records[0].Allocation.Generation++ }, func(s *dnsSnapshot) { s.Scopes[0].Floor.Source = 1 }, func(s *dnsSnapshot) { s.Protected = nil }, func(s *dnsSnapshot) { s.Views = append(s.Views, s.Views[0]) }, func(s *dnsSnapshot) { s.Views[0].Pins.Active = nil }} {
		var s dnsSnapshot
		if json.Unmarshal(raw, &s) != nil {
			t.Fatal("fixture")
		}
		mutate(&s)
		bad, _ := json.Marshal(s)
		if _, e = DecodeDNSManager(bad); e == nil {
			t.Fatal("erased/mismatched view accepted")
		}
	}
}

func TestDNSForwardScopeInternalPrivacyAndConfiguredPeer(t *testing.T) {
	d := newDNSFixture(t)
	d = publishDNS(t, d, d.cfg, 190)
	for _, name := range []string{"secret.second.sfc.test.", "0.43.10.in-addr.arpa.", "missing.app.sfc.test."} {
		var out DNSResult
		d, out = askDNS(t, d, name, dns.TypeA, 200)
		if out.Forward != nil || out.Response == nil {
			t.Fatal("internal name sent upstream")
		}
	}
	foreign, _ := d.f.a.book.Allocation("private")
	if _, _, e := d.m.Acquire(d.f.c, d.f.n, d.f.a, "first", "dns", foreign, dnsWire("web.app.sfc.test.", dns.TypeA), d.clock(200)); e == nil {
		t.Fatal("foreign tenant source entered view")
	}
	d, h, raw := startDNS(t, d, "public.example.", dns.TypeA, 200)
	out, e := d.m.Answer(d.f.c, d.f.n, d.f.a, h, raw, d.clock(200))
	if e != nil || out.Forward == nil {
		t.Fatal("explicit upstream unavailable", e)
	}
	peer := out.Forward.Upstreams()[0]
	if _, e = out.Forward.Exchange(netip.MustParseAddrPort("1.1.1.1:53"), 1234); e == nil {
		t.Fatal("implicit upstream accepted")
	}
	x, e := out.Forward.Exchange(peer, 1234)
	if e != nil {
		t.Fatal(e)
	}
	q, e := x.Request()
	if e != nil || q.Id != 1234 || q.Question[0].Name != "public.example." {
		t.Fatal("unbound exchange", e)
	}
	response := new(dns.Msg)
	response.SetReply(q)
	response.Answer = []dns.RR{&dns.A{Hdr: header("public.example.", dns.TypeA, 60), A: net.IPv4(192, 0, 2, 9)}}
	answer, _ := response.Pack()
	r, e := d.m.FinishForward(d.f.c, d.f.n, d.f.a, x, peer, answer, d.clock(200))
	if e != nil || r.Id != 77 {
		t.Fatal("client ID restore", e)
	}
	if _, e = d.m.FinishForward(d.f.c, d.f.n, d.f.a, x, netip.MustParseAddrPort("1.1.1.1:53"), answer, d.clock(200)); e == nil {
		t.Fatal("foreign peer reply accepted")
	}
}

func TestDNSForwardRejectsWrongQuestionPrivateCNAMEAndExpiredWork(t *testing.T) {
	d := newDNSFixture(t)
	d = publishDNS(t, d, d.cfg, 190)
	d, h, raw := startDNS(t, d, "public.example.", dns.TypeA, 200)
	out, _ := d.m.Answer(d.f.c, d.f.n, d.f.a, h, raw, d.clock(200))
	peer := out.Forward.Upstreams()[0]
	x, _ := out.Forward.Exchange(peer, 1234)
	q, _ := x.Request()
	base := new(dns.Msg)
	base.SetReply(q)
	base.Answer = []dns.RR{&dns.A{Hdr: header("public.example.", dns.TypeA, 60), A: net.IPv4(192, 0, 2, 9)}}
	for _, mutate := range []func(*dns.Msg){func(m *dns.Msg) { m.Id++ }, func(m *dns.Msg) { m.Question[0].Name = "wrong.example." }, func(m *dns.Msg) { m.Truncated = true }, func(m *dns.Msg) {
		m.Answer = []dns.RR{&dns.CNAME{Hdr: header("public.example.", dns.TypeCNAME, 60), Target: "secret.sfc.test."}}
	}, func(m *dns.Msg) {
		m.Answer = append(m.Answer, &dns.A{Hdr: header("unrelated.example.", dns.TypeA, 60), A: net.IPv4(192, 0, 2, 8)})
	}, func(m *dns.Msg) {
		m.Answer = []dns.RR{&dns.CNAME{Hdr: header("public.example.", dns.TypeCNAME, 60), Target: "target.example."}, &dns.CNAME{Hdr: header("target.example.", dns.TypeCNAME, 60), Target: "public.example."}}
	}} {
		bad := base.Copy()
		mutate(bad)
		wire, _ := bad.Pack()
		if _, e := d.m.FinishForward(d.f.c, d.f.n, d.f.a, x, peer, wire, d.clock(200)); e == nil {
			t.Fatal("mismatched/poisoned upstream response")
		}
	}
	wire, _ := base.Pack()
	if _, e := d.m.FinishForward(d.f.c, d.f.n, d.f.a, x, peer, wire, d.clock(202)); e == nil {
		t.Fatal("expired query still responded")
	}
	var e error
	d.m, e = d.m.Release(h, d.clock(202))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = d.m.FinishForward(d.f.c, d.f.n, d.f.a, x, peer, wire, d.clock(202)); e == nil {
		t.Fatal("late reply after release")
	}
}

func TestDNSSerialIsSharedAcrossSkippedUpdatesAndWrap(t *testing.T) {
	d := newDNSFixture(t)
	d.cfg.Serial = ^uint32(0)
	d = publishDNS(t, d, d.cfg, 190)
	cfg := ownDNSConfig(d.cfg)
	cfg.Source = 200
	cfg.Serial = 0
	d = publishDNS(t, d, cfg, 200)
	_, out := askDNS(t, d, "app.sfc.test.", dns.TypeSOA, 201)
	if out.Response.Answer[0].(*dns.SOA).Serial != 0 || !SerialAfter(0, ^uint32(0)) || SerialAfter(1<<31, 0) {
		t.Fatal("serial sequence space")
	}
	stale := cfg
	stale.Source++
	stale.Serial = 1 << 31
	if _, e := d.m.Prepare(d.f.c, d.f.n, d.f.a, "admin", 200, stale); e == nil {
		t.Fatal("ambiguous half-space jump accepted")
	}
	// A second process skips earlier sources and consumes the committed serial,
	// rather than calculating how many views that particular process observed.
	other := newDNSFixture(t)
	cfg = ownDNSConfig(other.cfg)
	cfg.Source = 900
	cfg.Serial = 9
	other = publishDNS(t, other, cfg, 200)
	_, out = askDNS(t, other, "app.sfc.test.", dns.TypeSOA, 201)
	if out.Response.Answer[0].(*dns.SOA).Serial != 9 {
		t.Fatal("node-local serial counter")
	}
}

func TestDNSBudgetTruncationAndQueryCapacityHoldOldUsers(t *testing.T) {
	d := newDNSFixture(t)
	d.cfg.MaxResponseBytes = 512
	d.cfg.Names = nil
	for i := 20; i < 60; i++ {
		var e error
		endpoint := fmt.Sprintf("many-%d", i)
		d.f.a, _, e = d.f.a.ReserveStatic(endpoint, poolOwner(Source{Owner: pub(d.f.key)}), "first/lan", "first/lan/pool", uint64(i), addr(fmt.Sprintf("10.42.0.%d", i)))
		if e != nil {
			t.Fatal(e)
		}
		d.cfg.Names = append(d.cfg.Names, DNSName{"many", endpoint, uint64(i)})
	}
	d = publishDNS(t, d, d.cfg, 190)
	d, h, raw := startDNS(t, d, "many.app.sfc.test.", dns.TypeA, 200)
	out, e := d.m.Answer(d.f.c, d.f.n, d.f.a, h, raw, d.clock(200))
	wire, _ := out.Response.Pack()
	if e != nil || !out.Response.Truncated || len(wire) > 512 {
		t.Fatal("response budget ignored", len(wire), e)
	}
	d, _, _ = startDNS(t, d, "app.sfc.test.", dns.TypeSOA, 200)
	if _, _, e = d.m.Acquire(d.f.c, d.f.n, d.f.a, "first", "dns", d.origin, raw, d.clock(200)); !errors.Is(e, ErrDNSQueryCapacity) || !errors.Is(e, ErrProtocol) {
		t.Fatal("query capacity exceeded")
	}
	encodeDNS(t, d.m)
}

func TestDNSHoldCannotBeExpiredByRebootOrBackwardClock(t *testing.T) {
	d := newDNSFixture(t)
	d = publishDNS(t, d, d.cfg, 190)
	old := d.m.current["first/dns"]
	cfg := ownDNSConfig(d.cfg)
	cfg.Source++
	cfg.Serial++
	d = publishDNS(t, d, cfg, 200)
	unknown := d.clock(300)
	unknown.Boot = [32]byte{9}
	if _, e := d.m.Collect(old, unknown); e == nil {
		t.Fatal("reboot skipped TTL hold")
	}
	var e error
	d.m, e = d.m.RebaseHold(old, unknown)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = d.m.Collect(old, unknown); e == nil {
		t.Fatal("new boot expired hold immediately")
	}
	unknown.Wall += 30
	unknown.Mono += 30
	d.m, e = d.m.Collect(old, unknown)
	if e != nil {
		t.Fatal(e)
	}
	encodeDNS(t, d.m)
}

func TestDNSForwardCacheUsesOriginalSourceTTLsAndDropsOnRecovery(t *testing.T) {
	d := newDNSFixture(t)
	d = publishDNS(t, d, d.cfg, 190)
	d, h, raw := startDNS(t, d, "public.example.", dns.TypeA, 200)
	out, _ := d.m.Answer(d.f.c, d.f.n, d.f.a, h, raw, d.clock(200))
	peer := out.Forward.Upstreams()[0]
	x, _ := out.Forward.Exchange(peer, 1234)
	q, _ := x.Request()
	reply := new(dns.Msg)
	reply.SetReply(q)
	reply.Answer = []dns.RR{&dns.A{Hdr: header("public.example.", dns.TypeA, 60), A: net.IPv4(192, 0, 2, 9)}}
	wire, _ := reply.Pack()
	var e error
	d.m, _, e = d.m.CompleteForward(d.f.c, d.f.n, d.f.a, x, peer, wire, d.clock(200))
	if e != nil || d.m.CacheEntries() != 1 {
		t.Fatal(e)
	}
	d.m, e = d.m.Release(h, d.clock(200))
	if e != nil {
		t.Fatal(e)
	}
	_, out = askDNS(t, d, "public.example.", dns.TypeA, 210)
	if out.Forward != nil || out.Response.Answer[0].Header().Ttl != 20 || out.Response.Id != 77 {
		t.Fatal("cache extended original TTL", out)
	}
	_, out = askDNS(t, d, "public.example.", dns.TypeA, 230)
	if out.Forward == nil {
		t.Fatal("expired cache served")
	}
	copy, e := DecodeDNSManager(encodeDNS(t, d.m))
	if e != nil || copy.CacheEntries() != 0 {
		t.Fatal("volatile cache survived reboot", e)
	}
	cfg := ownDNSConfig(d.cfg)
	cfg.Source++
	cfg.Serial++
	d = publishDNS(t, d, cfg, 211)
	_, out = askDNS(t, d, "public.example.", dns.TypeA, 212)
	if out.Forward == nil {
		t.Fatal("old view cache reused under new source")
	}
}

func TestDNSNegativeCacheUsesSOAMinimumAndNoCrossTenantHit(t *testing.T) {
	d := newDNSFixture(t)
	d = publishDNS(t, d, d.cfg, 190)
	d, h, raw := startDNS(t, d, "absent.example.", dns.TypeA, 200)
	out, _ := d.m.Answer(d.f.c, d.f.n, d.f.a, h, raw, d.clock(200))
	peer := out.Forward.Upstreams()[0]
	x, _ := out.Forward.Exchange(peer, 1234)
	q, _ := x.Request()
	reply := new(dns.Msg)
	reply.SetReply(q)
	reply.Rcode = dns.RcodeNameError
	reply.Ns = []dns.RR{&dns.SOA{Hdr: header("example.", dns.TypeSOA, 100), Ns: "ns.example.", Mbox: "admin.example.", Minttl: 3}}
	wire, _ := reply.Pack()
	var e error
	d.m, _, e = d.m.CompleteForward(d.f.c, d.f.n, d.f.a, x, peer, wire, d.clock(200))
	if e != nil {
		t.Fatal(e)
	}
	d.m, e = d.m.Release(h, d.clock(200))
	if e != nil {
		t.Fatal(e)
	}
	_, out = askDNS(t, d, "absent.example.", dns.TypeA, 202)
	if out.Forward != nil || out.Response.Rcode != dns.RcodeNameError || out.Response.Ns[0].Header().Ttl != 1 {
		t.Fatal("negative TTL mismatch")
	}
	_, out = askDNS(t, d, "absent.example.", dns.TypeA, 203)
	if out.Forward == nil {
		t.Fatal("negative cache lived past SOA minimum")
	}
	other := d
	other.cfg = ownDNSConfig(d.cfg)
	other.cfg.Tenant = "second"
	other.cfg.Network = "private"
	other.cfg.Pool = "pool"
	other.cfg.Members = nil
	other.cfg.Names = []DNSName{{"secret", "private", 4}}
	other.cfg.Zone = "other.sfc.test."
	other.cfg.ClientZone = ""
	other.origin, _ = d.f.a.book.Allocation("private")
	other = publishDNS(t, other, other.cfg, 201)
	_, out = askDNS(t, other, "absent.example.", dns.TypeA, 202)
	if out.Forward == nil {
		t.Fatal("cross-tenant cache hit")
	}
	statuses := other.m.Views()
	slices.SortFunc(statuses, func(a, b DNSViewStatus) int { return int(a.Source) - int(b.Source) })
	if len(statuses) != 2 {
		t.Fatal("unexpected view ownership")
	}
}

func TestDNSForwardCNAMENegativeCacheAndNamespaceReclassification(t *testing.T) {
	d := newDNSFixture(t)
	d = publishDNS(t, d, d.cfg, 190)
	d, h, raw := startDNS(t, d, "public.example.", dns.TypeA, 200)
	out, _ := d.m.Answer(d.f.c, d.f.n, d.f.a, h, raw, d.clock(200))
	peer := out.Forward.Upstreams()[0]
	x, _ := out.Forward.Exchange(peer, 1234)
	q, _ := x.Request()
	reply := new(dns.Msg)
	reply.SetReply(q)
	reply.Rcode = dns.RcodeNameError
	reply.Answer = []dns.RR{&dns.CNAME{Hdr: header("public.example.", dns.TypeCNAME, 60), Target: "target.other.example."}}
	reply.Ns = []dns.RR{&dns.SOA{Hdr: header("other.example.", dns.TypeSOA, 100), Ns: "ns.other.example.", Mbox: "admin.other.example.", Minttl: 3}}
	wire, _ := reply.Pack()
	var e error
	d.m, _, e = d.m.CompleteForward(d.f.c, d.f.n, d.f.a, x, peer, wire, d.clock(200))
	if e != nil || d.m.CacheEntries() != 1 {
		t.Fatal("CNAME target's negative authority rejected", e)
	}
	out, e = d.m.Answer(d.f.c, d.f.n, d.f.a, h, raw, d.clock(201))
	if e != nil || out.Forward != nil || out.Response.Answer[0].Header().Ttl != 2 || out.Response.Ns[0].Header().Ttl != 2 {
		t.Fatal("CNAME negative cache exceeded SOA minimum", e)
	}
	newZone := ownDNSConfig(d.cfg)
	newZone.ID, newZone.Zone, newZone.ClientZone = "new-zone", "target.other.example.", ""
	newZone.Source = 101
	newZone.Names = []DNSName{{"inner", "web-four", 2}}
	d = grantDNS(t, d, newZone)
	d.m, e = d.m.Prepare(d.f.c, d.f.n, d.f.a, "admin", 0, newZone)
	if e != nil {
		t.Fatal(e)
	}
	out, e = d.m.Answer(d.f.c, d.f.n, d.f.a, h, raw, d.clock(201))
	if e != nil || out.Forward == nil {
		t.Fatal("cached CNAME exposed newly private namespace", e)
	}
	if _, e = d.m.FinishForward(d.f.c, d.f.n, d.f.a, x, peer, wire, d.clock(201)); e == nil {
		t.Fatal("inflight old reply bypassed current private namespace")
	}
	d.m, e = d.m.Release(h, d.clock(201))
	if e != nil {
		t.Fatal(e)
	}
	encodeDNS(t, d.m)
}

func TestDNSCacheBoundedEvictionAndUncertainClocks(t *testing.T) {
	d := newDNSFixture(t)
	d = publishDNS(t, d, d.cfg, 190)
	for i, name := range []string{"one.example.", "two.example.", "three.example."} {
		at := int64(200 + i)
		var h DNSQuery
		var raw []byte
		d, h, raw = startDNS(t, d, name, dns.TypeA, at)
		out, e := d.m.Answer(d.f.c, d.f.n, d.f.a, h, raw, d.clock(at))
		if e != nil || out.Forward == nil {
			t.Fatal(e)
		}
		peer := out.Forward.Upstreams()[0]
		x, _ := out.Forward.Exchange(peer, uint16(3000+i))
		q, _ := x.Request()
		reply := new(dns.Msg)
		reply.SetReply(q)
		reply.Answer = []dns.RR{&dns.A{Hdr: header(name, dns.TypeA, 60), A: net.IPv4(192, 0, 2, byte(i+1))}}
		wire, _ := reply.Pack()
		d.m, _, e = d.m.CompleteForward(d.f.c, d.f.n, d.f.a, x, peer, wire, d.clock(at))
		if e != nil || d.m.CacheEntries() > 2 {
			t.Fatal("unbounded cache", e)
		}
		d.m, e = d.m.Release(h, d.clock(at))
		if e != nil {
			t.Fatal(e)
		}
	}
	_, out := askDNS(t, d, "one.example.", dns.TypeA, 203)
	if out.Forward == nil {
		t.Fatal("oldest bounded entry not evicted")
	}
	d, h, raw := startDNS(t, d, "three.example.", dns.TypeA, 203)
	clock := d.clock(203)
	clock.Certain = false
	out, e := d.m.Answer(d.f.c, d.f.n, d.f.a, h, raw, clock)
	if e != nil || out.Forward == nil {
		t.Fatal("uncertain clock served cached TTL", e)
	}
	for _, now := range []Clock{{Boot: [32]byte{9}, Wall: 203, Mono: 203, Certain: true}, {Boot: d.f.boot, Wall: 199, Mono: 203, Certain: true}} {
		if _, hit := d.m.cached(h.view, dns.Question{Name: "three.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, 77, now); hit {
			t.Fatal("reboot/backward wall extended cache")
		}
	}
}

func TestDNSPublishCannotUseStaleTimeBeforeLastActiveCompletion(t *testing.T) {
	d := newDNSFixture(t)
	d = publishDNS(t, d, d.cfg, 190)
	d, _ = askDNS(t, d, "web.app.sfc.test.", dns.TypeA, 230)
	var e error
	d.m, e = DecodeDNSManager(encodeDNS(t, d.m))
	if e != nil {
		t.Fatal("last completion restore", e)
	}
	old := d.m.current["first/dns"]
	cfg := ownDNSConfig(d.cfg)
	cfg.Source++
	cfg.Serial++
	cfg.Names = []DNSName{{"web", "web-six", 3}}
	d = publishDNS(t, d, cfg, 211)
	if _, e := d.m.Collect(old, d.clock(241)); e == nil {
		t.Fatal("stale publication clock reclaimed before last active response TTL ended")
	}
	if _, e = d.m.RebaseHold(old, d.clock(211)); e == nil {
		t.Fatal("stale same-boot rebase bypassed last completion")
	}
	d.m, e = d.m.RebaseHold(old, d.clock(241))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = d.m.Collect(old, d.clock(260)); e == nil {
		t.Fatal("rebase did not preserve full hold")
	}
	d.m, e = d.m.Collect(old, d.clock(271))
	if e != nil {
		t.Fatal(e)
	}
	encodeDNS(t, d.m)
}
