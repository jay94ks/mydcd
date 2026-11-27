// SPDX-License-Identifier: Apache-2.0

package services

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type dnsProtocolGate struct {
	entered, release chan struct{}
	once             sync.Once
}
type dnsProtocolUpstream struct {
	mu       sync.Mutex
	address  netip.AddrPort
	counts   map[string][2]int
	gates    map[string]*dnsProtocolGate
	value    atomic.Uint32
	udp, tcp *dns.Server
	done     []chan error
	ctx      context.Context
}

func openDNSProtocolUpstream(t *testing.T, ctx context.Context) *dnsProtocolUpstream {
	t.Helper()
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := net.Listen("tcp4", udp.LocalAddr().String())
	if err != nil {
		_ = udp.Close()
		t.Fatal(err)
	}
	u := &dnsProtocolUpstream{address: netip.MustParseAddrPort(udp.LocalAddr().String()), counts: map[string][2]int{}, gates: map[string]*dnsProtocolGate{}, ctx: ctx}
	u.value.Store(9)
	ready1, ready2 := make(chan struct{}), make(chan struct{})
	u.udp = &dns.Server{PacketConn: udp, Handler: dns.HandlerFunc(u.handle), NotifyStartedFunc: func() { close(ready1) }}
	u.tcp = &dns.Server{Listener: tcp, Handler: dns.HandlerFunc(u.handle), NotifyStartedFunc: func() { close(ready2) }}
	for _, s := range []*dns.Server{u.udp, u.tcp} {
		done := make(chan error, 1)
		u.done = append(u.done, done)
		go func() { done <- s.ActivateAndServe() }()
	}
	for _, ready := range []chan struct{}{ready1, ready2} {
		select {
		case <-ready:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	t.Cleanup(func() {
		u.mu.Lock()
		for _, g := range u.gates {
			g.once.Do(func() { close(g.release) })
		}
		u.mu.Unlock()
		clean, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = u.udp.ShutdownContext(clean)
		_ = u.tcp.ShutdownContext(clean)
		for _, done := range u.done {
			select {
			case e := <-done:
				if e != nil {
					t.Error(e)
				}
			case <-clean.Done():
				t.Error("upstream fixture Stop/Wait", clean.Err())
			}
		}
	})
	return u
}
func (u *dnsProtocolUpstream) block(name string) *dnsProtocolGate {
	u.mu.Lock()
	defer u.mu.Unlock()
	g := &dnsProtocolGate{entered: make(chan struct{}), release: make(chan struct{})}
	u.gates[name] = g
	return g
}
func (u *dnsProtocolUpstream) count(name string) [2]int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.counts[name]
}
func (u *dnsProtocolUpstream) handle(w dns.ResponseWriter, q *dns.Msg) {
	if len(q.Question) != 1 {
		return
	}
	name := q.Question[0].Name
	tcp := w.RemoteAddr().Network() == "tcp"
	u.mu.Lock()
	counts := u.counts[name]
	index := 0
	if tcp {
		index = 1
	}
	counts[index]++
	u.counts[name] = counts
	gate := u.gates[name]
	first := counts[0]+counts[1] == 1
	value := byte(u.value.Load())
	u.mu.Unlock()
	if gate != nil && first {
		close(gate.entered)
		select {
		case <-gate.release:
		case <-u.ctx.Done():
			return
		}
	}
	r := new(dns.Msg)
	r.SetReply(q)
	if !dns.IsSubDomain("public.example.", name) {
		r.Rcode = dns.RcodeNameError
		_ = w.WriteMsg(r)
		return
	}
	switch {
	case name == "fallback.public.example." || name == "oversize.public.example.":
		if !tcp {
			r.Truncated = true
			_ = w.WriteMsg(r)
			return
		}
		if name == "oversize.public.example." {
			_, _ = w.Write(make([]byte, 4097))
			return
		}
	case name == "wrong.public.example.":
		r.Question[0].Name = "unrelated.public.example."
	case name == "case.public.example.":
		r.Question[0].Name = strings.ToUpper(name)
	case name == "loop.public.example.":
		r.Answer = []dns.RR{&dns.CNAME{Hdr: header(name, dns.TypeCNAME, 4), Target: name}}
		_ = w.WriteMsg(r)
		return
	case name == "alias.public.example.":
		r.Answer = []dns.RR{&dns.CNAME{Hdr: header(name, dns.TypeCNAME, 4), Target: "hidden.tenant-private.example."}}
		_ = w.WriteMsg(r)
		return
	case name == "nxdomain.public.example." || name == "nodata.public.example.":
		if name == "nxdomain.public.example." {
			r.Rcode = dns.RcodeNameError
		}
		r.Ns = []dns.RR{&dns.SOA{Hdr: header("public.example.", dns.TypeSOA, 4), Ns: "ns.public.example.", Mbox: "hostmaster.public.example.", Serial: 1, Refresh: 10, Retry: 10, Expire: 60, Minttl: 4}}
		_ = w.WriteMsg(r)
		return
	}
	if q.Question[0].Qtype == dns.TypeAAAA {
		r.Answer = []dns.RR{addressRR(name, netip.MustParseAddr("2001:db8::99"), 4)}
	} else {
		n := 1
		if name == "bulk.public.example." {
			n = 45
		}
		for i := 0; i < n; i++ {
			r.Answer = append(r.Answer, addressRR(name, netip.AddrFrom4([4]byte{203, 0, 113, value + byte(i)}), 4))
		}
	}
	_ = w.WriteMsg(r)
}

func verifyDNSNativeProtocol(t *testing.T, ctx context.Context, o *DNSOwner, up *dnsProtocolUpstream, gateway, client netip.Addr, current func() DNSOwnerPolicy, replace func(DNSConfig), protect func([]string), deadline func(time.Duration)) {
	t.Helper()
	h := &http.Client{Timeout: 4 * time.Second, Transport: &http.Transport{Proxy: nil}}
	defer h.CloseIdleConnections()
	type result struct {
		message *dns.Msg
		raw     []byte
		err     error
	}
	ask := func(name string, kind uint16, protocol string, edns uint16, fragment bool) result {
		q := new(dns.Msg)
		q.SetQuestion(name, kind)
		if edns != 0 {
			q.SetEdns0(edns, false)
		}
		raw, e := q.Pack()
		if e != nil {
			return result{err: e}
		}
		url := "http://" + client.String() + ":8080/dns-query?server=" + netip.AddrPortFrom(gateway, 53).String() + "&transport=" + protocol
		if fragment {
			url += "&fragment=1&half_close=1"
		}
		req, e := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(raw))
		if e != nil {
			return result{err: e}
		}
		response, e := h.Do(req)
		if e != nil {
			return result{err: e}
		}
		wire, e := io.ReadAll(io.LimitReader(response.Body, 65536))
		_ = response.Body.Close()
		if e != nil {
			return result{err: e}
		}
		m := new(dns.Msg)
		if response.StatusCode != 200 || m.Unpack(wire) != nil || m.Id != q.Id {
			return result{raw: wire, err: ErrProtocol}
		}
		return result{m, wire, nil}
	}
	check := func(name string, kind uint16, protocol string, edns uint16, rcode, answers int, fragment bool) result {
		t.Helper()
		r := ask(name, kind, protocol, edns, fragment)
		if r.err != nil || r.message.Rcode != rcode || answers >= 0 && len(r.message.Answer) != answers {
			t.Fatal("native protocol", name, kind, protocol, edns, r.message, r.err, string(r.raw))
		}
		return r
	}
	for _, kind := range []uint16{dns.TypeSOA, dns.TypeNS} {
		check("app.sfc.test.", kind, "tcp", 0, dns.RcodeSuccess, 1, true)
	}
	check("probe.app.sfc.test.", dns.TypeA, "udp", 0, dns.RcodeSuccess, 1, false)
	check("probe.app.sfc.test.", dns.TypeAAAA, "udp", 1232, dns.RcodeSuccess, 0, false)
	reverse, e := dns.ReverseAddr(client.String())
	if e != nil {
		t.Fatal(e)
	}
	r := check(reverse, dns.TypePTR, "udp", 0, dns.RcodeSuccess, 1, false)
	if r.message.Answer[0].(*dns.PTR).Ptr != "probe.app.sfc.test." {
		t.Fatal("original committed PTR", r.message)
	}
	check("absent.app.sfc.test.", dns.TypeA, "udp", 0, dns.RcodeNameError, 0, false)
	before := up.count("absent.app.sfc.test.")
	if before != ([2]int{}) {
		t.Fatal("private NXDOMAIN was forwarded")
	}
	bulk := check("bulk.public.example.", dns.TypeA, "udp", 0, dns.RcodeSuccess, -1, false)
	if !bulk.message.Truncated || len(bulk.raw) > 512 {
		t.Fatal("plain UDP ignored 512-byte client", len(bulk.raw))
	}
	count := up.count("bulk.public.example.")
	for _, test := range []struct {
		protocol string
		size     uint16
		fragment bool
	}{{"udp", 1232, false}, {"udp", 65535, false}, {"tcp", 0, true}} {
		r = check("bulk.public.example.", dns.TypeA, test.protocol, test.size, dns.RcodeSuccess, 45, test.fragment)
		if r.message.Truncated || up.count("bulk.public.example.") != count || r.message.Answer[0].Header().Ttl > current().Config.TTL {
			t.Fatal("client truncation contaminated cache or configured TTL", r.message)
		}
	}
	timer := time.NewTimer(3200 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	check("bulk.public.example.", dns.TypeA, "tcp", 0, dns.RcodeSuccess, 45, false)
	if up.count("bulk.public.example.")[0] <= count[0] {
		t.Fatal("expired cache extended original TTL")
	}
	check("public.example.", dns.TypeAAAA, "tcp", 1232, dns.RcodeSuccess, 1, true)
	check("fallback.public.example.", dns.TypeA, "udp", 1232, dns.RcodeSuccess, 1, false)
	if c := up.count("fallback.public.example."); c[0] != 1 || c[1] != 1 {
		t.Fatal("upstream TCP fallback", c)
	}
	check("case.public.example.", dns.TypeA, "udp", 0, dns.RcodeSuccess, 1, false)
	for _, name := range []string{"wrong.public.example.", "loop.public.example.", "oversize.public.example."} {
		check(name, dns.TypeA, "tcp", 0, dns.RcodeServerFailure, 0, false)
	}
	protect([]string{"tenant-private.example."})
	check("hidden.tenant-private.example.", dns.TypeA, "udp", 0, dns.RcodeRefused, 0, false)
	if up.count("hidden.tenant-private.example.") != ([2]int{}) {
		t.Fatal("other tenant private name reached upstream")
	}
	check("alias.public.example.", dns.TypeA, "udp", 0, dns.RcodeServerFailure, 0, false)
	for _, name := range []string{"nxdomain.public.example.", "nodata.public.example."} {
		code := dns.RcodeSuccess
		if strings.HasPrefix(name, "nxdomain") {
			code = dns.RcodeNameError
		}
		r = check(name, dns.TypeA, "udp", 1232, code, 0, false)
		if len(r.message.Ns) != 1 || r.message.Ns[0].Header().Ttl > current().Config.NegativeTTL {
			t.Fatal("negative TTL", r.message)
		}
		before := up.count(name)
		check(name, dns.TypeA, "tcp", 0, code, 0, true)
		if after := up.count(name); after != before {
			t.Fatalf("negative cache miss for %s: upstream UDP/TCP before=%v after=%v", name, before, after)
		}
	}
	late := up.block("late.public.example.")
	out := make(chan result, 1)
	go func() { out <- ask("late.public.example.", dns.TypeA, "udp", 1232, false) }()
	select {
	case <-late.entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if o.Status("first", "dns").Queries != 1 {
		t.Fatal("in-flight query was not durably pinned")
	}
	protect([]string{"tenant-private.example.", "late.public.example."})
	late.once.Do(func() { close(late.release) })
	select {
	case r = <-out:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if r.err != nil || r.message.Rcode != dns.RcodeServerFailure {
		t.Fatal("late private namespace leaked", r.message, r.err)
	}
	slow := up.block("slow.public.example.")
	old := make(chan result, 1)
	go func() { old <- ask("slow.public.example.", dns.TypeA, "tcp", 0, true) }()
	select {
	case <-slow.entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	cfg := ownDNSConfig(current().Config)
	cfg.Source++
	cfg.Serial++
	replace(cfg)
	if e = o.Apply(ctx, "first", "dns"); e != nil {
		t.Fatal("hot original in-flight view", e)
	}
	up.value.Store(19)
	r = check("slow.public.example.", dns.TypeA, "udp", 1232, dns.RcodeSuccess, 1, false)
	if r.message.Answer[0].(*dns.A).A.String() != "203.0.113.19" {
		t.Fatal("new view used original cache")
	}
	slow.once.Do(func() { close(slow.release) })
	select {
	case r = <-old:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if r.err != nil || r.message.Answer[0].(*dns.A).A.String() != "203.0.113.9" {
		t.Fatal("old query borrowed newest view/peer result", r.message, r.err)
	}
	before = up.count("slow.public.example.")
	r = check("slow.public.example.", dns.TypeA, "tcp", 0, dns.RcodeSuccess, 1, false)
	if up.count("slow.public.example.") != before || r.message.Answer[0].(*dns.A).A.String() != "203.0.113.19" {
		t.Fatal("late original completion poisoned new view cache")
	}
	timeout := up.block("timeout.public.example.")
	deadline(250 * time.Millisecond)
	started := time.Now()
	check("timeout.public.example.", dns.TypeA, "tcp", 0, dns.RcodeServerFailure, 0, false)
	if elapsed := time.Since(started); elapsed < 150*time.Millisecond || elapsed > 1500*time.Millisecond {
		t.Fatal("declared ms deadline was inflated to seconds", elapsed)
	}
	timeout.once.Do(func() { close(timeout.release) })
	deadline(2 * time.Second)
	t.Log("actual nonroot wire client: owned DNS A/PTR/SOA/NS/negative + forwarded AAAA; UDP512/EDNS65535/TCP fragment+half-close; full per-view/negative cache+TTL, fallback, wrong question/CNAME loop/oversize and timeout SERVFAIL, private/late-private denial, original hot query/cache isolation")
}
