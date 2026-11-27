// SPDX-License-Identifier: Apache-2.0

package services

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sys/unix"
)

// E4 final boundary bundle: the configured response limit is independent of
// the 4096-byte request limit. UDP must additionally fit an IPv4 datagram.
func TestDNSReplyLargeConfiguredBudgetRespectsUDPAndTCPFraming(t *testing.T) {
	request := new(dns.Msg)
	request.SetQuestion("large.public.example.", dns.TypeTXT)
	request.SetEdns0(65535, false)
	raw, err := request.Pack()
	if err != nil {
		t.Fatal(err)
	}
	response := new(dns.Msg)
	response.SetReply(request)
	for i := 0; i < 270; i++ {
		response.Answer = append(response.Answer, &dns.TXT{Hdr: header(request.Question[0].Name, dns.TypeTXT, 20), Txt: []string{strings.Repeat("x", 255)}})
	}
	original, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	for _, tcp := range []bool{false, true} {
		maximum := 65507
		if tcp {
			maximum = 65535
		}
		wire, err := EncodeDNSReply(raw, response, tcp, 65535)
		if err != nil || len(wire) <= 4096 || len(wire) > maximum {
			t.Fatal("large configured response", tcp, len(wire), err)
		}
		decoded := new(dns.Msg)
		if decoded.Unpack(wire) != nil || !decoded.Truncated || decoded.Id != request.Id {
			t.Fatal("large response framing", tcp)
		}
		if tcp {
			frame := make([]byte, 2+len(wire))
			binary.BigEndian.PutUint16(frame, uint16(len(wire)))
			copy(frame[2:], wire)
			got, err := ReadDNSTCPFrame(bytes.NewReader(frame), 65535)
			if err != nil || !bytes.Equal(got, wire) {
				t.Fatal("large TCP length framing", err)
			}
		}
		after, err := json.Marshal(response)
		if err != nil || !bytes.Equal(original, after) {
			t.Fatal("transport budget mutated original/cache")
		}
	}
}

func TestDNSReplyTransportBudgetDoesNotTruncateCacheOrEchoOPT(t *testing.T) {
	request := new(dns.Msg)
	request.SetQuestion("many.public.example.", dns.TypeA)
	response := new(dns.Msg)
	response.SetReply(request)
	for i := 1; i <= 70; i++ {
		response.Answer = append(response.Answer, &dns.A{Hdr: header(request.Question[0].Name, dns.TypeA, 20), A: net.IPv4(192, 0, 2, byte(i))})
	}
	original, _ := response.Pack()
	for _, test := range []struct {
		name      string
		tcp       bool
		edns      uint16
		max       int
		truncated bool
	}{{"plain-udp", false, 0, 512, true}, {"small-edns", false, 256, 512, true}, {"edns-1232", false, 1232, 1232, false}, {"large-edns", false, 65535, 4096, false}, {"tcp-plain", true, 0, 4096, false}, {"tcp-small-edns", true, 512, 4096, false}} {
		t.Run(test.name, func(t *testing.T) {
			q := request.Copy()
			if test.edns != 0 {
				q.SetEdns0(test.edns, false)
			}
			raw, _ := q.Pack()
			wire, err := EncodeDNSReply(raw, response, test.tcp, 4096)
			if err != nil || len(wire) > test.max {
				t.Fatal("transport budget", len(wire), err)
			}
			m := new(dns.Msg)
			if m.Unpack(wire) != nil || m.Truncated != test.truncated || m.Id != q.Id {
				t.Fatal("reply framing/TC", m)
			}
			opt := m.IsEdns0()
			if (opt == nil) != (test.edns == 0) || opt != nil && (opt.UDPSize() != 4096 || len(opt.Option) != 0) {
				t.Fatal("per-transaction EDNS", opt)
			}
			after, _ := response.Pack()
			if !bytes.Equal(original, after) {
				t.Fatal("client truncation mutated original/cache")
			}
		})
	}
}

func TestDNSTCPFrameLengthIsCheckedBeforeBodyAndHandlesFragments(t *testing.T) {
	raw := dnsWire("web.app.sfc.test.", dns.TypeA)
	frame := make([]byte, 2+len(raw))
	binary.BigEndian.PutUint16(frame, uint16(len(raw)))
	copy(frame[2:], raw)
	got, err := ReadDNSTCPFrame(iotest.OneByteReader(bytes.NewReader(frame)), 4096)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatal("fragmented frame", err)
	}
	for _, n := range []uint16{0, 11, 4097, 65535} {
		var h [2]byte
		binary.BigEndian.PutUint16(h[:], n)
		r := bytes.NewReader(append(h[:], bytes.Repeat([]byte{1}, 32)...))
		if _, err = ReadDNSTCPFrame(r, 4096); err == nil || r.Len() != 32 {
			t.Fatal("oversized frame consumed/allocated body", n, r.Len(), err)
		}
	}
	if _, err = ReadDNSTCPFrame(bytes.NewReader(frame[:len(frame)-1]), 4096); err == nil {
		t.Fatal("partial body accepted")
	}
}

func TestDNSNativeTTLHoldRoundsEventUpAndElapsedDown(t *testing.T) {
	boot := [32]byte{5}
	start := dnsEventClock(boot, time.Unix(100, 950000000), unix.Timespec{Sec: 200, Nsec: 950000000}, true, true)
	tooSoon := dnsEventClock(boot, time.Unix(101, 20000000), unix.Timespec{Sec: 201, Nsec: 20000000}, false, true)
	if age, ok := elapsed(start, tooSoon); !ok || age != 0 {
		t.Fatal("70ms became a whole TTL second", age, ok)
	}
	safe := dnsEventClock(boot, time.Unix(102, 0), unix.Timespec{Sec: 202}, false, true)
	if age, ok := elapsed(start, safe); !ok || age != 1 {
		t.Fatal("conservative TTL did not become releasable", age, ok)
	}
}

func TestDNSUpstreamEDNSBelongsToOriginalViewAndPrivateReclassification(t *testing.T) {
	d := newDNSFixture(t)
	d = publishDNS(t, d, d.cfg, 190)
	q := new(dns.Msg)
	q.SetQuestion("becomes.private.example.", dns.TypeA)
	q.SetEdns0(65535, false)
	raw, _ := q.Pack()
	var h DNSQuery
	var err error
	d.m, h, err = d.m.Acquire(d.f.c, d.f.n, d.f.a, "first", "dns", d.origin, raw, d.clock(200))
	if err != nil {
		t.Fatal(err)
	}
	answer, err := d.m.Answer(d.f.c, d.f.n, d.f.a, h, raw, d.clock(200))
	if err != nil || answer.Forward == nil {
		t.Fatal(err)
	}
	x, err := answer.Forward.Exchange(d.cfg.Upstreams[0], 1234)
	if err != nil {
		t.Fatal(err)
	}
	request, err := x.Request()
	if err != nil || request.IsEdns0() == nil || request.IsEdns0().UDPSize() != uint16(d.cfg.MaxResponseBytes) {
		t.Fatal("upstream inherited client's oversized EDNS", err)
	}
	r := new(dns.Msg)
	r.SetReply(request)
	r.Answer = []dns.RR{addressRR(request.Question[0].Name, addr("192.0.2.3"), 30)}
	wire, _ := r.Pack()
	d.m, err = d.m.ProtectZones([]string{"private.example."})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = d.m.CompleteForward(d.f.c, d.f.n, d.f.a, x, d.cfg.Upstreams[0], wire, d.clock(201)); err == nil {
		t.Fatal("new private namespace leaked from original in-flight view")
	}
	if len(d.m.Queries()) != 1 || d.m.CacheEntries() != 0 {
		t.Fatal("refused response returned original pin or poisoned cache")
	}
	d.m, err = d.m.Release(h, d.clock(201))
	if err != nil {
		t.Fatal(err)
	}
}
