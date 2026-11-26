// SPDX-License-Identifier: Apache-2.0

package services

import (
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

func TestDNSCacheSameSecondAdmissionRetainsNewestReply(t *testing.T) {
	for _, kind := range []string{"positive", "nxdomain", "nodata"} {
		t.Run(kind, func(t *testing.T) {
			d := newDNSFixture(t)
			d = publishDNS(t, d, d.cfg, 190)
			for i, name := range []string{"z.example.", "y.example.", "a.example."} {
				var h DNSQuery
				var raw []byte
				d, h, raw = startDNS(t, d, name, dns.TypeA, 200)
				out, err := d.m.Answer(d.f.c, d.f.n, d.f.a, h, raw, d.clock(200))
				if err != nil || out.Forward == nil {
					t.Fatal("expected original forward", err)
				}
				peer := out.Forward.Upstreams()[0]
				x, err := out.Forward.Exchange(peer, uint16(3000+i))
				if err != nil {
					t.Fatal(err)
				}
				q, err := x.Request()
				if err != nil {
					t.Fatal(err)
				}
				reply := new(dns.Msg)
				reply.SetReply(q)
				negative := i == 2 && kind != "positive"
				if negative {
					if kind == "nxdomain" {
						reply.Rcode = dns.RcodeNameError
					}
					reply.Ns = []dns.RR{&dns.SOA{Hdr: header("example.", dns.TypeSOA, 60), Ns: "ns.example.", Mbox: "admin.example.", Minttl: 60}}
				} else {
					reply.Answer = []dns.RR{addressRR(name, netip.MustParseAddr("192.0.2.9"), 60)}
				}
				wire, err := reply.Pack()
				if err != nil {
					t.Fatal(err)
				}
				before := d.m
				d.m, reply, err = d.m.CompleteForward(d.f.c, d.f.n, d.f.a, x, peer, wire, d.clock(200))
				if err != nil || d.m.CacheEntries() != min(i+1, 2) || before.CacheEntries() != min(i, 2) {
					t.Fatal("admission mutated original or exceeded cache budget", err)
				}
				wantTTL := d.cfg.TTL
				if negative {
					wantTTL = d.cfg.NegativeTTL
					if reply.Ns[0].(*dns.SOA).Minttl > wantTTL {
						t.Fatal("outgoing SOA exceeded negative TTL")
					}
				}
				for _, section := range [][]dns.RR{reply.Answer, reply.Ns} {
					for _, rr := range section {
						if rr.Header().Ttl > wantTTL {
							t.Fatal("outgoing reply exceeded configured TTL")
						}
					}
				}
				d.m, err = d.m.Release(h, d.clock(200))
				if err != nil {
					t.Fatal(err)
				}
				_, hit := d.m.cached(h.view, q.Question[0], 77, d.clock(200))
				if !hit {
					t.Fatalf("newly admitted %s %q evicted itself in same-second tie", kind, name)
				}
			}
		})
	}
}
