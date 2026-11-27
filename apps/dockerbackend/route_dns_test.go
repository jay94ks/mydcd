// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"testing"

	"github.com/miekg/dns"
)

func TestRouteDNSInvalidInputIsNotIsolationTimeout(t *testing.T) {
	for _, args := range [][]string{nil, {"sctp", "192.0.2.1:53", "apps.test."}, {"udp", "gateway:53", "apps.test."}, {"udp", "192.0.2.1:54", "apps.test."}, {"tcp", "0.0.0.0:53", "apps.test."}, {"udp", "192.0.2.1:53", "bad..zone"}} {
		if err := routeDNSProbe(args); err == nil || errors.Is(err, errRouteDNSTimeout) {
			t.Fatal("invalid input presented as network isolation", args, err)
		}
	}
}

func TestRouteDNSRequiresExactAuthoritativeSOA(t *testing.T) {
	query := new(dns.Msg)
	query.SetQuestion("near.sfc.test.", dns.TypeSOA)
	answer := new(dns.Msg)
	answer.SetReply(query)
	answer.Authoritative = true
	answer.Answer = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeSOA, Class: dns.ClassINET}}}
	if err := validateRouteDNSResponse(query, answer); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*dns.Msg){
		func(m *dns.Msg) { m.Id++ },
		func(m *dns.Msg) { m.Authoritative = false },
		func(m *dns.Msg) { m.Response = false },
		func(m *dns.Msg) { m.Truncated = true },
		func(m *dns.Msg) { m.Rcode = dns.RcodeNameError },
		func(m *dns.Msg) { m.Question[0].Name = "foreign.test." },
		func(m *dns.Msg) { m.Answer = nil },
		func(m *dns.Msg) { m.Answer[0].Header().Name = "foreign.test." },
	} {
		bad := answer.Copy()
		mutate(bad)
		if err := validateRouteDNSResponse(query, bad); err == nil || errors.Is(err, errRouteDNSTimeout) {
			t.Fatal("invalid DNS response presented as successful/denied query", bad, err)
		}
	}
}
