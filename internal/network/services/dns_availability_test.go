// SPDX-License-Identifier: Apache-2.0

package services

import (
	"bytes"
	"testing"

	"github.com/miekg/dns"
)

func TestDNSAvailabilityFiltersOneReplicaWithoutChangingReservedView(t *testing.T) {
	d := newDNSFixture(t)
	d.cfg.Names = []DNSName{{Name: "web", Endpoint: "web-four", Generation: 2}, {Name: "web", Endpoint: "origin", Generation: 1}}
	d = publishDNS(t, d, d.cfg, 100)
	d, handle, raw := startDNS(t, d, "web.app.mydc.test.", dns.TypeA, 200)
	before := encodeDNS(t, d.m)
	result, err := d.m.Answer(d.f.c, d.f.n, d.f.a, handle, raw, d.clock(200), []DNSAddressReference{{Endpoint: "web-four", Generation: 2}})
	if err != nil || result.Response.Rcode != dns.RcodeSuccess || len(result.Response.Answer) != 1 {
		t.Fatal("one unavailable address disabled the healthy peer", err)
	}
	address, ok := result.Response.Answer[0].(*dns.A)
	if !ok || address.A.String() != "10.42.0.10" {
		t.Fatal("unavailable replica was returned")
	}
	result, err = d.m.Answer(d.f.c, d.f.n, d.f.a, handle, raw, d.clock(200), []DNSAddressReference{{Endpoint: "web-four", Generation: 3}})
	if err != nil || len(result.Response.Answer) != 2 {
		t.Fatal("another generation's availability replaced this exact address", err)
	}
	result, err = d.m.Answer(d.f.c, d.f.n, d.f.a, handle, raw, d.clock(200), []DNSAddressReference{{Endpoint: "web-four", Generation: 2}, {Endpoint: "origin", Generation: 1}})
	if err != nil || len(result.Response.Answer) != 0 || result.Response.Rcode != dns.RcodeSuccess {
		t.Fatal("unavailable reserved name was advertised as unowned or serving", err)
	}
	if !bytes.Equal(before, encodeDNS(t, d.m)) {
		t.Fatal("serving availability altered names, generations, references or query ownership")
	}
	if _, err = d.m.Answer(d.f.c, d.f.n, d.f.a, handle, raw, d.clock(200), []DNSAddressReference{{Endpoint: "web-four", Generation: 0}}); err == nil {
		t.Fatal("invalid filter accepted")
	}
}
