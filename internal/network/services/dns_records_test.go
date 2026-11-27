// SPDX-License-Identifier: Apache-2.0

package services

import (
	"slices"
	"strconv"
	"testing"

	"github.com/miekg/dns"
)

func TestValidDNSRecordsShape(t *testing.T) {
	zone := "apps.sfc.test."
	good := []DNSRecord{
		{Name: "www.apps.sfc.test.", Type: "CNAME", Value: "public.apps.sfc.test."},
		{Name: "legacy.apps.sfc.test.", Type: "A", Value: "192.0.2.7"},
		{Name: "legacy.apps.sfc.test.", Type: "A", Value: "192.0.2.8"},
		{Name: "docs.apps.sfc.test.", Type: "CNAME", Value: "example.org."},
		{Name: "legacy.apps.sfc.test.", Type: "AAAA", Value: "2001:db8::7"},
		{Name: "apps.apps.sfc.test.", Type: "TXT", Value: `"v=spf1 -all" "second; part"`},
		{Name: "mail.apps.sfc.test.", Type: "MX", Value: "10 mx.example.org.", TTL: 60},
		{Name: "_pg._tcp.apps.sfc.test.", Type: "SRV", Value: "10 5 5432 legacy.apps.sfc.test."},
		{Name: "legacy.apps.sfc.test.", Type: "CAA", Value: `0 issue "letsencrypt.org"`},
	}
	out, err := ValidDNSRecords(zone, "", good)
	if err != nil || len(out) != 9 || out[0].Name != "_pg._tcp.apps.sfc.test." {
		t.Fatal("good records", out, err)
	}
	for _, bad := range [][]DNSRecord{
		{{Name: "www", Type: "A", Value: "192.0.2.7"}},                                                                               // not a full name
		{{Name: "www.other.test.", Type: "A", Value: "192.0.2.7"}},                                                                   // outside the zone
		{{Name: "apps.sfc.test.", Type: "CNAME", Value: "example.org."}},                                                             // the zone itself
		{{Name: "ns.apps.sfc.test.", Type: "A", Value: "192.0.2.7"}},                                                                 // the name server
		{{Name: "www.apps.sfc.test.", Type: "A", Value: "2001:db8::1"}},                                                              // not IPv4
		{{Name: "www.apps.sfc.test.", Type: "A", Value: "0.0.0.0"}},                                                                  // unspecified
		{{Name: "www.apps.sfc.test.", Type: "A", Value: "224.0.0.1"}},                                                                // multicast
		{{Name: "www.apps.sfc.test.", Type: "NS", Value: "ns.example.org."}},                                                         // the zone's own type
		{{Name: "www.apps.sfc.test.", Type: "CNAME", Value: "www.apps.sfc.test."}},                                                   // itself
		{{Name: "www.apps.sfc.test.", Type: "CNAME", Value: "Example.org."}},                                                         // not canonical
		{{Name: "www.apps.sfc.test.", Type: "CNAME", Value: "a.test."}, {Name: "www.apps.sfc.test.", Type: "A", Value: "192.0.2.7"}}, // CNAME and A
		{{Name: "www.apps.sfc.test.", Type: "CNAME", Value: "a.test."}, {Name: "www.apps.sfc.test.", Type: "CNAME", Value: "b.test."}},
		{{Name: "www.apps.sfc.test.", Type: "A", Value: "192.0.2.7"}, {Name: "www.apps.sfc.test.", Type: "A", Value: "192.0.2.7"}},
	} {
		if _, err := ValidDNSRecords(zone, "", bad); err == nil {
			t.Fatal("accepted", bad)
		}
	}
	// ParseDNSRecord makes the value canonical; ValidDNSRecords wants it so.
	for _, c := range []struct{ in, want DNSRecord }{
		{DNSRecord{Name: "Mail.apps.sfc.test", Type: "MX", Value: "10 MX.Example.org"}, DNSRecord{Name: "mail.apps.sfc.test.", Type: "MX", Value: "10 mx.example.org."}},
		{DNSRecord{Name: "t.apps.sfc.test.", Type: "TXT", Value: `"hello world"`}, DNSRecord{Name: "t.apps.sfc.test.", Type: "TXT", Value: `"hello world"`}},
		{DNSRecord{Name: "x.apps.sfc.test.", Type: "AAAA", Value: "2001:DB8:0::1"}, DNSRecord{Name: "x.apps.sfc.test.", Type: "AAAA", Value: "2001:db8::1"}},
	} {
		got, _, err := ParseDNSRecord(c.in)
		if err != nil || got != c.want {
			t.Fatal("parse", c.in, got, err)
		}
		if _, err := ValidDNSRecords(zone, "", []DNSRecord{c.in}); err == nil && c.in != c.want {
			t.Fatal("non-canonical accepted", c.in)
		}
	}
	for _, bad := range []DNSRecord{
		{Name: "x.apps.sfc.test.", Type: "AAAA", Value: "::ffff:192.0.2.1"},
		{Name: "x.apps.sfc.test.", Type: "MX", Value: "70000 mx.example.org."},
		{Name: "x.apps.sfc.test.", Type: "SRV", Value: "1 2 x y."},
		{Name: "x.apps.sfc.test.", Type: "CAA", Value: `0 policy "x"`},
		{Name: "x.apps.sfc.test.", Type: "TXT", Value: "\"a\"\n\"b\""},
		{Name: "x.apps.sfc.test.", Type: "PTR", Value: "a.test."},
		{Name: "x.apps.sfc.test.", Type: "A", Value: "192.0.2.1", TTL: 3601},
	} {
		if _, _, err := ParseDNSRecord(bad); err == nil {
			t.Fatal("parsed", bad)
		}
	}
	if _, err := ValidDNSRecords(zone, "", []DNSRecord{{Name: "x.apps.sfc.test.", Type: "A", Value: "192.0.2.1", TTL: 5}, {Name: "x.apps.sfc.test.", Type: "A", Value: "192.0.2.2"}}); err == nil {
		t.Fatal("one set with two TTLs")
	}
	if _, err := ValidDNSRecords(zone, "", []DNSRecord{{Name: "x.apps.sfc.test.", Type: "CNAME", Value: "a.test."}, {Name: "x.apps.sfc.test.", Type: "TXT", Value: `"a"`}}); err == nil {
		t.Fatal("CNAME beside TXT")
	}
	if _, err := ValidDNSRecords(zone, "clients.apps.sfc.test.", []DNSRecord{{Name: "a.clients.apps.sfc.test.", Type: "A", Value: "192.0.2.7"}}); err == nil {
		t.Fatal("record in the client zone")
	}
	many := []DNSRecord{}
	for i := 0; i < 9; i++ {
		many = append(many, DNSRecord{Name: "many.apps.sfc.test.", Type: "A", Value: "192.0.2." + string(rune('1'+i))})
	}
	if _, err := ValidDNSRecords(zone, "", many); err == nil {
		t.Fatal("more than 8 addresses at one name")
	}
}

func TestManagedDNSServesHandRecords(t *testing.T) {
	f, definition, registrations := managedDNSFixture(t)
	definition.Policy.Records = []DNSRecord{
		{Name: "www.apps.sfc.test.", Type: "CNAME", Value: "alias.apps.sfc.test."},
		{Name: "alias.apps.sfc.test.", Type: "CNAME", Value: "public.apps.sfc.test."},
		{Name: "legacy.apps.sfc.test.", Type: "A", Value: "192.0.2.7"},
		{Name: "legacy.apps.sfc.test.", Type: "TXT", Value: `"hello"`, TTL: 3},
		{Name: "mail.apps.sfc.test.", Type: "MX", Value: "10 legacy.apps.sfc.test."},
		{Name: "apps.sfc.test.", Type: "TXT", Value: `"v=spf1 -all"`},
		{Name: "docs.apps.sfc.test.", Type: "CNAME", Value: "example.org."},
		{Name: "loop.apps.sfc.test.", Type: "CNAME", Value: "loop2.apps.sfc.test."},
		{Name: "loop2.apps.sfc.test.", Type: "CNAME", Value: "loop.apps.sfc.test."},
		// an app service has this name, so it waits
		{Name: "storage.apps.sfc.test.", Type: "A", Value: "192.0.2.9"},
	}
	served, shadowed, err := definition.Records(registrations)
	if err != nil || len(served) != 9 || len(shadowed) != 1 || shadowed[0].Name != "storage.apps.sfc.test." {
		t.Fatal("served/shadowed", served, shadowed, err)
	}
	plans, err := definition.Plans(f.c, f.n, f.a, "admin", 77, 4, registrations)
	if err != nil || len(plans) != 4 {
		t.Fatal("plans", len(plans), err)
	}
	plan := plans[0]
	if !slices.Equal(plan.Config.Records, served) {
		t.Fatal("plan records", plan.Config.Records)
	}
	m, err := NewDNSManager(f.n.Cluster(), plan.Owner, []string{"sfc.test."}, 8, 8)
	if err != nil {
		t.Fatal(err)
	}
	originEndpoint := "workload/task/first/sample/api/app/0"
	if plan.Node == "node-b" {
		originEndpoint = "workload/task/first/sample/database/app/0"
	}
	if plan.Config.Pool == "six" {
		originEndpoint = originEndpoint[:len(originEndpoint)-1] + "1"
	}
	origin, _ := f.a.AddressBook().Allocation(originEndpoint)
	d := dnsFixture{f: f, m: m, cfg: plan.Config, origin: origin}
	d = publishDNS(t, d, d.cfg, 190)
	// The records survive the owner's checkpoint.
	raw, err := d.m.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if d.m, err = DecodeDNSManager(raw); err != nil {
		t.Fatal("checkpoint with hand records", err)
	}
	text := func(r *dns.Msg) []string {
		var out []string
		for _, rr := range r.Answer {
			switch v := rr.(type) {
			case *dns.A:
				out = append(out, v.Hdr.Name+" A "+v.A.String())
			case *dns.CNAME:
				out = append(out, v.Hdr.Name+" CNAME "+v.Target)
			case *dns.TXT:
				out = append(out, v.Hdr.Name+" TXT "+v.Txt[0]+" "+strconv.Itoa(int(v.Hdr.Ttl)))
			case *dns.MX:
				out = append(out, v.Hdr.Name+" MX "+v.Mx+" "+strconv.Itoa(int(v.Hdr.Ttl)))
			default:
				out = append(out, rr.String())
			}
		}
		return out
	}
	for _, c := range []struct {
		name  string
		kind  uint16
		rcode int
		want  []string
		soa   bool
	}{
		{"legacy.apps.sfc.test.", dns.TypeA, dns.RcodeSuccess, []string{"legacy.apps.sfc.test. A 192.0.2.7"}, false},
		{"legacy.apps.sfc.test.", dns.TypeAAAA, dns.RcodeSuccess, nil, true},
		{"legacy.apps.sfc.test.", dns.TypeTXT, dns.RcodeSuccess, []string{"legacy.apps.sfc.test. TXT hello 3"}, false},
		{"mail.apps.sfc.test.", dns.TypeMX, dns.RcodeSuccess, []string{"mail.apps.sfc.test. MX legacy.apps.sfc.test. 30"}, false},
		{"www.apps.sfc.test.", dns.TypeA, dns.RcodeSuccess, []string{"www.apps.sfc.test. CNAME alias.apps.sfc.test.", "alias.apps.sfc.test. CNAME public.apps.sfc.test.", "public.apps.sfc.test. A 10.60.0.10"}, false},
		{"www.apps.sfc.test.", dns.TypeCNAME, dns.RcodeSuccess, []string{"www.apps.sfc.test. CNAME alias.apps.sfc.test."}, false},
		{"docs.apps.sfc.test.", dns.TypeA, dns.RcodeSuccess, []string{"docs.apps.sfc.test. CNAME example.org."}, false},
		{"loop.apps.sfc.test.", dns.TypeA, dns.RcodeSuccess, []string{"loop.apps.sfc.test. CNAME loop2.apps.sfc.test.", "loop2.apps.sfc.test. CNAME loop.apps.sfc.test."}, true},
		// the app's address, not the waiting hand record
		{"storage.apps.sfc.test.", dns.TypeA, dns.RcodeSuccess, []string{"storage.apps.sfc.test. A 10.61.0.10"}, false},
		{"nothing.apps.sfc.test.", dns.TypeA, dns.RcodeNameError, nil, true},
		{"apps.sfc.test.", dns.TypeTXT, dns.RcodeSuccess, []string{"apps.sfc.test. TXT v=spf1 -all 30"}, false},
	} {
		var answer DNSResult
		d, answer = askDNS(t, d, c.name, c.kind, 200)
		if answer.Response == nil {
			t.Fatal("no answer", c.name)
		}
		got := text(answer.Response)
		if answer.Response.Rcode != c.rcode || !slices.Equal(got, c.want) || (len(answer.Response.Ns) == 1) != c.soa {
			t.Fatalf("%s %s = rcode %d %v ns %d", c.name, dns.TypeToString[c.kind], answer.Response.Rcode, got, len(answer.Response.Ns))
		}
	}
	// A view whose records sit at a registered name, or are not canonical,
	// is refused.
	bad := plan.Config
	bad.Records = append(slices.Clone(bad.Records), DNSRecord{Name: "storage.apps.sfc.test.", Type: "A", Value: "192.0.2.9"})
	sortDNSRecords(bad.Records)
	if _, err := buildDNS(f.c, f.n, f.a, "admin", bad); err == nil {
		t.Fatal("record at a registered name accepted")
	}
	bad = plan.Config
	bad.Records = []DNSRecord{{Name: "x.apps.sfc.test.", Type: "A", Value: "192.0.2.7"}, {Name: "a.apps.sfc.test.", Type: "A", Value: "192.0.2.7"}}
	if _, err := buildDNS(f.c, f.n, f.a, "admin", bad); err == nil {
		t.Fatal("unsorted records accepted")
	}
}

func TestMoveDNSRecordsTakesTargetsInTheZone(t *testing.T) {
	in := []DNSRecord{
		{Name: "_pg._tcp.a.test.", Type: "SRV", Value: "10 5 5432 db.a.test."},
		{Name: "mail.a.test.", Type: "MX", Value: "10 mx.example.org."},
		{Name: "www.a.test.", Type: "CNAME", Value: "web.a.test.", TTL: 5},
	}
	got, err := MoveDNSRecords(in, "a.test.", "b.test.", "")
	want := []DNSRecord{
		{Name: "_pg._tcp.b.test.", Type: "SRV", Value: "10 5 5432 db.b.test."},
		{Name: "mail.b.test.", Type: "MX", Value: "10 mx.example.org."},
		{Name: "www.b.test.", Type: "CNAME", Value: "web.b.test.", TTL: 5},
	}
	if err != nil || !slices.Equal(got, want) {
		t.Fatal(got, err)
	}
}
