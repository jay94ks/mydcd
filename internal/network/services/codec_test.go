// SPDX-License-Identifier: Apache-2.0

package services

import (
	"testing"

	"github.com/miekg/dns"
)

func TestDNSLibraryQuerySubsetAndCanonicalNames(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("DB.App.MYDC.test.", dns.TypeA)
	raw, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	q, err := DecodeDNSQuery(raw, 4096)
	if err != nil || q.Question[0].Name != "db.app.mydc.test." {
		t.Fatal(err)
	}
	for _, change := range []func(*dns.Msg){func(v *dns.Msg) { v.Response = true }, func(v *dns.Msg) { v.Question = append(v.Question, v.Question[0]) }, func(v *dns.Msg) { v.Question[0].Qtype = dns.TypeANY }, func(v *dns.Msg) { v.Question[0].Qtype = dns.TypeAXFR }, func(v *dns.Msg) { v.Question[0].Qclass = dns.ClassCHAOS }} {
		var copy dns.Msg
		if copy.Unpack(raw) != nil {
			t.Fatal("fixture")
		}
		change(&copy)
		bad, err := copy.Pack()
		if err != nil {
			t.Fatal(err)
		}
		if _, err = DecodeDNSQuery(bad, 4096); err == nil {
			t.Fatal("unsupported query accepted")
		}
	}
	if _, err = DecodeDNSQuery(raw[:8], 4096); err == nil {
		t.Fatal("truncation accepted")
	}
	if _, err = Domain("bad\\name."); err == nil {
		t.Fatal("escaped name accepted")
	}
}
