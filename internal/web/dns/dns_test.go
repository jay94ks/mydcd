// SPDX-License-Identifier: Apache-2.0

package dns

import "testing"

func TestInRange(t *testing.T) {
	pats := []string{"shop", "*.shop"}
	for n, want := range map[string]bool{"shop": true, "a.shop": true, "b.a.shop": true, "*.shop": true, "xshop": false, "www": false, "@": false} {
		if InRange(n, pats) != want {
			t.Errorf("%s: want %v", n, want)
		}
	}
}

func TestCheckSet(t *testing.T) {
	ok := []RRSet{
		{Name: "@", Type: "A", TTL: 300, Records: []Record{{Content: "192.0.2.1"}}},
		{Name: "*.shop", Type: "AAAA", TTL: 300, Records: []Record{{Content: "2001:db8::1"}}},
		{Name: "_acme-challenge.shop", Type: "TXT", TTL: 60, Records: []Record{{Content: "abc"}}},
	}
	for _, r := range ok {
		if err := CheckSet(r, fakeCaps); err != nil {
			t.Errorf("%+v: %v", r, err)
		}
	}
	bad := []RRSet{
		{Name: "Shop", Type: "A", TTL: 300, Records: []Record{{Content: "192.0.2.1"}}},
		{Name: "a.*", Type: "A", TTL: 300, Records: []Record{{Content: "192.0.2.1"}}},
		{Name: "x", Type: "A", TTL: 10, Records: []Record{{Content: "192.0.2.1"}}},
		{Name: "x", Type: "A", TTL: 300, Records: []Record{{Content: "2001:db8::1"}}},
		{Name: "x", Type: "SRV", TTL: 300, Records: []Record{{Content: "x"}}},
		{Name: "x", Type: "CNAME", TTL: 300, Records: []Record{{Content: "a."}, {Content: "b."}}},
		{Name: "x", Type: "TXT", TTL: 300},
		{Name: "x.", Type: "TXT", TTL: 300, Records: []Record{{Content: "a"}}},
	}
	for _, r := range bad {
		if CheckSet(r, fakeCaps) == nil {
			t.Errorf("%+v accepted", r)
		}
	}
}

func TestFingerprintIgnoresOrder(t *testing.T) {
	a := &RRSet{Name: "shop", Type: "A", TTL: 300, Records: []Record{{Content: "192.0.2.1"}, {Content: "192.0.2.2"}}}
	b := &RRSet{Name: "shop", Type: "A", TTL: 300, Records: []Record{{Content: "192.0.2.2"}, {Content: "192.0.2.1"}}}
	if Fingerprint(a) != Fingerprint(b) {
		t.Fatal("order changed the fingerprint")
	}
	b.TTL = 60
	if Fingerprint(a) == Fingerprint(b) || Fingerprint(nil) != "absent" {
		t.Fatal("fingerprint misses a change")
	}
}
