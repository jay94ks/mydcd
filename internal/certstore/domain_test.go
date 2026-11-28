// SPDX-License-Identifier: Apache-2.0

package certstore

import "testing"

func TestNormalizeDomainRefusesNonRegistrableNames(t *testing.T) {
	for in, want := range map[string]string{"Shop.Example.com.": "shop.example.com", "예시.한국": "xn--vv4b11d.xn--3e0b707e", "shop.co.kr": "shop.co.kr"} {
		if got, ok := NormalizeDomain(in); !ok || got != want {
			t.Fatalf("%q -> %q %v, want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "com", "co.kr", "localhost", "*.shop.example", "0.0.0.0", "::", "ff02::1", "fe80::1%eth0", "shop example.com", "a..b"} {
		if got, ok := NormalizeDomain(in); ok {
			t.Fatalf("%q accepted as %q", in, got)
		}
	}
	for in, want := range map[string]string{"192.0.2.1": "192.0.2.1", "::ffff:192.0.2.1": "192.0.2.1", "2001:DB8::1": "2001:db8::1", "::1": "::1"} {
		if got, ok := NormalizeDomain(in); !ok || got != want {
			t.Fatalf("IP %q -> %q %v, want %q", in, got, ok, want)
		}
	}
	if !DomainCovers("192.0.2.1", "192.0.2.1") || DomainCovers("192.0.2.1", "x.192.0.2.1") || DomainCovers("0.2.1", "192.0.2.1") || DomainCovers("192.0.2.1", "192.0.2.10") {
		t.Fatal("an IP entry covers only that address")
	}
	if DisplayDomain("xn--vv4b11d.xn--3e0b707e") != "예시.한국" {
		t.Fatal("unicode form")
	}
	if !DomainCovers("shop.example", "*.api.shop.example") || !DomainCovers("shop.example", "shop.example") || DomainCovers("shop.example", "myshop.example") {
		t.Fatal("covers")
	}
}

func TestDomainListUsesCatalogRevision(t *testing.T) {
	c := New([32]byte{1})
	c, err := c.AddDomain("shop.example", "admin", 0, 5)
	if err != nil || c.Revision != 1 {
		t.Fatal(err)
	}
	if _, err := c.AddDomain("shop.example", "admin", 1, 6); err == nil {
		t.Fatal("duplicate added")
	}
	if _, err := c.AddDomain("api.example", "admin", 0, 6); err == nil {
		t.Fatal("stale revision accepted")
	}
	if _, err := c.AddDomain("Shop2.example", "admin", 1, 6); err == nil {
		t.Fatal("unnormalized name accepted")
	}
	c, err = c.AddDomain("a.example", "admin", 1, 6)
	if err != nil || c.Domains[0].Name != "a.example" || c.Validate() != nil {
		t.Fatal("not sorted", err)
	}
	if _, err := c.RemoveDomain("b.example", 2); err == nil {
		t.Fatal("removed a missing domain")
	}
	c, err = c.RemoveDomain("a.example", 2)
	if err != nil || len(c.Domains) != 1 || c.Revision != 3 {
		t.Fatal(err)
	}
	c, _ = c.RemoveDomain("shop.example", 3)
	if c.Domains != nil || c.Validate() != nil {
		t.Fatal("empty list kept")
	}
}

func TestIPEntryLinksIPSANCertificate(t *testing.T) {
	c := New([32]byte{1})
	v, _, m := signedCertificate(t, 10, 900, 20, "192.0.2.7", "shop.example")
	defer m.Clear()
	c, err := c.Put(v, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.LookupHost("192.0.2.7", 30)) != 0 {
		t.Fatal("linked before the IP was registered")
	}
	if c, err = c.AddDomain("192.0.2.7", "admin", c.Revision, 30); err != nil {
		t.Fatal(err)
	}
	got := c.LookupHost("192.0.2.7", 30)
	if len(got) != 1 || got[0].Metadata.ID != v.Metadata.ID || len(c.LookupHost("shop.example", 30)) != 0 || len(c.LookupHost("192.0.2.8", 30)) != 0 {
		t.Fatal("IP entry must link exactly its address", got)
	}
	six, _, m6 := signedCertificate(t, 10, 900, 20, "2001:db8::5")
	defer m6.Clear()
	if c, err = c.Put(six, 30); err != nil {
		t.Fatal(err)
	}
	if c, err = c.AddDomain("2001:db8::5", "admin", c.Revision, 30); err != nil {
		t.Fatal(err)
	}
	if got := c.LookupHost("2001:DB8:0:0::5", 30); len(got) != 1 || got[0].Metadata.ID != six.Metadata.ID {
		t.Fatal("IPv6 host not compared in canonical form", got)
	}
}

func TestNormalizeResponder(t *testing.T) {
	for in, want := range map[string]string{"10.0.0.5:8402": "10.0.0.5:8402", "[::ffff:10.0.0.5]:80": "10.0.0.5:80", "[2001:DB8::5]:80": "[2001:db8::5]:80"} {
		if got, ok := NormalizeResponder(in); !ok || got != want {
			t.Fatalf("%q -> %q %v, want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "web:80", "10.0.0.5", "10.0.0.5:0", "0.0.0.0:80", "[::]:80", "[fe80::1%eth0]:80", "224.0.0.1:80"} {
		if got, ok := NormalizeResponder(in); ok {
			t.Fatalf("%q accepted as %q", in, got)
		}
	}
}

func TestDomainOwnersNestOnlyUnderClusterLevel(t *testing.T) {
	c := New([32]byte{1})
	c, err := c.AddDomain("example.com", "admin", 0, 5)
	if err != nil {
		t.Fatal(err)
	}
	if c, err = c.AddOwnedDomain("a.example.com", "alpha", "admin", 1, 6); err != nil {
		t.Fatal(err)
	}
	if _, err := c.AddOwnedDomain("x.a.example.com", "beta", "admin", 2, 7); err == nil {
		t.Fatal("other tenant nested under a tenant domain")
	}
	if _, err := c.AddDomain("x.a.example.com", "admin", 2, 7); err == nil {
		t.Fatal("cluster-level domain nested under a tenant domain")
	}
	if _, err := c.AssignDomain("example.com", "beta", 2); err == nil {
		t.Fatal("outer domain given to another tenant over a tenant domain")
	}
	if _, err := c.AddOwnedDomain("b.example.com", "Bad", "admin", 2, 7); err == nil {
		t.Fatal("invalid tenant id")
	}
	if c, err = c.AssignDomain("example.com", "alpha", 2); err != nil || c.Revision != 3 {
		t.Fatal("same tenant may own the outer domain", err)
	}
	if d, ok := c.DomainOwner("*.www.a.example.com"); !ok || d.Name != "a.example.com" {
		t.Fatal("longest match", d, ok)
	}
	if _, ok := c.DomainOwner("example.org"); ok {
		t.Fatal("unregistered host owned")
	}
	if got := c.TenantDomains("alpha"); len(got) != 2 || len(c.TenantDomains("")) != 0 {
		t.Fatal("tenant domains", got)
	}
	bad := c.Own()
	bad.Domains[1].Tenant = "beta"
	bad.Domains[0].Tenant = "alpha"
	if bad.Validate() == nil {
		t.Fatal("validate kept a cross-tenant nesting")
	}
}
