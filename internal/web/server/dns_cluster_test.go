// SPDX-License-Identifier: Apache-2.0

package server

import (
	"testing"
)

func domainRows(t *testing.T, f *fixture) map[string]map[string]any {
	t.Helper()
	code, out := f.do("GET", "/api/v1/dns/domains", nil)
	if code != 200 || out["cluster"] != true {
		t.Fatalf("domains: %d %v", code, out)
	}
	rows := map[string]map[string]any{}
	for _, it := range out["items"].([]any) {
		m := it.(map[string]any)
		rows[m["domain"].(string)] = m
	}
	return rows
}

func TestDNSClusterDomains(t *testing.T) {
	f, _, _ := dnsFixture(t)
	fakeLogin(t, f, "admin")
	rows := domainRows(t, f)
	if r := rows["shop.example.com"]; r == nil || r["provider"] != nil || r["registered"] != true || r["addedBy"] == "" {
		t.Fatalf("a registered domain without a provider: %v", rows)
	}
	for in, want := range map[string]string{"com": "public-suffix", "co.kr": "public-suffix", "bad domain": "invalid-domain", "*.example.org": "invalid-domain"} {
		if code, out := f.do("POST", "/api/v1/dns/domains", map[string]any{"domain": in}); code != 422 || errCode(out) != want {
			t.Fatalf("%s: %d %v", in, code, out)
		}
	}
	if code, out := f.do("POST", "/api/v1/dns/domains", map[string]any{"domain": "shop.example.com"}); code != 409 || errCode(out) != "exists" {
		t.Fatalf("registered twice: %d %v", code, out)
	}
	// the fixture's unlinked old.partner.example.net certificate gains a link
	if code, out := f.do("POST", "/api/v1/dns/domains", map[string]any{"domain": "Example.NET."}); code != 201 || out["domain"].(map[string]any)["registered"] != true || out["linked"] != float64(1) {
		t.Fatalf("register without provider: %d %v", code, out)
	}
	if r := domainRows(t, f)["example.net"]; r == nil || r["provider"] != nil || r["hosts"] != float64(1) || r["certificates"] != float64(1) {
		t.Fatalf("registered domain row: %v", r)
	}
	if code, out := f.do("GET", "/api/v1/dns/domains/example.net/records", nil); code != 409 || errCode(out) != "no-provider" {
		t.Fatalf("records without provider: %d %v", code, out)
	}

	// register and connect in one call
	_, out := f.do("POST", "/api/v1/dns/providers", map[string]any{"vendor": "fake", "name": "main", "token": "fake-token-1234"})
	id := out["provider"].(map[string]any)["id"].(string)
	_, out = f.do("GET", "/api/v1/dns/providers/"+id+"/domains", nil)
	for _, it := range out["items"].([]any) {
		if m := it.(map[string]any); m["name"] == "example.com" && (m["registered"] != false || m["connected"] != false) {
			t.Fatalf("import row: %v", m)
		}
	}
	if code, out := f.do("POST", "/api/v1/dns/domains", map[string]any{"domain": "example.com", "provider": id}); code != 201 {
		t.Fatalf("register with provider: %d %v", code, out)
	}
	if p, _ := domainRows(t, f)["example.com"]["provider"].(map[string]any); p == nil || p["id"] != id || p["vendor"] != "fake" {
		t.Fatalf("provider row: %v", p)
	}
	if code, _ := f.do("GET", "/api/v1/dns/domains/example.com/records", nil); code != 200 {
		t.Fatal("records with provider")
	}

	// deleting the provider keeps the domain registered
	if code, _ := f.do("DELETE", "/api/v1/dns/providers/"+id, nil); code != 204 {
		t.Fatal("delete provider in use")
	}
	if r := domainRows(t, f)["example.com"]; r == nil || r["provider"] != nil {
		t.Fatalf("after provider delete: %v", r)
	}
	_, out = f.do("POST", "/api/v1/dns/providers", map[string]any{"vendor": "fake", "name": "again", "token": "fake-token-5678"})
	id = out["provider"].(map[string]any)["id"].(string)
	if code, out := f.do("PUT", "/api/v1/dns/domains/example.com/provider", map[string]any{"provider": id}); code != 200 || out["domain"].(map[string]any)["provider"] == nil {
		t.Fatalf("attach: %d %v", code, out)
	}
	if code, out := f.do("PUT", "/api/v1/dns/domains/example.org/provider", map[string]any{"provider": id}); code != 404 {
		t.Fatalf("attach to an unregistered domain: %d %v", code, out)
	}
	if code, out := f.do("DELETE", "/api/v1/dns/domains/example.com/provider", nil); code != 200 || out["domain"].(map[string]any)["provider"] != nil {
		t.Fatalf("detach: %d %v", code, out)
	}
	if r := domainRows(t, f)["example.com"]; r == nil || r["provider"] != nil {
		t.Fatal("detach removed the domain")
	}

	if code, out := f.do("DELETE", "/api/v1/dns/domains/example.net", nil); code != 200 || out["unlinkedHosts"] != float64(1) || out["unlinkedCertificates"] != float64(1) {
		t.Fatalf("remove: %d %v", code, out)
	}
	if domainRows(t, f)["example.net"] != nil {
		t.Fatal("removed domain still listed")
	}
	if code, _ := f.do("DELETE", "/api/v1/dns/domains/example.net", nil); code != 404 {
		t.Fatal("remove twice")
	}

	f.do("POST", "/api/v1/auth/logout", nil)
	fakeLogin(t, f, "alice")
	if len(domainRows(t, f)) != 0 {
		t.Fatal("alice sees domains with no assignment")
	}
	if code, _ := f.do("POST", "/api/v1/dns/domains", map[string]any{"domain": "example.biz"}); code != 403 {
		t.Fatal("non-admin registered a domain")
	}
}
