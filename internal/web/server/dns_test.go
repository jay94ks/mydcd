// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/web/dns"
	"github.com/jay94ks/seafield/internal/web/seal"
	"github.com/jay94ks/seafield/internal/web/sfc"
)

func dnsFixture(t *testing.T) (*fixture, *dns.FakeWorld, *seal.Box) {
	f, _ := newFakeFixture(t)
	world := dns.NewFakeWorld()
	reg := &dns.Registry{}
	reg.Register(dns.FakeVendor(world))
	reg.Register(dns.Vendor{Info: dns.ProviderInfo{ID: "later", Name: "Later DNS"}}) // listed, not ready
	box, _ := seal.Open(t.TempDir(), bytes.Repeat([]byte{3}, seal.KeySize))
	f.srv.opt.DNS, f.srv.opt.Seal = reg, box
	return f, world, box
}

func TestDNSProvidersAndDomains(t *testing.T) {
	f, _, box := dnsFixture(t)
	fakeLogin(t, f, "admin")
	_, out := f.do("GET", "/api/v1/dns/vendors", nil)
	vs := out["items"].([]any)
	if len(vs) != 2 || vs[0].(map[string]any)["ready"] != true || vs[1].(map[string]any)["ready"] != false {
		t.Fatalf("vendors: %v", vs)
	}
	if code, out := f.do("POST", "/api/v1/dns/providers", map[string]any{"vendor": "fake", "name": "x", "token": "wrong-token-1"}); code != 502 || errCode(out) != "dns-auth-failed" {
		t.Fatalf("bad token: %d %v", code, out)
	}
	if code, _ := f.do("POST", "/api/v1/dns/providers", map[string]any{"vendor": "later", "name": "h", "token": "abcdefgh1234"}); code != 422 {
		t.Fatalf("not-ready vendor: %d", code)
	}
	code, out := f.do("POST", "/api/v1/dns/providers", map[string]any{"vendor": "fake", "name": "main", "token": "fake-token-secret-9876"})
	if code != 201 {
		t.Fatalf("add provider: %d %v", code, out)
	}
	p := out["provider"].(map[string]any)
	id := p["id"].(string)
	if p["tokenHint"] != "…9876" || p["lastCheckOk"] != true || strings.Contains(mustString(out), "secret") {
		t.Fatalf("provider row: %v", out)
	}
	if v, err := box.Get("dns-" + id); err != nil || string(v) != "fake-token-secret-9876" {
		t.Fatalf("sealed token: %q %v", v, err)
	}
	_, out = f.do("GET", "/api/v1/dns/providers/"+id+"/domains", nil)
	if s := mustString(out); !strings.Contains(s, `"hasZone":false,"name":"other.org"`) {
		t.Fatalf("domains: %s", s)
	}
	if code, out := f.do("POST", "/api/v1/dns/domains", map[string]any{"domain": "other.org", "provider": id}); code != 409 || errCode(out) != "zone-elsewhere" {
		t.Fatalf("zone elsewhere: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/dns/domains", map[string]any{"domain": "example.com", "provider": id,
		"assignments": []map[string]any{{"tenant": "shop", "names": []string{"shop", "*.shop"}}}}); code != 201 {
		t.Fatalf("add domain: %d %v", code, out)
	}
	if code, _ := f.do("POST", "/api/v1/dns/domains", map[string]any{"domain": "example.com", "provider": id}); code != 409 {
		t.Fatal("domain added twice")
	}
	// the check fails after a bad token replacement and keeps the old token
	if code, _ := f.do("PUT", "/api/v1/dns/providers/"+id+"/token", map[string]any{"token": "fake-expired"}); code != 502 {
		t.Fatalf("bad replacement accepted: %d", code)
	}
	if v, _ := box.Get("dns-" + id); string(v) != "fake-token-secret-9876" {
		t.Fatal("bad replacement overwrote the token")
	}
	// alice (not admin) cannot manage providers
	f.do("POST", "/api/v1/auth/logout", nil)
	fakeLogin(t, f, "alice")
	if code, _ := f.do("GET", "/api/v1/dns/providers", nil); code != 403 {
		t.Fatal("non-admin listed providers")
	}
	_, out = f.do("GET", "/api/v1/dns/domains", nil)
	ds := out["items"].([]any)
	if len(ds) != 1 || ds[0].(map[string]any)["myNames"] == nil {
		t.Fatalf("alice domains: %v", ds)
	}
}

func mustString(v any) string { return string(mustJSON(v)) }

func addExampleDomain(t *testing.T, f *fixture) {
	t.Helper()
	fakeLogin(t, f, "admin")
	_, out := f.do("POST", "/api/v1/dns/providers", map[string]any{"vendor": "fake", "name": "main", "token": "fake-token-1234"})
	id := out["provider"].(map[string]any)["id"].(string)
	if code, out := f.do("POST", "/api/v1/dns/domains", map[string]any{"domain": "example.com", "provider": id,
		"assignments": []map[string]any{{"tenant": "shop", "names": []string{"shop", "*.shop"}}}}); code != 201 {
		t.Fatalf("add domain: %d %v", code, out)
	}
	f.do("POST", "/api/v1/auth/logout", nil)
}

func basisOf(t *testing.T, out map[string]any) map[string]string {
	t.Helper()
	b := map[string]string{}
	cs, ok := out["changes"].([]any)
	if !ok {
		t.Fatalf("no changes: %v", out)
	}
	for _, c := range cs {
		m := c.(map[string]any)
		b[m["name"].(string)+"|"+m["type"].(string)] = m["fingerprint"].(string)
	}
	return b
}

func TestDNSPlanApplyInRange(t *testing.T) {
	f, world, _ := dnsFixture(t)
	addExampleDomain(t, f)
	fakeLogin(t, f, "alice")
	shopA := map[string]any{"name": "shop", "type": "A", "records": []map[string]any{{"content": "203.0.113.10"}, {"content": "203.0.113.11"}}}
	if code, out := f.do("POST", "/api/v1/dns/domains/example.com/plan", map[string]any{"upsert": []any{map[string]any{"name": "www", "type": "A", "records": []map[string]any{{"content": "203.0.113.1"}}}}}); code != 403 || errCode(out) != "out-of-range" {
		t.Fatalf("out of range planned: %d %v", code, out)
	}
	if code, _ := f.do("POST", "/api/v1/dns/domains/example.com/plan", map[string]any{"upsert": []any{map[string]any{"name": "shop", "type": "A", "records": []map[string]any{{"content": "not-ip"}}}}}); code != 422 {
		t.Fatal("bad address planned")
	}
	code, plan := f.do("POST", "/api/v1/dns/domains/example.com/plan", map[string]any{"upsert": []any{shopA}})
	if code != 200 || len(plan["problems"].([]any)) != 0 {
		t.Fatalf("plan: %d %v", code, plan)
	}
	// a manager cannot file the change under another workspace
	if code, out := f.do("POST", "/api/v1/dns/domains/example.com/apply", map[string]any{"opId": opB, "upsert": []any{shopA}, "basis": basisOf(t, plan), "tenant": "payments"}); code != 403 || world.Applies() != 0 {
		t.Fatalf("foreign tenant accepted: %d %v", code, out)
	}
	body := map[string]any{"opId": opA, "upsert": []any{shopA}, "basis": basisOf(t, plan), "app": "php-shop"}
	code, out := f.do("POST", "/api/v1/dns/domains/example.com/apply", body)
	if code != 200 || out["history"].(map[string]any)["result"] != "applied" || out["history"].(map[string]any)["tenant"] != "shop" {
		t.Fatalf("apply: %d %v", code, out)
	}
	// the same opId does not apply again
	if code, out := f.do("POST", "/api/v1/dns/domains/example.com/apply", body); code != 200 || out["history"].(map[string]any)["result"] != "applied" || world.Applies() != 1 {
		t.Fatalf("retry: %d %v applies=%d", code, out, world.Applies())
	}
	// alice sees only her range, marked managed
	_, out = f.do("GET", "/api/v1/dns/domains/example.com/records", nil)
	items := out["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["managed"].(map[string]any)["app"] != "php-shop" || items[0].(map[string]any)["writable"] != true {
		t.Fatalf("alice records: %v", items)
	}

	// changed elsewhere between plan and apply: nothing is applied
	_, plan = f.do("POST", "/api/v1/dns/domains/example.com/plan", map[string]any{"delete": []any{map[string]any{"name": "shop", "type": "A"}}})
	world.SetRecord("example.com", dns.RRSet{Name: "shop", Type: "A", TTL: 300, Records: []dns.Record{{Content: "192.0.2.9"}}})
	code, out = f.do("POST", "/api/v1/dns/domains/example.com/apply", map[string]any{"opId": opB, "delete": []any{map[string]any{"name": "shop", "type": "A"}}, "basis": basisOf(t, plan)})
	if code != 409 || errCode(out) != "zone-changed" || world.Applies() != 1 {
		t.Fatalf("stale apply: %d %v", code, out)
	}

	// revert of the first change gives a request that deletes shop A again
	code, out = f.do("POST", "/api/v1/dns/domains/example.com/history/"+opA+"/revert", nil)
	if code != 200 || len(out["request"].(map[string]any)["delete"].([]any)) != 1 {
		t.Fatalf("revert: %d %v", code, out)
	}
	_, out = f.do("GET", "/api/v1/dns/domains/example.com/history", nil)
	if len(out["items"].([]any)) != 1 {
		t.Fatalf("history: %v", out)
	}
}

func TestDNSAdminOutsideAndValidation(t *testing.T) {
	f, world, _ := dnsFixture(t)
	addExampleDomain(t, f)
	fakeLogin(t, f, "admin")
	mx := map[string]any{"name": "@", "type": "MX", "records": []map[string]any{{"content": "mx2.example.com.", "priority": 20}}}
	if code, out := f.do("POST", "/api/v1/dns/domains/example.com/plan", map[string]any{"upsert": []any{mx}}); code != 409 || errCode(out) != "outside" {
		t.Fatalf("outside without confirm: %d %v", code, out)
	}
	code, plan := f.do("POST", "/api/v1/dns/domains/example.com/plan", map[string]any{"upsert": []any{mx}, "outside": true})
	if code != 200 {
		t.Fatalf("outside plan: %d %v", code, plan)
	}
	if code, out := f.do("POST", "/api/v1/dns/domains/example.com/apply", map[string]any{"opId": opA, "upsert": []any{mx}, "outside": true, "basis": basisOf(t, plan)}); code != 200 || out["history"].(map[string]any)["snapshot"] == "" {
		t.Fatalf("outside apply: %d %v", code, out)
	}
	// admin records view marks outside records
	_, out := f.do("GET", "/api/v1/dns/domains/example.com/records", nil)
	for _, it := range out["items"].([]any) {
		m := it.(map[string]any)
		if m["outside"] != true || m["managed"] != nil {
			t.Fatalf("outside record shown as Seafield Cluster's: %v", m)
		}
	}
	// provider validation: a CNAME next to an A record
	world.SetRecord("example.com", dns.RRSet{Name: "shop", Type: "A", TTL: 300, Records: []dns.Record{{Content: "192.0.2.9"}}})
	cname := map[string]any{"name": "shop", "type": "CNAME", "records": []map[string]any{{"content": "example.com."}}}
	_, plan = f.do("POST", "/api/v1/dns/domains/example.com/plan", map[string]any{"upsert": []any{cname}})
	if len(plan["problems"].([]any)) != 1 {
		t.Fatalf("validation: %v", plan)
	}
	if code, _ := f.do("POST", "/api/v1/dns/domains/example.com/apply", map[string]any{"opId": opB, "upsert": []any{cname}, "basis": basisOf(t, plan)}); code != 422 {
		t.Fatalf("invalid apply: %d", code)
	}
	// snapshots and restore
	_, out = f.do("GET", "/api/v1/dns/domains/example.com/snapshots", nil)
	snaps := out["items"].([]any)
	if len(snaps) != 1 {
		t.Fatalf("snapshots: %v", out)
	}
	sid := snaps[0].(map[string]any)["id"].(string)
	if code, _ := f.do("POST", "/api/v1/dns/domains/example.com/snapshots/"+sid+"/restore", map[string]any{"confirm": "nope"}); code != 400 {
		t.Fatal("restore without confirm")
	}
	if code, out := f.do("POST", "/api/v1/dns/domains/example.com/snapshots/"+sid+"/restore", map[string]any{"confirm": "example.com"}); code != 200 {
		t.Fatalf("restore: %d %v", code, out)
	}
	_, out = f.do("GET", "/api/v1/dns/domains/example.com/records", nil)
	if s := mustString(out); strings.Contains(s, "mx2.example.com.") {
		t.Fatalf("restore kept the change: %s", s)
	}
}

func TestDNSViewerCannotChange(t *testing.T) {
	f, _, _ := dnsFixture(t)
	addExampleDomain(t, f)
	priv := sfc.FixtureKey("bob")
	if code, out := keyLogin(f, "bob", priv); code != 200 {
		t.Fatalf("bob login: %d %v", code, out)
	}
	if code, _ := f.do("GET", "/api/v1/dns/domains/example.com/records", nil); code != 200 {
		t.Fatalf("viewer read: %d", code)
	}
	shopA := map[string]any{"name": "shop", "type": "A", "records": []map[string]any{{"content": "203.0.113.10"}}}
	if code, _ := f.do("POST", "/api/v1/dns/domains/example.com/plan", map[string]any{"upsert": []any{shopA}}); code != 403 {
		t.Fatalf("viewer planned: %d", code)
	}
}
