// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"sync"
	"testing"

	"github.com/jay94ks/mydcd/internal/web/dns"
	"github.com/jay94ks/mydcd/internal/web/seal"
)

const opRv = "d1b2c3d4-0000-4000-8000-000000000001"

// stubResolver answers from a table keyed server|fqdn|type.
type stubResolver struct {
	mu   sync.Mutex
	ans  map[string]dns.Answer
	seen []string
}

func (s *stubResolver) Query(_ context.Context, server, fqdn, rtype string, recurse bool) (dns.Answer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := server + "|" + fqdn + "|" + rtype
	s.seen = append(s.seen, k)
	a, ok := s.ans[k]
	if !ok {
		return dns.Answer{}, &dns.Error{Kind: dns.Unavailable, Detail: "timeout"}
	}
	return a, nil
}

func TestDNSRenameProviderAndRevertOf(t *testing.T) {
	f, _, _ := dnsFixture(t)
	addExampleDomain(t, f)
	fakeLogin(t, f, "admin")
	_, out := f.do("GET", "/api/v1/dns/providers", nil)
	id := out["items"].([]any)[0].(map[string]any)["id"].(string)
	if code, out := f.do("PUT", "/api/v1/dns/providers/"+id, map[string]any{"name": "  메인 계정 "}); code != 200 || out["provider"].(map[string]any)["name"] != "메인 계정" {
		t.Fatalf("rename: %d %v", code, out)
	}
	if code, _ := f.do("PUT", "/api/v1/dns/providers/"+id, map[string]any{"name": " "}); code != 422 {
		t.Fatalf("empty name: %d", code)
	}
	if code, _ := f.do("PUT", "/api/v1/dns/providers/nope", map[string]any{"name": "x"}); code != 404 {
		t.Fatalf("missing: %d", code)
	}

	shopA := map[string]any{"name": "shop", "type": "A", "records": []map[string]any{{"content": "203.0.113.10"}}}
	_, plan := f.do("POST", "/api/v1/dns/domains/example.com/plan", map[string]any{"upsert": []any{shopA}, "tenant": "shop"})
	if code, out := f.do("POST", "/api/v1/dns/domains/example.com/apply", map[string]any{"opId": opA, "upsert": []any{shopA}, "basis": basisOf(t, plan), "tenant": "shop"}); code != 200 {
		t.Fatalf("apply: %d %v", code, out)
	}
	_, rv := f.do("POST", "/api/v1/dns/domains/example.com/history/"+opA+"/revert", nil)
	req := rv["request"].(map[string]any)
	_, plan = f.do("POST", "/api/v1/dns/domains/example.com/plan", req)
	if code, _ := f.do("POST", "/api/v1/dns/domains/example.com/apply", map[string]any{"opId": opRv, "delete": req["delete"], "upsert": req["upsert"], "tenant": "shop", "basis": basisOf(t, plan), "revertOf": "nope"}); code != 422 {
		t.Fatalf("unknown revertOf: %d", code)
	}
	code, out := f.do("POST", "/api/v1/dns/domains/example.com/apply", map[string]any{"opId": opRv, "delete": req["delete"], "upsert": req["upsert"], "tenant": "shop", "basis": basisOf(t, plan), "revertOf": rv["revertOf"]})
	if code != 200 || out["history"].(map[string]any)["revertOf"] != opA || out["history"].(map[string]any)["result"] != "applied" {
		t.Fatalf("revert apply: %d %v", code, out)
	}
}

func TestDNSPropagation(t *testing.T) {
	f, _, _ := dnsFixture(t)
	// a fake vendor that offers the check
	world := dns.NewFakeWorld()
	v := dns.FakeVendor(world)
	v.Capabilities.Propagation = true
	reg := &dns.Registry{}
	reg.Register(v)
	box, _ := seal.Open(t.TempDir(), bytes.Repeat([]byte{4}, seal.KeySize))
	f.srv.opt.DNS, f.srv.opt.Seal = reg, box
	res := &stubResolver{ans: map[string]dns.Answer{
		"1.1.1.1:53|example.com|NS":               {Values: []string{"ns1.fake-dns.test", "ns2.fake-dns.test"}, TTL: 3600},
		"ns1.fake-dns.test:53|shop.example.com|A": {Values: []string{"203.0.113.10"}, TTL: 300},
		"ns2.fake-dns.test:53|shop.example.com|A": {Values: []string{"203.0.113.10"}, TTL: 300},
		"1.1.1.1:53|shop.example.com|A":           {Values: []string{"203.0.113.10"}, TTL: 120},
		"8.8.8.8:53|shop.example.com|A":           {Values: []string{"192.0.2.9"}, TTL: 40},
	}}
	f.srv.opt.Resolver = res
	addExampleDomain(t, f)
	world.SetRecord("example.com", dns.RRSet{Name: "shop", Type: "A", TTL: 300, Records: []dns.Record{{Content: "203.0.113.10"}}})

	fakeLogin(t, f, "alice")
	if code, _ := f.do("GET", "/api/v1/dns/domains/example.com/propagation?name=www&type=A", nil); code != 403 {
		t.Fatalf("out of range: %d", code)
	}
	code, out := f.do("GET", "/api/v1/dns/domains/example.com/propagation?name=shop&type=A", nil)
	if code != 200 || out["name"] != "shop" || len(out["want"].([]any)) != 1 || out["checkedAt"] == nil {
		t.Fatalf("propagation: %d %v", code, out)
	}
	byServer := map[string]map[string]any{}
	for _, it := range out["resolvers"].([]any) {
		m := it.(map[string]any)
		byServer[m["server"].(string)] = m
	}
	if len(byServer) != 5 {
		t.Fatalf("resolvers: %v", out["resolvers"])
	}
	if m := byServer["ns1.fake-dns.test"]; m["kind"] != "authoritative" || m["fresh"] != true || m["ttlLeft"] != nil {
		t.Fatalf("authoritative: %v", m)
	}
	if m := byServer["1.1.1.1"]; m["kind"] != "public" || m["fresh"] != true || m["ttlLeft"] != float64(120) {
		t.Fatalf("fresh public: %v", m)
	}
	if m := byServer["8.8.8.8"]; m["fresh"] != false || m["ttlLeft"] != float64(40) {
		t.Fatalf("stale public: %v", m)
	}
	if m := byServer["9.9.9.9"]; m["fresh"] != false || m["error"] != "unavailable" {
		t.Fatalf("failed public: %v", m)
	}
	// a provider without the capability
	v.Capabilities.Propagation = false
	reg2 := &dns.Registry{}
	reg2.Register(v)
	f.srv.opt.DNS = reg2
	if code, out := f.do("GET", "/api/v1/dns/domains/example.com/propagation?name=shop&type=A", nil); code != 409 || errCode(out) != "not-supported" {
		t.Fatalf("no capability: %d %v", code, out)
	}
}
