// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"strings"
	"testing"
)

func TestDNSServers(t *testing.T) {
	f, _, _ := dnsFixture(t)
	addExampleDomain(t, f)
	fakeLogin(t, f, "admin")
	shopA := map[string]any{"name": "shop", "type": "A", "records": []map[string]any{{"content": "203.0.113.10"}}}
	_, plan := f.do("POST", "/api/v1/dns/domains/example.com/plan", map[string]any{"upsert": []any{shopA}})
	if code, out := f.do("POST", "/api/v1/dns/domains/example.com/apply", map[string]any{"opId": opA, "upsert": []any{shopA}, "basis": basisOf(t, plan)}); code != 200 {
		t.Fatalf("apply: %d %v", code, out)
	}
	const base = "/api/v1/dns/domains/example.com/servers"
	_, out := f.do("GET", base, nil)
	items := out["items"].([]any)
	if len(items) != 2 || out["staged"] != float64(0) || out["revision"] != float64(0) {
		t.Fatalf("no links: %v", out)
	}
	if a := items[0].(map[string]any); a["node"] != "node-a" || a["state"] != "not-linked" || fmt.Sprint(a["listen"]) != "[443]" || fmt.Sprint(a["addresses"]) != "[203.0.113.11]" {
		t.Fatalf("node-a: %v", a)
	}
	for _, bad := range []struct {
		node string
		body map[string]any
		code int
	}{
		{"node-c", map[string]any{"linked": true, "revision": 0}, 404}, // local gateway only
		{"node-a", map[string]any{"linked": true, "revision": 3}, 409},
		{"node-a", map[string]any{"linked": true, "addressSource": "manual", "addresses": []string{"10.0.0.1"}, "revision": 0}, 422},
		{"node-a", map[string]any{"linked": true, "addresses": []string{"203.0.113.9"}, "revision": 0}, 422},
	} {
		if code, out := f.do("PUT", base+"/"+bad.node, bad.body); code != bad.code {
			t.Fatalf("%v: %d %v", bad, code, out)
		}
	}
	code, out := f.do("PUT", base+"/node-a", map[string]any{"linked": true, "revision": 0})
	if code != 200 || out["staged"] != float64(1) || !strings.Contains(mustString(out["changes"]), `"content":"203.0.113.11"`) {
		t.Fatalf("link node-a: %d %v", code, out)
	}
	code, out = f.do("PUT", base+"/node-b", map[string]any{"linked": true, "addressSource": "manual", "addresses": []string{"198.51.100.50", "2001:db8::50"},
		"autoRemove": false, "revision": out["revision"]})
	if code != 200 || out["staged"] != float64(2) {
		t.Fatalf("link node-b: %d %v", code, out)
	}
	ch := mustString(out["changes"])
	if !strings.Contains(ch, `{"name":"shop","records":[{"content":"198.51.100.50"},{"content":"203.0.113.11"}],"ttl":3600,"type":"A"}`) || !strings.Contains(ch, `"records":[{"content":"2001:db8::50"}],"ttl":3600,"type":"AAAA"`) || strings.Contains(ch, "outside") {
		t.Fatalf("changes: %s", ch)
	}
	rev := out["revision"]

	// The reach check: documentation addresses are not public.
	_, out = f.do("POST", base+"/check", map[string]any{"node": "node-b"})
	if r := out["items"].([]any)[0].(map[string]any); r["ok"] != false || !strings.Contains(r["error"].(string), "공개 주소가 아님") {
		t.Fatalf("check: %v", out)
	}

	fakeLogin(t, f, "alice")
	_, out = f.do("GET", base, nil)
	if len(out["items"].([]any)) != 2 || out["changes"] != nil || out["partial"] != true {
		t.Fatalf("alice: %v", out)
	}
	if b := out["items"].([]any)[1].(map[string]any); b["reach"].(map[string]any)["ok"] != false || b["autoRemove"] != false {
		t.Fatalf("alice node-b: %v", b)
	}
	if code, _ := f.do("PUT", base+"/node-a", map[string]any{"linked": false, "revision": rev}); code != 403 {
		t.Fatalf("alice put: %d", code)
	}
	if code, _ := f.do("POST", base+"/check", map[string]any{"node": "node-a", "addresses": []string{"198.51.100.1"}}); code != 422 {
		t.Fatalf("alice try: %d", code)
	}

	fakeLogin(t, f, "admin")
	code, out = f.do("PUT", base+"/node-a", map[string]any{"linked": false, "revision": rev})
	if code != 200 || out["staged"] != float64(2) {
		t.Fatalf("unlink node-a: %d %v", code, out)
	}
	if code, out := f.do("PUT", base+"/node-b", map[string]any{"linked": false, "revision": out["revision"]}); code != 422 || errCode(out) != "last-server" {
		t.Fatalf("last: %d %v", code, out)
	}
}
