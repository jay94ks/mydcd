// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// "Revert this change" on real sfcd: the web keeps the target before each
// change, offers the fields the change changed with what changed since, and
// sends the picked ones back as a new change checked against the revision
// read now.
func TestRealServerOpRevert(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	f, c := newRealFixture(t, ctx, 2)
	op := realOpID()
	realShop(t, c)
	alice, _ := realMembers(t, c)
	if code, out := keyLogin(f, "alice", alice.Private); code != 200 {
		t.Fatalf("alice login: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/t/shop/networks", map[string]any{"opId": op(), "kind": "tun", "name": "mesh", "members": []map[string]any{{"node": "node-0", "cidr": "10.50.1.0/24"}}}); opState(t, code, out) != "applied" {
		t.Fatalf("tun: %d %v", code, out)
	}
	dnsURL := "/api/v1/t/shop/networks/mesh/dns"
	rev := func() float64 {
		d, _ := networkRow(t, f, "mesh")["dns"].(map[string]any)
		if d == nil {
			return 0
		}
		return d["revision"].(float64)
	}
	// send changes the DNS policy and waits until the read shows it
	send := func(method, url string, body map[string]any) string {
		t.Helper()
		before := rev()
		id := op()
		body["opId"] = id
		if _, ok := body["expected"]; !ok && before != 0 {
			body["expected"] = before
		}
		if code, out := f.do(method, url, body); opState(t, code, out) != "applied" {
			t.Fatalf("%s %s %v: %d %v", method, url, body, code, out)
		}
		c.Wait("dns changed", func() bool { return rev() != before })
		return id
	}
	plan := func(id string) map[string]any {
		t.Helper()
		code, p := f.do("GET", "/api/v1/ops/"+id+"/revert", nil)
		if code != 200 {
			t.Fatalf("plan %s: %d %v", id, code, p)
		}
		return p
	}
	field := func(p map[string]any, path string) map[string]any {
		for _, x := range p["fields"].([]any) {
			if m := x.(map[string]any); m["path"] == path {
				return m
			}
		}
		return nil
	}

	first := send("POST", dnsURL, map[string]any{"zone": "mesh.internal", "ttl": 10, "upstreams": []string{"1.1.1.1"}})
	// a change that made the policy has nothing to go back to
	if p := plan(first); p["revert"] != "no" || p["reason"] != "created" {
		t.Fatalf("created plan: %v", p)
	}
	// alice: TTL 10 → 30 and a new upstream; then the TTL again 30 → 60
	mine := send("POST", dnsURL, map[string]any{"zone": "mesh.internal", "ttl": 30, "upstreams": []string{"10.0.0.53"}})
	if _, o := f.do("GET", "/api/v1/ops/"+mine, nil); o["op"].(map[string]any)["revert"] != "here" {
		t.Fatalf("row hint: %v", o)
	}
	send("POST", dnsURL, map[string]any{"zone": "mesh.internal", "ttl": 60, "upstreams": []string{"10.0.0.53"}})

	p := plan(mine)
	if p["revert"] != "here" || p["action"] != "configure-network-dns" || p["expected"] != rev() || len(p["fields"].([]any)) != 2 {
		t.Fatalf("plan: %v", p)
	}
	ttl, up := field(p, "Policy.TTL"), field(p, "Policy.Upstreams")
	if fmt.Sprint(ttl["before"], ttl["after"], ttl["now"], ttl["changedSince"]) != "10 30 60 true" {
		t.Fatalf("ttl: %v", ttl)
	}
	if fmt.Sprint(up["before"], up["after"], up["now"], up["changedSince"]) != "[1.1.1.1:53] [10.0.0.53:53] [10.0.0.53:53] false" {
		t.Fatalf("upstreams: %v", up)
	}
	revURL := "/api/v1/ops/" + mine + "/revert"
	for _, b := range []map[string]any{
		{"opId": op(), "expected": p["expected"]},                                    // no fields
		{"opId": op(), "fields": []string{"Policy.TTL"}},                             // no expected
		{"opId": op(), "expected": p["expected"], "fields": []string{"Policy.Zone"}}, // not changed by it
	} {
		if code, out := f.do("POST", revURL, b); code != 400 && code != 422 {
			t.Fatalf("bad revert %v: %d %v", b, code, out)
		}
	}
	if code, out := f.do("POST", revURL, map[string]any{"opId": op(), "expected": p["expected"].(float64) - 1, "fields": []string{"Policy.Upstreams"}}); code != 409 || errCode(out) != "stale" {
		t.Fatalf("stale revert: %d %v", code, out)
	}
	// put back only the upstream; the later TTL stays
	before := rev()
	back := op()
	code, out := f.do("POST", revURL, map[string]any{"opId": back, "expected": p["expected"], "fields": []string{"Policy.Upstreams"}})
	if opState(t, code, out) != "applied" {
		t.Fatalf("revert: %d %v", code, out)
	}
	if o := out["op"].(map[string]any); o["revertOf"] != mine || o["action"] != "configure-network-dns" || o["tenant"] != "shop" || o["revert"] != "here" {
		t.Fatalf("revert op: %v", o)
	}
	c.Wait("reverted", func() bool { return rev() != before })
	if d := networkRow(t, f, "mesh")["dns"].(map[string]any); fmt.Sprint(d["upstreams"], d["ttl"]) != "[1.1.1.1:53] 60" {
		t.Fatalf("after revert: %v", d)
	}
	// the same opId again is the same op
	if code, again := f.do("POST", revURL, map[string]any{"opId": back, "expected": p["expected"], "fields": []string{"Policy.Upstreams"}}); code != 200 || again["op"].(map[string]any)["id"] != back {
		t.Fatalf("repeat: %d %v", code, again)
	}
	// the revert is itself revertible
	if p := plan(back); p["revert"] != "here" || field(p, "Policy.Upstreams") == nil {
		t.Fatalf("revert of revert: %v", p)
	}

	// records: a set; reverting one change takes out only its own rows
	recordsURL := dnsURL + "/records"
	addWWW := send("PATCH", recordsURL, map[string]any{"add": []map[string]any{{"name": "www", "type": "CNAME", "value": "example.org"}}})
	send("PATCH", recordsURL, map[string]any{"add": []map[string]any{{"name": "legacy", "type": "A", "value": "192.0.2.7"}}})
	p = plan(addWWW)
	recs := field(p, "Policy.Records")
	if recs == nil || recs["kind"] != "set" || len(recs["added"].([]any)) != 1 || recs["removed"] != nil || recs["changedSince"] != false || len(p["fields"].([]any)) != 1 {
		t.Fatalf("records plan: %v", p)
	}
	before = rev()
	if code, out := f.do("POST", "/api/v1/ops/"+addWWW+"/revert", map[string]any{"opId": op(), "expected": p["expected"], "fields": []string{"Policy.Records"}}); opState(t, code, out) != "applied" {
		t.Fatalf("records revert: %d %v", code, out)
	}
	c.Wait("records reverted", func() bool { return rev() != before })
	_, names := f.do("GET", dnsURL+"/names", nil)
	if rs := names["records"].([]any); len(rs) != 1 || rs[0].(map[string]any)["name"] != "legacy.mesh.internal." {
		t.Fatalf("records after revert: %v", names["records"])
	}

	// what is not reverted here says why
	if code, out := f.do("POST", "/api/v1/t/shop/networks", map[string]any{"opId": op(), "kind": "tun", "name": "mesh", "members": []map[string]any{{"node": "node-0", "cidr": "10.50.2.0/24"}}}); opState(t, code, out) != "failed" {
		t.Fatalf("duplicate network: %d %v", code, out)
	} else if p := plan(out["op"].(map[string]any)["id"].(string)); p["revert"] != "no" || p["reason"] != "not-applied" {
		t.Fatalf("failed op plan: %v", p)
	}
	if code, out := f.do("GET", "/api/v1/ops/nope/revert", nil); code != 404 {
		t.Fatalf("unknown op: %d %v", code, out)
	}
	_ = ctx
}

// A change sent from the management change screen (POST /ops) is reverted
// the same way: a membership's role, and a workspace's servers (a list).
func TestRealServerOpRevertManage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	f, c := newRealFixture(t, ctx, 2)
	op := realOpID()
	realShopOn(t, c)
	realMembers(t, c)
	if code, out := keyLogin(f, "admin", c.Admin.Private); code != 200 {
		t.Fatalf("admin login: %d %v", code, out)
	}
	base := func(action string, payload map[string]any) map[string]any {
		_, b := f.do("POST", "/api/v1/ops/actions/"+action+"/base", map[string]any{"payload": payload})
		return b
	}
	submit := func(action string, payload map[string]any) string {
		t.Helper()
		b := base(action, payload)
		id := op()
		if code, out := f.do("POST", "/api/v1/ops", map[string]any{"opId": id, "action": action, "expected": b["expected"], "payload": payload, "tenant": "shop"}); opState(t, code, out) != "applied" {
			t.Fatalf("%s: %d %v", action, code, out)
		}
		c.Wait(action+" read", func() bool { return base(action, payload)["expected"] != b["expected"] })
		return id
	}
	revert := func(id string, fields ...string) {
		t.Helper()
		_, p := f.do("GET", "/api/v1/ops/"+id+"/revert", nil)
		if p["revert"] != "here" {
			t.Fatalf("plan %s: %v", id, p)
		}
		if code, out := f.do("POST", "/api/v1/ops/"+id+"/revert", map[string]any{"opId": op(), "expected": p["expected"], "fields": fields}); opState(t, code, out) != "applied" {
			t.Fatalf("revert %s: %d %v", id, code, out)
		}
	}

	member := map[string]any{"Tenant": "shop", "User": "u-bob"}
	role := submit("set-membership", map[string]any{"Tenant": "shop", "User": "u-bob", "Role": "manager", "Enabled": true})
	revert(role, "Role")
	c.Wait("role back", func() bool { return base("set-membership", member)["current"].(map[string]any)["Role"] == "viewer" })

	nodes := func() string {
		return fmt.Sprint(base("set-nodes", map[string]any{"Tenant": "shop"})["current"].(map[string]any)["AllowedNodes"])
	}
	start := nodes()
	one := submit("set-nodes", map[string]any{"Tenant": "shop", "Remove": []string{"node-1"}})
	_, p := f.do("GET", "/api/v1/ops/"+one+"/revert", nil)
	if fs := p["fields"].([]any); len(fs) != 1 || fs[0].(map[string]any)["kind"] != "set" {
		t.Fatalf("set-nodes plan: %v", p)
	}
	revert(one, "Nodes")
	c.Wait("nodes back", func() bool { return nodes() == start })

	// The account scope takes a change, so a revert sends the change back:
	// the removed action is added again, then the first change's actions
	// go (Unlimited, as the ceiling was empty) and key-only turns off.
	scope := func() map[string]any {
		_, out := f.do("GET", "/api/v1/users/u-bob/scope", nil)
		return out
	}
	patch := func(body map[string]any) string {
		t.Helper()
		rev := scope()["revision"]
		body["opId"], body["expected"] = op(), rev
		code, out := f.do("PATCH", "/api/v1/users/u-bob/scope", body)
		if opState(t, code, out) != "applied" {
			t.Fatalf("scope %v: %d %v", body, code, out)
		}
		c.Wait("scope read", func() bool { return scope()["revision"] != rev })
		return out["op"].(map[string]any)["id"].(string)
	}
	limit := patch(map[string]any{"add": []string{"restart-task", "pause-app-cd"}, "keyOnly": true})
	drop := patch(map[string]any{"remove": []string{"pause-app-cd"}})
	revert(drop, "Operations")
	c.Wait("action back", func() bool { return len(scope()["actions"].([]any)) == 2 })
	_, p = f.do("GET", "/api/v1/ops/"+limit+"/revert", nil)
	if p["revert"] != "here" || len(p["fields"].([]any)) != 2 {
		t.Fatalf("scope plan: %v", p)
	}
	revert(limit, "Operations", "KeyOnly")
	c.Wait("scope back", func() bool { s := scope(); return len(s["actions"].([]any)) == 0 && s["keyOnly"] == false })
}

// A network DNS record removed by hand stays restorable; the restore is a
// new change against the DNS revision read now.
func TestRealServerTrashDNSRecord(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	f, c := newRealFixture(t, ctx, 2)
	op := realOpID()
	realShop(t, c)
	alice, _ := realMembers(t, c)
	if code, out := keyLogin(f, "alice", alice.Private); code != 200 {
		t.Fatalf("alice login: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/t/shop/networks", map[string]any{"opId": op(), "kind": "tun", "name": "mesh", "members": []map[string]any{{"node": "node-0", "cidr": "10.50.1.0/24"}}}); opState(t, code, out) != "applied" {
		t.Fatalf("tun: %d %v", code, out)
	}
	rev := func() float64 {
		d, _ := networkRow(t, f, "mesh")["dns"].(map[string]any)
		if d == nil {
			return 0
		}
		return d["revision"].(float64)
	}
	change := func(method, url string, body map[string]any) {
		t.Helper()
		before := rev()
		body["opId"] = op()
		if before != 0 {
			body["expected"] = before
		}
		if code, out := f.do(method, url, body); opState(t, code, out) != "applied" {
			t.Fatalf("%s %v: %d %v", url, body, code, out)
		}
		c.Wait("dns changed", func() bool { return rev() != before })
	}
	recordsURL := "/api/v1/t/shop/networks/mesh/dns/records"
	www := map[string]any{"name": "www", "type": "CNAME", "value": "example.org"}
	change("POST", "/api/v1/t/shop/networks/mesh/dns", map[string]any{"zone": "mesh.internal"})
	change("PATCH", recordsURL, map[string]any{"add": []any{www}})
	change("PATCH", recordsURL, map[string]any{"remove": []any{www}})

	_, out := f.do("GET", "/api/v1/trash", nil)
	items := out["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("trash: %v", out)
	}
	it := items[0].(map[string]any)
	if it["kind"] != "dns-record" || it["tenant"] != "shop" || it["name"] != "www.mesh.internal. CNAME" || it["detail"].(map[string]any)["value"] != "example.org." {
		t.Fatalf("item: %v", it)
	}
	restore := "/api/v1/trash/" + it["id"].(string) + "/restore"
	// the name has another CNAME now
	change("PATCH", recordsURL, map[string]any{"add": []any{map[string]any{"name": "www", "type": "CNAME", "value": "other.example.org"}}})
	if code, out := f.do("POST", restore, map[string]any{"opId": op()}); code != 409 || errCode(out) != "exists" || len(out["current"].([]any)) != 1 {
		t.Fatalf("restore over another: %d %v", code, out)
	}
	before := rev()
	if code, out := f.do("POST", restore, map[string]any{"opId": op(), "replace": true}); opState(t, code, out) != "applied" || out["op"].(map[string]any)["tenant"] != "shop" {
		t.Fatalf("restore: %d %v", code, out)
	}
	c.Wait("restored", func() bool { return rev() != before })
	_, names := f.do("GET", "/api/v1/t/shop/networks/mesh/dns/names", nil)
	if rs := names["records"].([]any); len(rs) != 1 || rs[0].(map[string]any)["value"] != "example.org." {
		t.Fatalf("records: %v", names["records"])
	}
	// the restored item is gone; replacing the other CNAME was an edit of
	// the name (its revert puts it back), not a delete
	_, out = f.do("GET", "/api/v1/trash", nil)
	if items := out["items"].([]any); len(items) != 0 {
		t.Fatalf("trash after restore: %v", items)
	}
	if code, _ := f.do("POST", restore, map[string]any{"opId": op()}); code != 404 {
		t.Fatalf("restore twice: %d", code)
	}
}
