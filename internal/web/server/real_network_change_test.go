// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/control"
)

// A network change through the web on real mydcd: a TUN network's member
// is planned, drained, fenced with node-0's closure and committed to a new
// pool, and the network is retired with no members.
func TestRealServerNetworkChange(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	f, c := newRealFixture(t, ctx, 2)
	op := realOpID()
	// No "lan": node-1's TUN and node-0's would share one kernel here.
	realShopOn(t, c)
	if code, out := keyLogin(f, "admin", c.Admin.Private); code != 200 {
		t.Fatalf("admin login: %d %v", code, out)
	}
	post := func(path string, body map[string]any) (int, map[string]any) {
		t.Helper()
		body["opId"] = op()
		return f.do("POST", "/api/v1/t/shop/networks"+path, body)
	}
	step := func(path string, body map[string]any) map[string]any {
		t.Helper()
		code, out := post(path, body)
		if s := opState(t, code, out); s != "applied" {
			t.Fatalf("%s %v: %s %d %v", path, body, s, code, out)
		}
		return out
	}
	status := func(name string) map[string]any {
		t.Helper()
		code, out := f.do("GET", "/api/v1/t/shop/networks/"+name+"/change", nil)
		if code != 200 {
			t.Fatalf("status %s: %d %v", name, code, out)
		}
		return out
	}
	member := func(st map[string]any) map[string]any { return st["members"].([]any)[0].(map[string]any) }

	step("", map[string]any{"kind": "tun", "name": "mesh", "tunnelCidr": "10.255.40.0/24", "members": []map[string]any{{"node": "node-0", "cidr": "10.50.1.0/24"}}})
	if st := status("mesh"); st["kind"] != "tun" || member(st)["phase"] != "none" || st["next"] != "" {
		t.Fatalf("initial: %v", st)
	}
	// node-0 makes the network's bridge before the change starts: mydcd
	// cannot close a member drained before its bridge exists. The
	// engine starts with bridge, host and none.
	c.Wait("mesh bridge", func() bool { return len(c.Nodes[0].Engine.Networks()) > 3 })

	// TUN: plan, drain, fence, commit
	plan := step("/mesh/change", map[string]any{"node": "node-0", "cidr": "10.50.9.0/24"})
	var p control.NetworkChangePlan
	userPayload(t, f, "u-admin", plan["op"].(map[string]any)["id"].(string), &p)
	if p.Target.Pools[0].Prefix.String() != "10.50.9.0/24" || p.Target.Logical != "mesh" {
		t.Fatalf("plan payload: %+v", p)
	}
	if st := status("mesh"); member(st)["phase"] != "reserved" || member(st)["target"] != "10.50.9.0/24" || st["next"] != "drain" {
		t.Fatalf("reserved: %v", st)
	}
	if code, out := post("/mesh/change", map[string]any{"node": "node-0", "cidr": "10.50.8.0/24"}); code != 409 || errCode(out) != "change-pending" {
		t.Fatalf("double plan: %d %v", code, out)
	}
	if code, out := post("/mesh/change/commit", map[string]any{}); code != 409 || errCode(out) != "not-fenced" {
		t.Fatalf("commit early: %d %v", code, out)
	}
	step("/mesh/change/drain", map[string]any{"node": "node-0"})
	if st := status("mesh"); member(st)["phase"] != "draining" || st["next"] != "fence" {
		t.Fatalf("draining: %v", st)
	}
	// node-0 reports the drained member closed; then it is fenced
	c.Wait("fenced", func() bool {
		code, out := post("/mesh/change/fence", map[string]any{"node": "node-0"})
		if code == 409 && errCode(out) == "in-use" {
			return false
		}
		if s := opState(t, code, out); s != "applied" {
			t.Fatalf("fence: %s %d %v", s, code, out)
		}
		return true
	})
	if code, out := post("/mesh/change/fence", map[string]any{"node": "node-0"}); code != 409 || errCode(out) != "not-draining" {
		t.Fatalf("fence twice: %d %v", code, out)
	}
	c.Wait("commit next", func() bool { return status("mesh")["next"] == "commit" })
	step("/mesh/change/commit", map[string]any{})
	c.Wait("committed", func() bool { m := member(status("mesh")); return m["cidr"] == "10.50.9.0/24" && m["phase"] == "none" })

	// TUN retire: fenced again, then no members
	if code, out := post("/mesh/retire", map[string]any{}); code != 409 || errCode(out) != "not-fenced" {
		t.Fatalf("retire early: %d %v", code, out)
	}
	step("/mesh/change", map[string]any{"node": "node-0", "cidr": "10.50.10.0/24"})
	step("/mesh/change/drain", map[string]any{"node": "node-0"})
	c.Wait("fenced again", func() bool {
		code, out := post("/mesh/change/fence", map[string]any{"node": "node-0"})
		return code != 409 && opState(t, code, out) == "applied"
	})
	c.Wait("retire", func() bool {
		code, out := post("/mesh/retire", map[string]any{})
		return code != 409 && opState(t, code, out) == "applied"
	})
	c.Wait("retired", func() bool { code, _ := f.do("GET", "/api/v1/t/shop/networks/mesh/change", nil); return code == 404 })

}
