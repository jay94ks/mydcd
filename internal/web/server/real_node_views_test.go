// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/identity"
)

// The server screens on two real sfcd nodes: summary, Raft status, disks,
// mesh links and a Raft compaction, and that a workspace manager sees none
// of the cluster-wide ones.
func TestRealServerNodeViews(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	f, c := newRealFixture(t, ctx, 2)
	op := realOpID()
	realShop(t, c)
	alice, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	c.Change(0, "alice", "put-user", 0, access.User{ID: "u-alice", Username: "alice", Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: alice.Public, Enabled: true}}})
	c.Change(0, "alice-shop", "set-membership", 0, access.Membership{Tenant: "shop", User: "u-alice", Role: access.Manager, Enabled: true})
	if code, out := keyLogin(f, "alice", alice.Private); code != 200 {
		t.Fatalf("alice login: %d %v", code, out)
	}
	for _, p := range []string{"/api/v1/nodes/summary", "/api/v1/raft", "/api/v1/raft/compact", "/api/v1/disks"} {
		if code, out := f.do("GET", p, nil); code != 403 {
			t.Fatalf("alice %s: %d %v", p, code, out)
		}
	}
	// the workspace views: its storage roots' disks only, links without the
	// sides' observations
	if code, out := f.do("GET", "/api/v1/disks?tenant=shop", nil); code != 200 {
		t.Fatalf("tenant disks: %d %v", code, out)
	} else {
		for _, it := range out["items"].([]any) {
			if row := it.(map[string]any); row["purpose"] != "storage-root" || row["device"] != nil {
				t.Fatalf("tenant disk row: %v", row)
			}
		}
	}
	if code, out := f.do("GET", "/api/v1/mesh?tenant=shop", nil); code != 200 || strings.Contains(fmt.Sprint(out["items"]), "rttMillis") {
		t.Fatalf("tenant mesh: %d %v", code, out)
	}
	if code, out := f.do("GET", "/api/v1/dashboard?tenant=shop", nil); code != 200 {
		t.Fatalf("alice dashboard: %d %v", code, out)
	} else {
		for _, it := range out["nodes"].([]any) {
			if row := it.(map[string]any); row["memTotal"] != nil || row["role"] != nil {
				t.Fatalf("tenant summary row: %v", row)
			}
		}
	}

	if code, out := keyLogin(f, "admin", c.Admin.Private); code != 200 {
		t.Fatalf("admin login: %d %v", code, out)
	}
	// node-1 is unreachable until its first report reaches node-0
	var rows map[string]map[string]any
	c.Wait("both servers ready", func() bool {
		code, out := f.do("GET", "/api/v1/nodes/summary", nil)
		rows = map[string]map[string]any{}
		for _, it := range out["items"].([]any) {
			row := it.(map[string]any)
			rows[row["node"].(string)] = row
		}
		return code == 200 && len(rows) == 2 && rows["node-0"]["status"] == "ready" && rows["node-1"]["status"] == "ready"
	})
	if r := rows["node-0"]; r["role"] != "leader" || r["memTotal"].(float64) <= 0 || r["observedAt"].(float64) > 1e11 {
		t.Fatalf("node-0 row: %v", r)
	}
	code, out := f.do("GET", "/api/v1/raft", nil)
	servers, _ := out["servers"].([]any)
	if code != 200 || out["leader"] != "node-0" || out["voters"] != float64(2) || out["quorum"] != float64(2) || len(servers) != 2 || servers[0].(map[string]any)["role"] != "leader" || servers[0].(map[string]any)["suffrage"] != "voter" || out["observedAt"].(float64) > 1e11 {
		t.Fatalf("raft: %d %v", code, out)
	}
	if el := out["elections"].([]any); len(el) == 0 || el[len(el)-1].(map[string]any)["leader"] != "node-0" {
		t.Fatalf("elections: %v", el)
	}
	code, out = f.do("GET", "/api/v1/nodes/node-0/disks", nil)
	disks, _ := out["items"].([]any)
	if code != 200 || len(disks) == 0 || disks[0].(map[string]any)["fsType"] == nil || disks[0].(map[string]any)["observedAt"].(float64) > 1e11 {
		t.Fatalf("node disks: %d %v", code, out)
	}
	// the device inventory of the server; the system disk holds "/"
	if devices, _ := out["devices"].(map[string]any); devices == nil || devices["node"] != "node-0" {
		t.Fatalf("node devices: %v", out)
	}
	c.Wait("mesh link observed", func() bool {
		_, out = f.do("GET", "/api/v1/mesh", nil)
		items, _ := out["items"].([]any)
		return len(items) == 1 && items[0].(map[string]any)["state"] != "pending"
	})
	if l := out["items"].([]any)[0].(map[string]any); l["id"] != "node-0/node-1" || l["observedAt"].(float64) > 1e11 {
		t.Fatalf("mesh link: %v", l)
	}

	code, out = f.do("GET", "/api/v1/raft/compact", nil)
	if code != 200 || out["retain"] != float64(10240) || out["last"] != nil || len(out["entries"].(map[string]any)) == 0 {
		t.Fatalf("compact status: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/raft/compact", map[string]any{"opId": op(), "nodes": []string{}, "mode": "all", "serial": true}); code != 422 {
		t.Fatalf("bad mode: %d %v", code, out)
	}
	code, out = f.do("GET", "/api/v1/raft/compact/plan?mode=minimal", nil)
	if code != 200 || len(out["plan"].(string)) != 64 || out["total"] != float64(2) || out["retain"] != float64(1000) || out["parallel"] != false {
		t.Fatalf("plan: %d %v", code, out)
	}
	plan := out["plan"]
	// sfcd does not say whether a server it will not plan exists
	if code, out := f.do("GET", "/api/v1/raft/compact/plan?mode=keep&nodes=node-z", nil); code != 403 {
		t.Fatalf("plan for an unknown server: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/raft/compact", map[string]any{"opId": op(), "nodes": []string{}, "mode": "keep", "serial": true, "plan": plan}); code != 409 || errCode(out) != "plan-changed" {
		t.Fatalf("other selection's plan: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/raft/compact", map[string]any{"opId": op(), "nodes": []string{}, "mode": "minimal", "serial": true}); code != 422 {
		t.Fatalf("no plan: %d %v", code, out)
	}
	o := op()
	code, out = f.do("POST", "/api/v1/raft/compact", map[string]any{"opId": o, "nodes": []string{}, "mode": "minimal", "serial": true, "plan": plan})
	if opState(t, code, out) != "applied" {
		t.Fatalf("compact: %d %v", code, out)
	}
	// both servers snapshot one after another
	var last map[string]any
	c.Wait("compaction done", func() bool {
		_, out = f.do("GET", "/api/v1/raft/compact", nil)
		last, _ = out["last"].(map[string]any)
		return last != nil && last["state"] == "done"
	})
	if last["id"] != o || last["by"] != "admin" || last["mode"] != "minimal" || last["operation"] != "op-"+o || len(last["nodes"].([]any)) != 2 {
		t.Fatalf("last: %v", last)
	}
	code, out = f.do("GET", "/api/v1/raft/compactions/op-"+o, nil)
	if code != 200 || out["complete"] != true || out["done"] != float64(2) || out["sequential"] != true || len(out["nodes"].([]any)) != 2 {
		t.Fatalf("job status: %d %v", code, out)
	}
	if code, out := f.do("GET", "/api/v1/raft/compactions/op-none", nil); code != 404 {
		t.Fatalf("unknown job: %d %v", code, out)
	}
}
