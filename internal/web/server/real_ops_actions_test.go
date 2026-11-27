// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
)

// The management change screen on real sfcd: the action list carries
// every action sfcd accepts with its fields, base reads the revision a
// change is checked against, and the change goes through POST /ops.
func TestRealServerOpActions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	f, c := newRealFixture(t, ctx, 2)
	op := realOpID()
	realShopOn(t, c)
	realMembers(t, c)
	if code, out := keyLogin(f, "admin", c.Admin.Private); code != 200 {
		t.Fatalf("admin login: %d %v", code, out)
	}

	code, list := f.do("GET", "/api/v1/ops/actions", nil)
	items, _ := list["items"].([]any)
	if code != 200 || len(items) != len(control.InputActions()) {
		t.Fatalf("actions: %d %d", code, len(items))
	}
	row := map[string]map[string]any{}
	for _, it := range items {
		m := it.(map[string]any)
		row[m["action"].(string)] = m
		if m["category"] == "other" {
			t.Errorf("%s has no category (key %s)", m["action"], m["key"])
		}
	}
	for action, want := range map[string][3]string{
		"set-membership": {"tenants", "here", "current"},
		"create-tenant":  {"tenants", "here", "zero"},
		"put-app-part":   {"apps", "no", "input"},
		"set-node-quota": {"reservations", "here", "current"},
		"put-registry":   {"registry", "here", "input"},
	} {
		if m := row[action]; m["category"] != want[0] || m["offer"] != want[1] || m["base"] != want[2] {
			t.Errorf("%s: %v", action, m)
		}
	}
	if f0 := row["set-nodes"]["fields"].([]any)[1].(map[string]any); f0["name"] != "Add" || f0["type"] != "list" || f0["replace"] == true {
		t.Errorf("set-nodes Add: %v", f0)
	}

	base := func(action string, payload map[string]any) (int, map[string]any) {
		return f.do("POST", "/api/v1/ops/actions/"+action+"/base", map[string]any{"payload": payload})
	}
	submit := func(action string, expected float64, payload map[string]any) (int, map[string]any) {
		return f.do("POST", "/api/v1/ops", map[string]any{"opId": op(), "action": action, "expected": expected, "payload": payload, "tenant": "shop"})
	}

	// bob's membership: read the base, change it with that Expected
	member := map[string]any{"Tenant": "shop", "User": "u-bob"}
	code, b := base("set-membership", member)
	if code != 200 || b["found"] != true || b["expected"] == float64(0) || b["current"].(map[string]any)["Role"] != "viewer" {
		t.Fatalf("membership base: %d %v", code, b)
	}
	stale := b["expected"].(float64)
	if code, out := submit("set-membership", stale, map[string]any{"Tenant": "shop", "User": "u-bob", "Role": "manager", "Enabled": true}); opState(t, code, out) != "applied" {
		t.Fatalf("set-membership: %d %v", code, out)
	}
	c.Wait("membership changed", func() bool {
		_, b := base("set-membership", member)
		return b["expected"] != stale && b["current"].(map[string]any)["Role"] == "manager"
	})
	// the old base no longer holds
	if code, out := submit("set-membership", stale, map[string]any{"Tenant": "shop", "User": "u-bob", "Role": "viewer", "Enabled": true}); opState(t, code, out) != "failed" {
		t.Fatalf("stale set-membership: %d %v", code, out)
	}
	// a user that is not there yet: Expected 0
	if code, b := base("put-user", map[string]any{"ID": "u-carol"}); code != 200 || b["found"] != false || b["expected"] != float64(0) {
		t.Fatalf("new user base: %d %v", code, b)
	}
	if code, b := base("put-user", map[string]any{"ID": "u-bob"}); code != 200 || b["found"] != true || b["current"].(map[string]any)["Username"] != "bob" {
		t.Fatalf("bob base: %d %v", code, b)
	}

	// cluster-wide settings
	code, b = base("set-node-cli-policy", map[string]any{})
	if code != 200 || b["found"] != true {
		t.Fatalf("node cli base: %d %v", code, b)
	}
	if code, out := submit("set-node-cli-policy", b["expected"].(float64), map[string]any{"disable_node_cli_operation": true}); opState(t, code, out) != "applied" {
		t.Fatalf("set-node-cli-policy: %d %v", code, out)
	}
	code, b = base("set-node-shell-policy", map[string]any{})
	if code != 200 || b["found"] != true {
		t.Fatalf("node shell base: %d %v", code, b)
	}

	// a network: the Networks collection revision, the row as current
	if code, out := f.do("POST", "/api/v1/t/shop/networks", map[string]any{"opId": op(), "kind": "tun", "name": "mesh", "members": []map[string]any{{"node": "node-0", "cidr": "10.50.3.0/24"}}}); opState(t, code, out) != "applied" {
		t.Fatalf("create mesh: %d %v", code, out)
	}
	c.Wait("mesh base", func() bool {
		_, b := base("set-network-toggle", map[string]any{"Tenant": "shop", "Name": "mesh"})
		return b["found"] == true && b["expected"] != float64(0)
	})
	_, b = base("set-network-toggle", map[string]any{"Tenant": "shop", "Name": "mesh"})
	if code, out := submit("set-network-toggle", b["expected"].(float64), map[string]any{"Tenant": "shop", "Name": "mesh", "Toggle": "local", "On": true}); opState(t, code, out) != "applied" {
		t.Fatalf("set-network-toggle: %d %v", code, out)
	}

	// refusals
	if code, out := base("put-registry", map[string]any{}); code != 422 || errCode(out) != "unsupported" {
		t.Fatalf("unsupported: %d %v", code, out)
	}
	if code, out := base("no-such-action", map[string]any{}); code != 404 {
		t.Fatalf("unknown: %d %v", code, out)
	}
	// a field the action does not have, and a replaced field left out
	if code, out := submit("set-membership", 0, map[string]any{"Tenant": "shop", "User": "u-bob", "Role": "viewer", "Enabled": true, "Extra": 1}); code != 400 || errCode(out) != "bad-payload" {
		t.Fatalf("unknown field: %d %v", code, out)
	}
	if code, out := submit("set-volume-capacity", 0, map[string]any{"Scope": map[string]any{}, "Native": [32]int{}}); code != 400 || errCode(out) != "bad-payload" {
		t.Fatalf("missing replaced field: %d %v", code, out)
	}
}
