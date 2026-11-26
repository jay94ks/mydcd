// SPDX-License-Identifier: Apache-2.0

package server

import (
	"testing"
)

// UI-3C log clearing: plan (target and dependents), clear with the same
// opId, status stages, refusal for a non-local log driver.
func TestLogClear(t *testing.T) {
	f, fake := newFakeFixture(t)
	op := opSeq("c3c0aaaa")
	fakeLogin(t, f, "alice")
	code, plan := f.do("GET", "/api/v1/t/shop/apps/php-shop/logs-clear/plan?service=db&instance=1", nil)
	if code != 200 || plan["clearable"] != true || len(plan["target"].(string)) != 64 {
		t.Fatalf("plan: %d %v", code, plan)
	}
	reasons := map[string]int{}
	for _, im := range plan["targets"].([]any) {
		row := im.(map[string]any)
		reasons[row["reason"].(string)]++
		if row["reason"] == "target" && (row["service"] != "db" || row["instance"] != "1") {
			t.Fatalf("target row: %v", row)
		}
	}
	if reasons["target"] != 1 {
		t.Fatalf("targets: %v", plan["targets"])
	}
	body := map[string]any{"opId": op(), "service": "db", "instance": "1", "target": plan["target"]}
	code, out := f.do("POST", "/api/v1/t/shop/apps/php-shop/logs-clear", body)
	if opState(t, code, out) != "applied" {
		t.Fatalf("clear: %d %v", code, out)
	}
	if code, again := f.do("POST", "/api/v1/t/shop/apps/php-shop/logs-clear", body); code != 200 || again["op"].(map[string]any)["requestId"] != out["op"].(map[string]any)["requestId"] {
		t.Fatalf("same opId: %d %v", code, again)
	}
	status := "/api/v1/t/shop/apps/php-shop/logs-clear/" + body["opId"].(string)
	var seen []string
	for i := 0; i < 4; i++ {
		code, st := f.do("GET", status, nil)
		if code != 200 {
			t.Fatalf("status: %d %v", code, st)
		}
		seen = append(seen, st["phase"].(string))
		if st["phase"] == "Succeeded" && len(st["newContainers"].([]any)) == 0 {
			t.Fatalf("no new containers: %v", st)
		}
	}
	if seen[0] != "Retiring" || seen[3] != "Succeeded" {
		t.Fatalf("stages %v", seen)
	}
	_, hist := f.do("GET", "/api/v1/t/shop/apps/php-shop/task/history?service=db&instance=1", nil)
	if exits := hist["exits"].([]any); len(exits) == 0 {
		t.Fatalf("history: %v", hist)
	}

	// a stale target (the containers changed)
	body["opId"] = op()
	if code, out := f.do("POST", "/api/v1/t/shop/apps/php-shop/logs-clear", body); code != 409 || errCode(out) != "plan-changed" {
		t.Fatalf("stale: %d %v", code, out)
	}
	fake.SetTaskLogDriver("shop", "php-shop", "web", "1", "syslog")
	if code, p := f.do("GET", "/api/v1/t/shop/apps/php-shop/logs-clear/plan?service=web&instance=1", nil); code != 200 || p["clearable"] != false || p["reason"] != "unsupported-log-driver" || p["driver"] != "syslog" {
		t.Fatalf("syslog plan: %d %v", code, p)
	}
	bobLogin(t, f)
	if code, _ := f.do("GET", "/api/v1/t/shop/apps/php-shop/logs-clear/plan?service=db&instance=1", nil); code != 403 {
		t.Fatalf("viewer plan: %d", code)
	}
}

// /observe logs between since and until (Unix seconds).
func TestObserveUntil(t *testing.T) {
	f, _ := newFakeFixture(t)
	fakeLogin(t, f, "alice")
	code, all := f.do("POST", "/api/v1/t/shop/apps/php-shop/observe", map[string]any{"service": "web", "kind": "logs", "tail": 20})
	if code != 200 || len(all["logs"].([]any)) < 4 {
		t.Fatalf("all: %d %v", code, all)
	}
	lines := all["logs"].([]any)
	from, to := lines[1].(map[string]any)["time"].(float64), lines[2].(map[string]any)["time"].(float64)
	// The fake's lines are 5 s apart and dated from now: a second may pass
	// between the two reads, so until has 2 s of slack (still short of the
	// next line).
	code, part := f.do("POST", "/api/v1/t/shop/apps/php-shop/observe", map[string]any{"service": "web", "kind": "logs", "tail": 20, "since": from, "until": to + 2})
	if code != 200 || len(part["logs"].([]any)) != 2 {
		t.Fatalf("between: %d %v", code, part)
	}
	if code, _ := f.do("POST", "/api/v1/t/shop/apps/php-shop/observe", map[string]any{"service": "web", "kind": "logs", "since": to, "until": from}); code != 400 {
		t.Fatalf("until before since: %d", code)
	}
}
