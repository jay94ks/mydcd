// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bufio"
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

const (
	opSa1 = "b1b2c3d4-0000-4000-8000-000000000001"
	opSa2 = "b1b2c3d4-0000-4000-8000-000000000002"
	opSa3 = "b1b2c3d4-0000-4000-8000-000000000003"
	opSa4 = "b1b2c3d4-0000-4000-8000-000000000004"
)

const tempShell = `name: try-shell
lifetime: temp
ttl: 1h
grace: 10m
mode: shell
image: busybox:1.36
networks: [shop-net]
x-sfc: {node: node-b}
`

func standaloneNames(out map[string]any) map[string]map[string]any {
	m := map[string]map[string]any{}
	for _, it := range out["items"].([]any) {
		v := it.(map[string]any)
		m[v["name"].(string)] = v
	}
	return m
}

func TestStandaloneLifecycle(t *testing.T) {
	f, fake := newFakeFixture(t)
	fakeLogin(t, f, "alice")

	code, out := f.do("GET", "/api/v1/t/shop/standalone", nil)
	names := standaloneNames(out)
	if code != 200 || names["shop-cron"] == nil || names["alice-debug"] == nil {
		t.Fatalf("list: %d %v", code, out)
	}
	if v := names["alice-debug"]; v["lifetime"] != "temp" || v["ownerName"] != "alice" || v["yaml"] == "" || v["expiresAt"] == nil {
		t.Fatalf("row: %v", v)
	}

	code, out = f.do("POST", "/api/v1/t/shop/standalone/plan", map[string]any{"yaml": tempShell})
	if code != 200 || out["name"] != "try-shell" || out["create"] != true {
		t.Fatalf("plan: %d %v", code, out)
	}
	code, out = f.do("POST", "/api/v1/t/shop/standalone/up", map[string]any{"opId": opSa1, "yaml": tempShell})
	if code != 200 || opState(t, code, out) != "applied" || out["op"].(map[string]any)["target"] != "try-shell" || out["op"].(map[string]any)["action"] != "standalone-up" {
		t.Fatalf("up: %d %v", code, out)
	}
	code, out = f.do("GET", "/api/v1/t/shop/standalone/try-shell", nil)
	item, _ := out["item"].(map[string]any)
	if code != 200 || item["state"] == nil || item["revision"] == nil {
		t.Fatalf("get: %d %v", code, out)
	}
	rev := item["revision"]

	// a temp one's time left is extended (sfcd's StandaloneExtendChange)
	exp := item["expiresAt"].(float64)
	code, out = f.do("POST", "/api/v1/t/shop/standalone/try-shell/extend", map[string]any{"opId": "b1b2c3d4-0000-4000-8000-000000000011", "ttlSeconds": 7200})
	if code != 200 || opState(t, code, out) != "applied" {
		t.Fatalf("extend: %d %v", code, out)
	}
	_, out = f.do("GET", "/api/v1/t/shop/standalone/try-shell", nil)
	if item = out["item"].(map[string]any); item["expiresAt"].(float64) <= exp {
		t.Fatalf("after extend: %v (was %v)", item, exp)
	}
	rev = item["revision"]

	// temp → fixed with the row's Target and the revision as expected
	code, out = f.do("POST", "/api/v1/t/shop/standalone/try-shell/pin", map[string]any{"opId": opSa2, "expected": rev, "restart": "on-failure"})
	if code != 200 || opState(t, code, out) != "applied" {
		t.Fatalf("pin: %d %v", code, out)
	}
	// stop / start / restart through task-restart-plan
	for i, verb := range []string{"stop", "start", "restart"} {
		code, out = f.do("POST", "/api/v1/t/shop/standalone/try-shell/"+verb, map[string]any{"opId": "b1b2c3d4-0000-4000-8000-00000000002" + string(rune('0'+i))})
		if code != 200 || opState(t, code, out) != "applied" {
			t.Fatalf("%s: %d %v", verb, code, out)
		}
	}
	if code, _ := f.do("POST", "/api/v1/t/shop/standalone/try-shell/explode", map[string]any{"opId": "b1b2c3d4-0000-4000-8000-000000000029"}); code != 404 {
		t.Fatalf("unknown verb: %d", code)
	}
	_, out = f.do("GET", "/api/v1/t/shop/standalone/try-shell", nil)
	if out["item"].(map[string]any)["lifetime"] != "fixed" {
		t.Fatalf("after pin: %v", out)
	}

	// a count limit is its own error code
	fake.SetStandaloneLimits(1, 10)
	second := `name: try-two
lifetime: temp
mode: shell
image: busybox:1.36
x-sfc: {node: node-b}
`
	code, out = f.do("POST", "/api/v1/t/shop/standalone/up", map[string]any{"opId": opSa3, "yaml": second})
	if code != 409 || out["error"].(map[string]any)["code"] != "limit-user-temp" {
		t.Fatalf("limit: %d %v", code, out)
	}
	if _, err := f.store.GetOp("u-alice", opSa3); err == nil {
		t.Fatal("refused up was stored")
	}

	// observe the standalone container like an app task
	code, out = f.do("POST", "/api/v1/t/shop/standalone/shop-cron/observe", map[string]any{"kind": "logs", "tail": 5})
	if code != 200 {
		t.Fatalf("observe: %d %v", code, out)
	}
	// a bad definition is refused before signing
	if code, _ := f.do("POST", "/api/v1/t/shop/standalone/up", map[string]any{"opId": opSa4, "yaml": "name: [x"}); code < 400 {
		t.Fatalf("bad yaml accepted: %d", code)
	}
	if _, err := f.store.GetOp("u-alice", opSa4); err == nil {
		t.Fatal("refused definition was stored")
	}
}

func TestStandaloneViewerSeesNoOtherTemp(t *testing.T) {
	f, _ := newFakeFixture(t)
	bobLogin(t, f)
	code, out := f.do("GET", "/api/v1/t/shop/standalone?all=1", nil)
	names := standaloneNames(out)
	if code != 200 || names["shop-cron"] == nil || names["alice-debug"] != nil {
		t.Fatalf("viewer list: %d %v", code, out)
	}
	code, out = f.do("POST", "/api/v1/t/shop/standalone/up", map[string]any{"opId": opSa1, "yaml": tempShell})
	if code == 200 && opState(t, code, out) == "applied" {
		t.Fatalf("viewer created: %v", out)
	}
}

func TestStandaloneLogFollowSSE(t *testing.T) {
	f, fake := newFakeFixture(t)
	fake.SetStreamTick(0)
	fakeLogin(t, f, "alice")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", f.http.URL+"/api/v1/t/shop/standalone/shop-cron/stream?kind=logs&tail=2", nil)
	resp, err := f.hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("sse: %d", resp.StatusCode)
	}
	sc := bufio.NewScanner(resp.Body)
	sent := false
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "data: ") && strings.Contains(line, "hello-standalone") {
			return
		}
		if !sent && line == "event: target" {
			sent = true
			go func() {
				time.Sleep(100 * time.Millisecond)
				fake.EmitStandaloneLog("shop", "shop-cron", "stdout", "hello-standalone")
			}()
		}
	}
	t.Fatalf("no standalone log line (%v)", sc.Err())
}

func TestStandaloneImportedFrom(t *testing.T) {
	f, _ := newFakeFixture(t)
	fakeLogin(t, f, "alice")
	from := map[string]any{"app": "php-shop", "service": "web", "items": []string{"imageCmd", "volumes"}}

	// a bad origin is refused before anything is signed
	code, _ := f.do("POST", "/api/v1/t/shop/standalone/up", map[string]any{"opId": opSa1, "yaml": tempShell,
		"importedFrom": map[string]any{"app": "php-shop", "service": "web", "items": []string{"everything"}}})
	if code != 400 {
		t.Fatalf("bad items: %d", code)
	}

	code, out := f.do("POST", "/api/v1/t/shop/standalone/up", map[string]any{"opId": opSa1, "yaml": tempShell, "importedFrom": from})
	if code != 200 || opState(t, code, out) != "applied" {
		t.Fatalf("up: %d %v", code, out)
	}
	_, out = f.do("GET", "/api/v1/t/shop/standalone/try-shell", nil)
	item := out["item"].(map[string]any)
	im, _ := item["importedFrom"].(map[string]any)
	if im["app"] != "php-shop" || im["service"] != "web" || im["by"] != "alice" || len(im["items"].([]any)) != 2 {
		t.Fatalf("importedFrom: %v", item)
	}
	_, out = f.do("GET", "/api/v1/t/shop/standalone", nil)
	if standaloneNames(out)["try-shell"]["importedFrom"] == nil || standaloneNames(out)["shop-cron"]["importedFrom"] != nil {
		t.Fatalf("list: %v", out)
	}

	// a failed up does not change what is shown; an applied plain up clears it
	rev := item["revision"]
	code, out = f.do("POST", "/api/v1/t/shop/standalone/up", map[string]any{"opId": opSa2, "yaml": tempShell, "expected": 999999})
	if code != 200 || opState(t, code, out) == "applied" {
		t.Fatalf("stale up applied: %d %v", code, out)
	}
	if _, out = f.do("GET", "/api/v1/t/shop/standalone/try-shell", nil); out["item"].(map[string]any)["importedFrom"] == nil {
		t.Fatalf("failed up cleared origin: %v", out)
	}
	code, out = f.do("POST", "/api/v1/t/shop/standalone/up", map[string]any{"opId": opSa3, "yaml": tempShell + "workdir: /tmp\n", "expected": rev})
	if code != 200 || opState(t, code, out) != "applied" {
		t.Fatalf("plain up: %d %v", code, out)
	}
	if _, out = f.do("GET", "/api/v1/t/shop/standalone/try-shell", nil); out["item"].(map[string]any)["importedFrom"] != nil {
		t.Fatalf("plain up kept origin: %v", out)
	}

	// an up with an origin, a pin that renames it (the origin moves), then
	// remove: the origin is forgotten. Targets are the frontend's display form.
	code, out = f.do("POST", "/api/v1/t/shop/standalone/up", map[string]any{"opId": opSa4, "yaml": tempShell, "expected": out["item"].(map[string]any)["revision"], "importedFrom": from})
	if code != 200 || opState(t, code, out) != "applied" {
		t.Fatalf("re-up: %d %v", code, out)
	}
	_, out = f.do("GET", "/api/v1/t/shop/standalone/try-shell", nil)
	code, out = f.do("POST", "/api/v1/t/shop/standalone/try-shell/pin", map[string]any{"opId": "b1b2c3d4-0000-4000-8000-000000000005",
		"expected": out["item"].(map[string]any)["revision"], "newName": "keep-shell", "restart": "on-failure"})
	if code != 200 || opState(t, code, out) != "applied" {
		t.Fatalf("pin: %d %v", code, out)
	}
	_, out = f.do("GET", "/api/v1/t/shop/standalone/keep-shell", nil)
	item = out["item"].(map[string]any)
	if im, _ := item["importedFrom"].(map[string]any); im["app"] != "php-shop" {
		t.Fatalf("origin after rename: %v", item)
	}
	if o, _ := f.store.StandaloneOrigin("shop", "try-shell"); o != nil {
		t.Fatalf("old name kept origin: %v", o)
	}
	code, out = f.do("POST", "/api/v1/t/shop/standalone/keep-shell/remove", map[string]any{"opId": "b1b2c3d4-0000-4000-8000-000000000006", "expected": item["revision"]})
	if code != 200 || opState(t, code, out) != "applied" {
		t.Fatalf("remove: %d %v", code, out)
	}
	if o, err := f.store.StandaloneOrigin("shop", "keep-shell"); err != nil || o != nil {
		t.Fatalf("origin after remove: %v %v", o, err)
	}
}

// A protected Group waits on the standalone-up original like a deploy's
// begin-app; the same approve endpoint continues the job.
func TestStandaloneUpGroupApproval(t *testing.T) {
	f, fake := newFakeFixture(t)
	fakeLogin(t, f, "alice")
	fake.SetGroupPassword("shop", "shop-db", "open-sesame")
	def := "name: sec-shell\nlifetime: fixed\nmode: shell\nimage: busybox:1.36\nnetworks: [shop-net]\nx-sfc:\n  node: node-b\n  secrets: {from: [group/shop-db]}\n"
	op := "b1b2c3d4-0000-4000-8000-000000000031"
	code, out := f.do("POST", "/api/v1/t/shop/standalone/up", map[string]any{"opId": op, "yaml": def})
	o, _ := out["op"].(map[string]any)
	if code != 202 && code != 200 || o["state"] != "running" || o["errorCode"] != "approval-required" {
		t.Fatalf("up: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/t/shop/apps/deploy/"+op+"/approve", map[string]any{"group": "shop-db", "password": "open-sesame"}); code != 200 || opState(t, code, out) != "applied" {
		t.Fatalf("approve: %d %v", code, out)
	}
	if code, out := f.do("GET", "/api/v1/t/shop/standalone/sec-shell", nil); code != 200 || out["item"].(map[string]any)["lifetime"] != "fixed" {
		t.Fatalf("get: %d %v", code, out)
	}
}

func TestStandaloneHostPortConflict(t *testing.T) {
	f, _ := newFakeFixture(t)
	fakeLogin(t, f, "alice")
	def := func(name string) string {
		return "name: " + name + "\nlifetime: fixed\nimage: busybox:1.36\nnetworks: [shop-net]\nports: [\"18080:80\"]\nx-sfc: {node: node-b}\n"
	}
	if code, out := f.do("POST", "/api/v1/t/shop/standalone/up", map[string]any{"opId": "b1b2c3d4-0000-4000-8000-000000000041", "yaml": def("port-a")}); code != 200 || opState(t, code, out) != "applied" {
		t.Fatalf("first: %d %v", code, out)
	}
	code, out := f.do("POST", "/api/v1/t/shop/standalone/plan", map[string]any{"yaml": def("port-b")})
	if code != 409 || out["error"].(map[string]any)["code"] != "host-port-conflict" {
		t.Fatalf("second: %d %v", code, out)
	}
}
