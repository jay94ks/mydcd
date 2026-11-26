// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestTaskDetailRoutes(t *testing.T) {
	f, fake := newFakeFixture(t)
	n := 0
	op := func() string { n++; return fmt.Sprintf("ab12c3d4-0000-4000-8000-%012d", n) }
	bobLogin(t, f)
	db := "/api/v1/t/shop/apps/php-shop/task"
	q := "?service=db&instance=1"
	code, out := f.do("GET", db+q, nil)
	if code != 200 || out["node"] != "node-b" || out["image"] != "mysql:8.4" {
		t.Fatalf("detail: %d %v", code, out)
	}
	if code, out := f.do("GET", "/api/v1/t/shop/apps/shop-worker/task/history?service=worker&instance=1", nil); code != 200 || len(out["exits"].([]any)) != 3 {
		t.Fatalf("history: %d %v", code, out)
	}
	if code, _ := f.do("GET", db+"/history"+q+"&limit=999", nil); code != 400 {
		t.Fatalf("bad limit: %d", code)
	}

	// Logs: secret values come masked; the cursor reads further back.
	fake.SetTaskSecretValue("shop", "php-shop", "db", "1", "mysql/MYSQL_PASSWORD", "hunter2")
	fake.AddTaskLog("shop", "php-shop", "db", "1", "connecting with password hunter2")
	code, out = f.do("GET", db+"/logs"+q+"&limit=50", nil)
	if code != 200 || out["masked"] != float64(1) || out["cursor"] == nil || len(out["lines"].([]any)) != 50 {
		t.Fatalf("logs: %d %v", code, out)
	}
	last := out["lines"].([]any)[49].(map[string]any)
	if strings.Contains(fmt.Sprint(last), "hunter2") || last["seq"] == nil {
		t.Fatalf("masked line: %v", last)
	}
	code, older := f.do("GET", db+"/logs"+q+"&limit=50&cursor="+out["cursor"].(string), nil)
	if code != 200 || older["lines"].([]any)[49].(map[string]any)["seq"].(float64) >= out["lines"].([]any)[0].(map[string]any)["seq"].(float64) {
		t.Fatalf("older: %d %v", code, older)
	}
	if code, out := f.do("GET", db+"/stats"+q, nil); code != 200 || len(out["items"].([]any)) == 0 {
		t.Fatalf("stats: %d %v", code, out)
	}

	// Relocation check: mydcd's plan, so a viewer is refused like a plan.
	if code, _ := f.do("GET", "/api/v1/t/shop/apps/php-shop/relocation-check?service=web&node=node-b", nil); code != 403 {
		t.Fatalf("viewer relocation: %d", code)
	}
	fakeLogin(t, f, "alice")
	code, out = f.do("GET", "/api/v1/t/shop/apps/php-shop/relocation-check?service=web&node=node-b", nil)
	if code != 200 || out["ok"] != true || out["from"] != "node-a" || fmt.Sprint(out["steps"]) != "[app]" {
		t.Fatalf("relocation: %d %v", code, out)
	}
	if code, _ := f.do("GET", "/api/v1/t/shop/apps/php-shop/relocation-check?service=web", nil); code != 400 {
		t.Fatalf("no node: %d", code)
	}
	// db with its own node-fixed mysql-data moves by a volume move; the
	// check is mydcd's plan of that move.
	code, out = f.do("GET", "/api/v1/t/shop/apps/php-shop/relocation-check?service=db&node=node-a", nil)
	if vs, _ := out["volumes"].([]any); code != 200 || fmt.Sprint(out["steps"]) != "[volume-move]" || len(vs) != 1 || vs[0].(map[string]any)["step"] != "move" {
		t.Fatalf("db relocation: %d %v", code, out)
	}
	if code, _ := f.do("GET", "/api/v1/t/shop/apps/php-shop/relocation-check?service=nope&node=node-a", nil); code != 404 {
		t.Fatalf("no service: %d", code)
	}
	bobLogin(t, f)

	// Restart: managers only (mydcd decides); Expected = the app revision.
	if code, out := f.do("POST", db+"/restart", map[string]any{"opId": op(), "service": "db", "instance": "1"}); opState(t, code, out) == "applied" {
		t.Fatalf("viewer restart: %d %v", code, out)
	}
	fakeLogin(t, f, "alice")
	if code, out := f.do("POST", db+"/restart", map[string]any{"opId": op(), "service": "db"}); code != 422 {
		t.Fatalf("no instance: %d %v", code, out)
	}
	if code, out := f.do("POST", db+"/restart", map[string]any{"opId": op(), "service": "db", "instance": "1"}); opState(t, code, out) != "applied" {
		t.Fatalf("restart: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/t/shop/apps/nope/task/restart", map[string]any{"opId": op(), "service": "db", "instance": "1"}); code != 404 {
		t.Fatalf("no app: %d %v", code, out)
	}
	if _, out := f.do("GET", "/api/v1/t/shop/apps/php-shop/task/history"+q, nil); !strings.Contains(fmt.Sprint(out["exits"]), "user") {
		t.Fatalf("restart in history: %v", out["exits"])
	}
}

// The web's own recovery of a volume file op whose reply was lost, and the
// same opId sent again (the file operations themselves run on real mydcd in
// TestRealServerVolumeFiles).
func TestVolumeFileRoutes(t *testing.T) {
	f, fake := newFakeFixture(t)
	n := 0
	op := func() string { n++; return fmt.Sprintf("ab12c3d4-0000-4000-8000-%012d", n) }
	raw := func(method, path string, body []byte) (int, string, http.Header) {
		t.Helper()
		req, _ := http.NewRequest(method, f.http.URL+path, bytes.NewReader(body))
		req.Header.Set("X-MyDC-Web", "1")
		res, err := f.hc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b), res.Header
	}
	base := "/api/v1/t/shop/volumes/uploads"
	const pre = "mydc-web-backups/"
	fakeLogin(t, f, "alice")
	content := []byte("first-volume-file-content-7f3c9a1e")
	if code, body, _ := raw("PUT", base+"/file?path="+pre+"a.db&opId="+op(), content); code != 200 || !strings.Contains(body, `"applied"`) {
		t.Fatalf("put: %d %s", code, body)
	}
	// A lost reply is settled from the job, never from the file found there:
	// after the write, the stored reply; before it, the same op streams again.
	fake.LoseNextReply("volume-file", true)
	if code, body, _ := raw("PUT", base+"/file?path="+pre+"b.db&opId="+op(), content); code != 200 || !strings.Contains(body, `"bytes":`+fmt.Sprint(len(content))) {
		t.Fatalf("lost after write: %d %s", code, body)
	}
	fake.LoseNextReply("volume-file", false)
	resumed := op()
	if code, body, _ := raw("PUT", base+"/file?path="+pre+"c.db&opId="+resumed, content); code != 200 || !strings.Contains(body, `"applied"`) {
		t.Fatalf("lost before write: %d %s", code, body)
	}
	// the same opId again: the stored op, nothing signed anew
	if code, body, _ := raw("PUT", base+"/file?path="+pre+"c.db&opId="+resumed, content); code != 200 || !strings.Contains(body, resumed) {
		t.Fatalf("same opId: %d %s", code, body)
	}
	if code, body, _ := raw("PUT", base+"/file?path="+pre+"c.db&opId="+resumed, []byte("other")); code != 409 {
		t.Fatalf("same opId, other content: %d %s", code, body)
	}
	for _, p := range []string{"b.db", "c.db"} {
		if code, out := f.do("DELETE", base+"/file", map[string]any{"opId": op(), "path": pre + p}); code != 200 {
			t.Fatalf("delete %s: %d %v", p, code, out)
		}
	}
	// The op records hold the path, size and digest, not the content.
	assertNowhere(t, f, string(content))
}
