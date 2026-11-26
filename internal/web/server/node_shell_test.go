// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/websocket"

	"github.com/jay94ks/mydcd/internal/web/mydc"
)

// shellDial dials the server shell socket with the fixture's cookies.
// refused: send a plain GET instead and return the HTTP status and body.
func shellDial(t *testing.T, f *fixture, node, opID string, refused ...bool) (*websocket.Conn, int, map[string]any) {
	t.Helper()
	path := "/api/v1/nodes/" + node + "/shell?opId=" + opID + "&cols=80&rows=24"
	cfg, _ := websocket.NewConfig(strings.Replace(f.http.URL, "http", "ws", 1)+path, f.http.URL)
	cfg.Header = http.Header{}
	for _, c := range f.hc.Jar.Cookies(mustURL(f.http.URL)) {
		cfg.Header.Add("Cookie", c.Name+"="+c.Value)
	}
	if len(refused) == 0 {
		conn, err := websocket.DialConfig(cfg)
		if err != nil {
			t.Fatalf("dial %s: %v", path, err)
		}
		return conn, 101, nil
	}
	req, _ := http.NewRequest("GET", f.http.URL+path, nil)
	req.Header = cfg.Header.Clone()
	req.Header.Set("Origin", f.http.URL)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return nil, resp.StatusCode, out
}

func TestNodeShell(t *testing.T) {
	f, fake := newFakeFixture(t)
	fake.SetIdleTimeout(0)
	n := 0
	op := func() string { n++; return fmt.Sprintf("e1b2c3d4-0000-4000-8000-%012d", n) }
	fakeLogin(t, f, "alice")

	code, pol := f.do("GET", "/api/v1/node-shell", nil)
	if code != 200 || !strings.Contains(fmt.Sprint(pol["nodes"]), "node:node-b") {
		t.Fatalf("policy for alice: %d %v", code, pol)
	}
	// mydcd refuses before the socket opens: not granted on node-a
	ra := op()
	if _, code, out := shellDial(t, f, "node-a", ra, true); code != 403 || errCode(out) != "forbidden" {
		t.Fatalf("node-a: %d %v", code, out)
	}
	// the refused submit is the op's outcome
	if code, got := f.do("GET", "/api/v1/ops/"+ra, nil); code != 200 || got["op"].(map[string]any)["state"] != "failed" || got["op"].(map[string]any)["errorCode"] != "forbidden" {
		t.Fatalf("refused op: %d %v", code, got)
	}

	// the same refusal on the socket: one error message, then it closes
	if c, _, _ := shellDial(t, f, "node-a", op()); c != nil {
		var m map[string]any
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if err := websocket.JSON.Receive(c, &m); err != nil || m["type"] != "error" || m["code"] != "forbidden" || m["status"] != float64(403) {
			t.Fatalf("socket refusal: %v %v", m, err)
		}
		if err := websocket.JSON.Receive(c, &m); err == nil {
			t.Fatalf("socket stays open: %v", m)
		}
		c.Close()
	}
	o := op()
	conn, code, out := shellDial(t, f, "node-b", o)
	if conn == nil {
		t.Fatalf("open: %d %v", code, out)
	}
	defer conn.Close()
	recv := func() map[string]any {
		t.Helper()
		var m map[string]any
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if err := websocket.JSON.Receive(conn, &m); err != nil {
			t.Fatalf("recv: %v", err)
		}
		return m
	}
	screen := func(until string) string {
		t.Helper()
		var b strings.Builder
		for !strings.Contains(b.String(), until) {
			m := recv()
			switch m["type"] {
			case "stdout":
				var data []byte
				raw, _ := json.Marshal(m["data"])
				_ = json.Unmarshal(raw, &data)
				b.Write(data)
			case "end", "error":
				t.Fatalf("ended before %q: %v (%q)", until, m, b.String())
			}
		}
		return b.String()
	}
	first := recv()
	sess, _ := first["session"].(map[string]any)
	if first["type"] != "session" || sess["node"] != "node-b" || sess["account"] != mydc.NodeShellAccount || sess["sudo"] != false {
		t.Fatalf("session: %v", first)
	}
	screen("$ ")
	_ = websocket.JSON.Send(conn, map[string]any{"type": "resize", "cols": 120, "rows": 40})
	_ = websocket.JSON.Send(conn, map[string]any{"type": "stdin", "data": []byte("whoami\r")})
	if s := screen(mydc.NodeShellAccount + "\r\n"); !strings.Contains(s, "whoami") {
		t.Fatalf("whoami: %q", s)
	}
	// the open session is listed (its byte counts only)
	code, list := f.do("GET", "/api/v1/node-shell/sessions", nil)
	if items, _ := list["items"].([]any); code != 200 || len(items) != 1 || items[0].(map[string]any)["bytesIn"] == float64(0) ||
		items[0].(map[string]any)["state"] != "opened" || items[0].(map[string]any)["sessionId"] != "shell-"+o || list["total"] != float64(1) {
		t.Fatalf("sessions: %d %v", code, list)
	}
	// a used opId never opens a second shell
	if _, code, out := shellDial(t, f, "node-b", o, true); code != 409 || errCode(out) != "shell-used" {
		t.Fatalf("reused opId: %d %v", code, out)
	}
	if c, _, _ := shellDial(t, f, "node-b", o); c != nil {
		var m map[string]any
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if err := websocket.JSON.Receive(c, &m); err != nil || m["code"] != "shell-used" || m["status"] != float64(409) {
			t.Fatalf("socket reused opId: %v %v", m, err)
		}
		c.Close()
	}
	_ = websocket.JSON.Send(conn, map[string]any{"type": "stdin", "data": []byte("exit\r")})
	for {
		m := recv()
		if m["type"] == "end" {
			if m["reason"] != "exit" || m["code"] != float64(0) {
				t.Fatalf("end: %v", m)
			}
			break
		}
	}
	// the op holds the signed open request and the outcome, no screen
	time.Sleep(50 * time.Millisecond)
	code, got := f.do("GET", "/api/v1/ops/"+o, nil)
	if opv, _ := got["op"].(map[string]any); code != 200 || opv["state"] != "applied" || strings.Contains(fmt.Sprint(got), "whoami") {
		t.Fatalf("op: %d %v", code, got)
	}

	// the ended session stays in the list, closed, with its end; active=1
	// leaves it out
	if code, act := f.do("GET", "/api/v1/node-shell/sessions?active=1", nil); code != 200 || len(act["items"].([]any)) != 0 || act["total"] != float64(0) {
		t.Fatalf("active sessions: %d %v", code, act)
	}
	if code, cl := f.do("GET", "/api/v1/node-shell/sessions?state=closed&node=node-b", nil); code != 200 || cl["total"] != float64(1) {
		t.Fatalf("closed sessions: %d %v", code, cl)
	}
	if code, _ := f.do("GET", "/api/v1/node-shell/sessions?state=gone", nil); code != 400 {
		t.Fatalf("bad state: %d", code)
	}
	code, list = f.do("GET", "/api/v1/node-shell/sessions", nil)
	if items, _ := list["items"].([]any); code != 200 || len(items) != 1 || items[0].(map[string]any)["state"] != "closed" ||
		items[0].(map[string]any)["closedAt"] == nil || fmt.Sprint(items[0].(map[string]any)["end"]) != "map[code:0 reason:exit]" {
		t.Fatalf("sessions after exit: %d %v", code, list)
	}

	// a forced close ends the browser's shell with reason closed
	conn2, code, out := shellDial(t, f, "node-b", op())
	if conn2 == nil {
		t.Fatalf("second open: %d %v", code, out)
	}
	defer conn2.Close()
	var m map[string]any
	conn2.SetReadDeadline(time.Now().Add(5 * time.Second))
	_ = websocket.JSON.Receive(conn2, &m)
	fake.CloseNodeShellNow(m["session"].(map[string]any)["sessionId"].(string))
	for {
		m = map[string]any{}
		if err := websocket.JSON.Receive(conn2, &m); err != nil {
			t.Fatalf("closed: %v", err)
		}
		if m["type"] == "end" {
			by, _ := m["closedBy"].(map[string]any)
			if m["reason"] != "closed" || by["user"] != "u-admin" {
				t.Fatalf("forced end: %v", m)
			}
			break
		}
	}

	// settings and grants: alice cannot, the administrator can
	if c, out := f.do("PUT", "/api/v1/node-shell", map[string]any{"opId": op(), "enabled": true}); opState(t, c, out) == "applied" {
		t.Fatalf("alice set policy: %v", out)
	}
	fakeLogin(t, f, "admin")
	if c, out := f.do("PUT", "/api/v1/node-shell", map[string]any{"opId": op(), "idleSeconds": 10}); c != 422 {
		t.Fatalf("bad idle: %d %v", c, out)
	}
	po := op()
	if c, out := f.do("PUT", "/api/v1/node-shell", map[string]any{"opId": po, "enabled": true}); opState(t, c, out) != "applied" {
		t.Fatalf("set policy: %d %v", c, out)
	}
	var p mydc.SetNodeShellPolicy
	userPayload(t, f, "u-admin", po, &p)
	if !p.Enabled || p.MaxSessions == 0 || p.IdleSeconds == 0 {
		t.Fatalf("policy payload: %+v", p)
	}
	if c, out := f.do("PUT", "/api/v1/node-shell/nodes/node-a", map[string]any{"opId": op(), "shell": "maybe"}); c != 422 {
		t.Fatalf("bad shell: %d %v", c, out)
	}
	if c, out := f.do("PUT", "/api/v1/node-shell/nodes/node-a", map[string]any{"opId": op(), "shell": "on", "sudo": true}); opState(t, c, out) != "applied" {
		t.Fatalf("set node: %d %v", c, out)
	}
	if c, out := f.do("PUT", "/api/v1/node-shell/grants/u-alice", map[string]any{"opId": op(), "nodes": []string{"node-a", "node-b"}}); opState(t, c, out) != "applied" {
		t.Fatalf("grant: %d %v", c, out)
	}
	_, pol = f.do("GET", "/api/v1/node-shell", nil)
	if pol["enabled"] != true || !strings.Contains(fmt.Sprint(pol["grants"]), "nodes:[node-a node-b]") || !strings.Contains(fmt.Sprint(pol["nodes"]), "node:node-a ready:true shell:on sudo:true") {
		t.Fatalf("policy after: %v", pol)
	}
	// closing a session that is gone: mydcd refuses
	if c, out := f.do("POST", "/api/v1/node-shell/sessions/sh-99/close", map[string]any{"opId": op()}); opState(t, c, out) == "applied" {
		t.Fatalf("close gone: %v", out)
	}
}
