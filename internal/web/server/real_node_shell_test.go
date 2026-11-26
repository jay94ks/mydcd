// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/websocket"

	"github.com/jay94ks/mydcd/internal/web/mydc"
	"github.com/jay94ks/mydcd/tests/clusterfixture"
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

// The server shell through the web on real mydcd: the administrator turns
// it on for node-0 and grants alice, node-0 prepares the mydc-shell account
// and reaches the test SSH server, and alice runs a shell there.
func TestRealServerNodeShell(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	f, c := newRealFixture(t, ctx, 2, clusterfixture.NodeShell(t, "node-0"))
	op := realOpID()
	realShopOn(t, c)
	alice, _ := realMembers(t, c)
	if code, out := keyLogin(f, "admin", c.Admin.Private); code != 200 {
		t.Fatalf("admin login: %d %v", code, out)
	}
	// node-0's readiness reports move the node shell root, so a change
	// signed just before one fails its CAS; it is sent again.
	put := func(path string, body map[string]any) {
		t.Helper()
		c.Wait("put "+path, func() bool {
			body["opId"] = op()
			code, out := f.do("PUT", "/api/v1/node-shell"+path, body)
			switch opState(t, code, out) {
			case "applied":
				return true
			case "failed":
				if out["op"].(map[string]any)["resultCode"] == float64(mydc.ResultConditionFailed) {
					return false
				}
			}
			t.Fatalf("%s %v: %d %v", path, body, code, out)
			return false
		})
	}
	if code, out := f.do("PUT", "/api/v1/node-shell", map[string]any{"opId": op(), "idleSeconds": 10}); code != 422 {
		t.Fatalf("bad idle: %d %v", code, out)
	}
	put("", map[string]any{"enabled": true})
	if code, out := f.do("PUT", "/api/v1/node-shell/nodes/node-0", map[string]any{"opId": op(), "shell": "maybe"}); code != 422 {
		t.Fatalf("bad shell: %d %v", code, out)
	}
	put("/nodes/node-0", map[string]any{"shell": "on"})
	put("/grants/u-alice", map[string]any{"nodes": []string{"node-0"}})
	var pol map[string]any
	c.Wait("node-0 shell ready", func() bool {
		_, pol = f.do("GET", "/api/v1/node-shell", nil)
		return strings.Contains(fmt.Sprint(pol["nodes"]), "node:node-0 ready:true")
	})
	if pol["enabled"] != true || !strings.Contains(fmt.Sprint(pol["grants"]), "nodes:[node-0]") {
		t.Fatalf("policy: %v", pol)
	}

	if code, out := keyLogin(f, "alice", alice.Private); code != 200 {
		t.Fatalf("alice login: %d %v", code, out)
	}
	if c, out := f.do("PUT", "/api/v1/node-shell", map[string]any{"opId": op(), "enabled": false}); c == 200 && opState(t, c, out) == "applied" {
		t.Fatalf("alice set policy: %v", out)
	}
	// mydcd refuses before the socket opens: alice has no grant on node-1
	var ra string
	c.Wait("node-1 refused", func() bool {
		ra = op()
		_, code, out := shellDial(t, f, "node-1", ra, true)
		if code == 409 && errCode(out) == "conflict" {
			return false // the root moved under it, as above
		}
		if code != 403 || errCode(out) != "forbidden" {
			t.Fatalf("node-1: %d %v", code, out)
		}
		return true
	})
	if code, got := f.do("GET", "/api/v1/ops/"+ra, nil); code != 200 || got["op"].(map[string]any)["state"] != "failed" {
		t.Fatalf("refused op: %d %v", code, got)
	}
	var o string
	var conn *websocket.Conn
	var first map[string]any
	c.Wait("shell open", func() bool {
		o = op()
		var code int
		var out map[string]any
		if conn, code, out = shellDial(t, f, "node-0", o); conn == nil {
			t.Fatalf("open: %d %v", code, out)
		}
		conn.SetReadDeadline(time.Now().Add(20 * time.Second))
		first = nil
		if err := websocket.JSON.Receive(conn, &first); err != nil {
			t.Fatalf("first: %v", err)
		}
		if first["type"] == "error" && first["code"] == "conflict" {
			conn.Close() // the root moved under it, as above
			return false
		}
		return true
	})
	defer conn.Close()
	recv := func() map[string]any {
		t.Helper()
		var m map[string]any
		conn.SetReadDeadline(time.Now().Add(20 * time.Second))
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
	sess, _ := first["session"].(map[string]any)
	if first["type"] != "session" || sess["node"] != "node-0" || sess["account"] != mydc.NodeShellAccount || sess["sudo"] != false {
		t.Fatalf("session: %v", first)
	}
	screen("$ ")
	_ = websocket.JSON.Send(conn, map[string]any{"type": "resize", "cols": 120, "rows": 40})
	_ = websocket.JSON.Send(conn, map[string]any{"type": "stdin", "data": []byte("whoami; stty size\r")})
	if s := screen("40 120"); !strings.Contains(s, mydc.NodeShellAccount+"\r\n") {
		t.Fatalf("whoami: %q", s)
	}
	// listed opened once node-0's report lands (it may be sent again)
	c.Wait("session opened", func() bool {
		code, list := f.do("GET", "/api/v1/node-shell/sessions", nil)
		items, _ := list["items"].([]any)
		if code != 200 || len(items) != 1 {
			t.Fatalf("sessions: %d %v", code, list)
		}
		return items[0].(map[string]any)["state"] == "opened"
	})
	if _, code, out := shellDial(t, f, "node-0", o, true); code != 409 || errCode(out) != "shell-used" {
		t.Fatalf("reused opId: %d %v", code, out)
	}
	_ = websocket.JSON.Send(conn, map[string]any{"type": "stdin", "data": []byte("exit 3\r")})
	for {
		if m := recv(); m["type"] == "end" {
			if m["reason"] != "exit" || m["code"] != float64(3) {
				t.Fatalf("end: %v", m)
			}
			break
		}
	}
	c.Wait("session closed", func() bool {
		_, cl := f.do("GET", "/api/v1/node-shell/sessions?state=closed&node=node-0", nil)
		return cl["total"] == float64(1)
	})
	if code, act := f.do("GET", "/api/v1/node-shell/sessions?active=1", nil); code != 200 || act["total"] != float64(0) {
		t.Fatalf("active sessions: %d %v", code, act)
	}
	if code, got := f.do("GET", "/api/v1/ops/"+o, nil); code != 200 || got["op"].(map[string]any)["state"] != "applied" || strings.Contains(fmt.Sprint(got), "whoami") {
		t.Fatalf("op: %d %v", code, got)
	}
	if code, _ := f.do("GET", "/api/v1/node-shell/sessions?state=gone", nil); code != 400 {
		t.Fatalf("bad state: %d", code)
	}

	// the administrator closes alice's second shell; it ends with reason
	// closed
	var conn2 *websocket.Conn
	var m map[string]any
	c.Wait("second open", func() bool {
		var code int
		var out map[string]any
		if conn2, code, out = shellDial(t, f, "node-0", op()); conn2 == nil {
			t.Fatalf("second open: %d %v", code, out)
		}
		conn2.SetReadDeadline(time.Now().Add(20 * time.Second))
		m = nil
		if err := websocket.JSON.Receive(conn2, &m); err != nil {
			t.Fatalf("second first: %v", err)
		}
		if m["type"] == "error" && m["code"] == "conflict" {
			conn2.Close()
			return false
		}
		return true
	})
	defer conn2.Close()
	if m["type"] != "session" {
		t.Fatalf("second session: %v", m)
	}
	id := m["session"].(map[string]any)["sessionId"].(string)
	if code, out := keyLogin(f, "admin", c.Admin.Private); code != 200 {
		t.Fatalf("admin login again: %d %v", code, out)
	}
	c.Wait("forced close", func() bool {
		code, out := f.do("POST", "/api/v1/node-shell/sessions/"+id+"/close", map[string]any{"opId": op()})
		switch opState(t, code, out) {
		case "applied":
			return true
		case "failed":
			if out["op"].(map[string]any)["resultCode"] == float64(mydc.ResultConditionFailed) {
				return false
			}
		}
		t.Fatalf("close: %d %v", code, out)
		return false
	})
	for {
		m = map[string]any{}
		conn2.SetReadDeadline(time.Now().Add(20 * time.Second))
		if err := websocket.JSON.Receive(conn2, &m); err != nil {
			t.Fatalf("closed: %v", err)
		}
		if m["type"] == "error" {
			t.Fatalf("closed: %v", m)
		}
		if m["type"] == "end" {
			if by, _ := m["closedBy"].(map[string]any); m["reason"] != "closed" || by["user"] != "u-admin" {
				t.Fatalf("forced end: %v", m)
			}
			break
		}
	}
	// closing a session that is gone: mydcd refuses
	if code, out := f.do("POST", "/api/v1/node-shell/sessions/sh-99/close", map[string]any{"opId": op()}); code == 200 && opState(t, code, out) == "applied" {
		t.Fatalf("close gone: %v", out)
	}
}
