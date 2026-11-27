// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bufio"
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/websocket"

	"github.com/jay94ks/seafield/internal/web/sfc"
)

func fakeLogin(t *testing.T, f *fixture, user string) {
	t.Helper()
	_, out := f.do("POST", "/api/v1/auth/credential/challenge", map[string]any{"username": user, "method": "password"})
	if code, out := f.do("POST", "/api/v1/auth/credential/login", map[string]any{"ticketId": out["ticketId"], "secret": user}); code != 200 {
		t.Fatalf("login %s: %d %v", user, code, out)
	}
}

func TestFakeLogFollowSSE(t *testing.T) {
	f, fake := newFakeFixture(t)
	fake.SetStreamTick(0)
	fakeLogin(t, f, "alice")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", f.http.URL+"/api/v1/t/shop/apps/php-shop/stream?kind=logs&service=web&tail=2", nil)
	resp, err := f.hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("sse: %d %v", resp.StatusCode, resp.Header)
	}
	sc := bufio.NewScanner(resp.Body)
	var events []string
	emitted := false
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "event: ") {
			events = append(events, strings.TrimPrefix(line, "event: "))
		}
		if strings.HasPrefix(line, "data: ") && strings.Contains(line, "hello-web") {
			break
		}
		if !emitted && len(events) > 0 && events[len(events)-1] == "target" && line == "" {
			emitted = true
			go func() {
				time.Sleep(100 * time.Millisecond)
				fake.EmitLog("shop", "php-shop", "web", "stdout", "hello-web")
			}()
		}
	}
	if len(events) == 0 || events[0] != "target" {
		t.Fatalf("events: %v (%v)", events, sc.Err())
	}
	found := false
	for _, e := range events {
		if e == "stdout" || e == "stderr" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no log event: %v", events)
	}
}

func TestFakeExecTerminal(t *testing.T) {
	f, fake := newFakeFixture(t)
	fake.SetIdleTimeout(0)
	fakeLogin(t, f, "alice")
	cfg, _ := websocket.NewConfig(strings.Replace(f.http.URL, "http", "ws", 1)+
		"/api/v1/t/shop/apps/php-shop/exec?opId="+opA+"&service=web&cmd=sh&tty=1&stdin=1&rows=24&cols=80", f.http.URL)
	u := mustURL(f.http.URL)
	cfg.Header = http.Header{}
	for _, c := range f.hc.Jar.Cookies(u) {
		cfg.Header.Add("Cookie", c.Name+"="+c.Value)
	}
	conn, err := websocket.DialConfig(cfg)
	if err != nil {
		req, _ := http.NewRequest("GET", cfg.Location.String(), nil)
		req.URL.Scheme = "http"
		req.Header = cfg.Header.Clone()
		req.Header.Set("Origin", f.http.URL)
		resp, _ := http.DefaultClient.Do(req)
		var b strings.Builder
		bufio.NewReader(resp.Body).WriteTo(&b)
		t.Fatalf("%v: %d %s", err, resp.StatusCode, b.String())
	}
	recv := func() map[string]any {
		t.Helper()
		var m map[string]any
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if err := websocket.JSON.Receive(conn, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	if m := recv(); m["type"] != "receipt" {
		t.Fatalf("first record: %v", m)
	}
	op, err := f.store.GetOp("u-alice", opA)
	if err != nil || op.Action != "exec" || len(op.Signed) == 0 {
		t.Fatalf("exec op must be stored before open: %+v %v", op, err)
	}
	websocket.JSON.Send(conn, execMsg{Type: "resize", Rows: 30, Cols: 100})
	websocket.JSON.Send(conn, execMsg{Type: "stdin", Data: []byte("ls\n")})
	if m := recv(); m["type"] != "stdout" || m["text"] != "ls\n" {
		t.Fatalf("echo: %v", m)
	}
	conn.Close()

	// status of the same original: still running, detached
	time.Sleep(100 * time.Millisecond)
	code, out := f.do("POST", "/api/v1/ops/"+opA+"/result", nil)
	if code != 202 || out["exec"] == nil {
		t.Fatalf("exec status: %d %v", code, out)
	}
	if code, _ := f.do("POST", "/api/v1/ops/"+opA+"/resume", nil); code != 409 {
		t.Fatalf("exec resume must be refused: %d", code)
	}

	// a cross-origin terminal is refused
	bad, _ := websocket.NewConfig(cfg.Location.String(), "https://evil.example")
	bad.Header = cfg.Header
	if _, err := websocket.DialConfig(bad); err == nil {
		t.Fatal("cross-origin exec accepted")
	}
}

func TestFakeExecViewerDenied(t *testing.T) {
	f, _ := newFakeFixture(t)
	priv := sfc.FixtureKey("bob")
	if code, out := keyLogin(f, "bob", priv); code != 200 {
		t.Fatalf("bob login: %d %v", code, out)
	}
	req, _ := http.NewRequest("GET", f.http.URL+"/api/v1/t/shop/apps/php-shop/exec?opId="+opA+"&service=web&cmd=sh", nil)
	req.Header.Set("Origin", f.http.URL)
	resp, err := f.hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("viewer exec: %d", resp.StatusCode)
	}
	if _, err := f.store.GetOp("u-bob", opA); err == nil {
		t.Fatal("a denied exec must not be stored")
	}
}

func TestLogoutEndsOpenStreams(t *testing.T) {
	f, fake := newFakeFixture(t)
	fake.SetIdleTimeout(0)
	fake.SetStreamTick(0)
	fakeLogin(t, f, "alice")

	// a terminal
	cfg, _ := websocket.NewConfig(strings.Replace(f.http.URL, "http", "ws", 1)+
		"/api/v1/t/shop/apps/php-shop/exec?opId="+opA+"&service=web&cmd=sh&tty=1&stdin=1&rows=24&cols=80", f.http.URL)
	cfg.Header = http.Header{}
	for _, c := range f.hc.Jar.Cookies(mustURL(f.http.URL)) {
		cfg.Header.Add("Cookie", c.Name+"="+c.Value)
	}
	conn, err := websocket.DialConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var m map[string]any
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err := websocket.JSON.Receive(conn, &m); err != nil || m["type"] != "receipt" {
		t.Fatalf("first record: %v %v", m, err)
	}

	// a log follow
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", f.http.URL+"/api/v1/t/shop/apps/php-shop/stream?kind=logs&service=web&tail=1", nil)
	resp, err := f.hc.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("sse: %v %v", resp, err)
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	if !sc.Scan() || !strings.HasPrefix(sc.Text(), "event: target") {
		t.Fatalf("sse first line: %q", sc.Text())
	}

	if code, out := f.do("POST", "/api/v1/auth/logout", nil); code/100 != 2 {
		t.Fatalf("logout: %d %v", code, out)
	}

	// the terminal ends: an error record or a closed socket, never more output
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		var m map[string]any
		err := websocket.JSON.Receive(conn, &m)
		if err != nil {
			if ne, ok := err.(interface{ Timeout() bool }); ok && ne.Timeout() {
				t.Fatal("terminal still open after logout")
			}
			break
		}
		if m["type"] == "error" || m["type"] == "end" {
			break
		}
	}

	// the log follow ends too
	done := make(chan bool, 1)
	go func() {
		for sc.Scan() {
			if strings.HasPrefix(sc.Text(), "event: error") || strings.HasPrefix(sc.Text(), "event: end") {
				break
			}
		}
		done <- true
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("log follow still open after logout")
	}
}
