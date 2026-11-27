// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/web/provlog"
)

func providerLogFixture(t *testing.T) (*fixture, *provlog.Log, func(time.Duration)) {
	f, _ := newFakeFixture(t)
	var mu sync.Mutex
	now := time.Date(2026, 11, 26, 3, 0, 0, 0, time.UTC)
	l, err := provlog.Open(t.TempDir(), provlog.Options{Now: func() time.Time { mu.Lock(); defer mu.Unlock(); return now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	f.srv.opt.ProviderLog = l
	return f, l, func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
}

func bearerGet(t *testing.T, f *fixture, path, tok string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest("GET", f.http.URL+path, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req) // no cookies: the token alone
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestProviderLogLifecycle(t *testing.T) {
	f, l, advance := providerLogFixture(t)
	fakeLogin(t, f, "alice")
	if code, _ := f.do("POST", "/api/v1/diag/provider-log/enable", nil); code != 403 {
		t.Fatalf("non-admin enable: %d", code)
	}
	if code, _ := f.do("GET", "/api/v1/diag/provider-log", nil); code != 403 {
		t.Fatalf("non-admin read: %d", code)
	}
	fakeLogin(t, f, "admin")
	_, st := f.do("GET", "/api/v1/diag/provider-log/state", nil)
	if st["enabled"] != false || st["disabledReason"] != "restart" {
		t.Fatalf("must start off: %v", st)
	}
	l.Add(provlog.Entry{Provider: "dns:hostinger", Op: "GetZone"})
	code, out := f.do("POST", "/api/v1/diag/provider-log/enable", nil)
	if code != 200 {
		t.Fatalf("enable: %d %v", code, out)
	}
	tok := out["token"].(string)
	l.Add(provlog.Entry{Provider: "dns:hostinger", Op: "Apply", Level: provlog.Error, Error: "boom"})

	code, out = bearerGet(t, f, "/api/v1/diag/provider-log?provider=dns:", tok)
	if code != 200 {
		t.Fatalf("token read: %d %v", code, out)
	}
	ents := out["page"].(map[string]any)["entries"].([]any)
	if len(ents) != 1 || ents[0].(map[string]any)["op"] != "Apply" {
		t.Fatalf("entries before enable must not be kept: %v", ents)
	}
	if code, _ := bearerGet(t, f, "/api/v1/diag/provider-log", "mpl_wrong"); code != 401 {
		t.Fatalf("wrong token: %d", code)
	}
	if code, _ := bearerGet(t, f, "/api/v1/diag/provider-log/state", tok); code != 401 {
		t.Fatalf("state/enable are for the web session only: %d", code)
	}
	if code, out := bearerGet(t, f, "/api/v1/diag/provider-log?tail=1", tok); code != 200 || len(out["page"].(map[string]any)["entries"].([]any)) != 1 {
		t.Fatalf("tail: %d %v", code, out)
	}

	// download as JSON lines
	req, _ := http.NewRequest("GET", f.http.URL+"/api/v1/diag/provider-log/download", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.Header.Get("Content-Type") != "application/x-ndjson" || !strings.Contains(string(body), `"op":"Apply"`) {
		t.Fatalf("download: %s %s", resp.Header.Get("Content-Type"), body)
	}

	// an idle hour ends collection and the token
	advance(61 * time.Minute)
	if code, _ := bearerGet(t, f, "/api/v1/diag/provider-log", tok); code != 401 {
		t.Fatalf("token after an idle hour: %d", code)
	}
	_, st = f.do("GET", "/api/v1/diag/provider-log/state", nil)
	if st["enabled"] != false || st["disabledReason"] != "idle" {
		t.Fatalf("state after idle: %v", st)
	}
	// the administrator can still read what was collected
	if code, out := f.do("GET", "/api/v1/diag/provider-log", nil); code != 200 || len(out["page"].(map[string]any)["entries"].([]any)) == 0 {
		t.Fatalf("admin read after idle: %d %v", code, out)
	}

	_, out = f.do("POST", "/api/v1/diag/provider-log/enable", nil)
	tok2 := out["token"].(string)
	if code, out := f.do("POST", "/api/v1/diag/provider-log/disable", nil); code != 200 || out["enabled"] != false {
		t.Fatalf("disable: %d %v", code, out)
	}
	if code, _ := bearerGet(t, f, "/api/v1/diag/provider-log", tok2); code != 401 {
		t.Fatalf("token after disable: %d", code)
	}
}

func TestProviderLogStream(t *testing.T) {
	f, l, advance := providerLogFixture(t)
	old := providerLogPing
	providerLogPing = 20 * time.Millisecond
	t.Cleanup(func() { providerLogPing = old })
	fakeLogin(t, f, "admin")
	_, out := f.do("POST", "/api/v1/diag/provider-log/enable", nil)
	tok := out["token"].(string)
	first := l.Add(provlog.Entry{Provider: "dns:hostinger", Op: "Check"})
	l.Add(provlog.Entry{Provider: "acme:letsencrypt", Op: "NewOrder"})

	req, _ := http.NewRequest("GET", f.http.URL+"/api/v1/diag/provider-log/stream?provider=dns:", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Last-Event-ID", "0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	next := func() (string, string) {
		var ev, id string
		for sc.Scan() {
			line := sc.Text()
			switch {
			case strings.HasPrefix(line, "event: "):
				ev = line[7:]
			case strings.HasPrefix(line, "id: "):
				id = line[4:]
			case line == "" && ev != "":
				return ev, id
			}
		}
		return "", ""
	}
	if ev, _ := next(); ev != "state" {
		t.Fatalf("first event %q", ev)
	}
	if ev, id := next(); ev != "entry" || id != "2" && id != "1" {
		t.Fatalf("backlog: %s %s", ev, id)
	} else if id != "2" || first.Seq != 2 {
		// seq 1 is the diag-enable note (provider sfc-web), filtered out
		t.Fatalf("backlog entry seq %s, first %d", id, first.Seq)
	}
	l.Add(provlog.Entry{Provider: "dns:hostinger", Op: "Apply"})
	if ev, id := next(); ev != "entry" || id != "4" {
		t.Fatalf("live: %s %s", ev, id)
	}
	advance(2 * time.Hour)
	if ev, _ := next(); ev != "expired" {
		t.Fatalf("want expired, got %q", ev)
	}
}
