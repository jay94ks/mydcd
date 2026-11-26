// SPDX-License-Identifier: Apache-2.0

package provlog

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

func TestOffByDefaultAndIdleExpiry(t *testing.T) {
	c := &clock{t: time.Date(2026, 11, 26, 0, 0, 0, 0, time.UTC)}
	l, err := Open("", Options{Now: c.now})
	if err != nil {
		t.Fatal(err)
	}
	l.Add(Entry{Provider: "dns:x", Op: "GetZone"})
	if st := l.State(); st.Enabled || st.Last != 0 || st.DisabledReason != "restart" {
		t.Fatalf("collection must start off and keep nothing: %+v", st)
	}
	tok, st, err := l.Enable("jay")
	if err != nil || !st.Enabled || !strings.HasPrefix(tok, "mpl_") {
		t.Fatalf("enable: %v %+v", err, st)
	}
	if l.Authorize("wrong") || !l.Authorize(tok) {
		t.Fatal("token check")
	}
	c.add(59 * time.Minute)
	l.Add(Entry{Provider: "dns:x", Op: "GetZone"}) // activity
	c.add(59 * time.Minute)
	if !l.Authorize(tok) {
		t.Fatal("activity must keep collection on")
	}
	c.add(time.Hour)
	if l.Authorize(tok) {
		t.Fatal("token must expire after an idle hour")
	}
	st = l.State()
	if st.Enabled || st.DisabledReason != "idle" {
		t.Fatalf("state after idle: %+v", st)
	}
	n := st.Last
	l.Add(Entry{Provider: "dns:x"})
	if l.State().Last != n {
		t.Fatal("entries after expiry must be dropped")
	}
	// enabling again gives a new token; the old one stays dead
	tok2, _, _ := l.Enable("jay")
	if tok2 == tok || l.Authorize(tok) || !l.Authorize(tok2) {
		t.Fatal("re-enable must replace the token")
	}
	l.Disable("jay")
	if l.Authorize(tok2) || l.State().DisabledReason != "user" {
		t.Fatal("disable")
	}
}

func TestMaxLifetime(t *testing.T) {
	c := &clock{t: time.Date(2026, 11, 26, 0, 0, 0, 0, time.UTC)}
	l, _ := Open("", Options{Now: c.now})
	tok, _, _ := l.Enable("jay")
	for i := 0; i < 24*2; i++ {
		c.add(30 * time.Minute)
		l.Add(Entry{Provider: "dns:x", Op: "GetZone"}) // periodic calls keep it from idling
	}
	if l.Authorize(tok) || l.State().DisabledReason != "limit" {
		t.Fatalf("collection must end %v after it was turned on: %+v", MaxLifetime, l.State())
	}
	tok, _, _ = l.Enable("jay")
	if !l.Authorize(tok) || !l.State().ExpiresAt.Equal(c.now().Add(IdleLimit)) {
		t.Fatalf("enabling again starts anew: %+v", l.State())
	}
}

func TestScrub(t *testing.T) {
	for _, in := range []string{
		`{"access_token":"s1","client_secret":"s2","apiToken":"s3","x-api-key":"s4","hmacKey":"s5","password":"s\"6"}`,
		`grant_type=refresh&refresh_token=s1&client_secret=s2&scope=dns`,
		`Authorization: Bearer s1`,
	} {
		out := Scrub(in)
		for _, bad := range []string{"s1", "s2", "s3", "s4", "s5", `s\"6`} {
			if strings.Contains(out, bad) {
				t.Errorf("%q leaked in %s", bad, out)
			}
		}
	}
	if out := Scrub(`grant_type=refresh&scope=dns`); out != `grant_type=refresh&scope=dns` {
		t.Fatalf("plain form fields must stay: %s", out)
	}
	if out := Scrub(`{"name":"www","content":"1.2.3.4"}`); out != `{"name":"www","content":"1.2.3.4"}` {
		t.Fatalf("plain JSON must stay: %s", out)
	}
}

func TestPersistAndList(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(dir, Options{MaxFile: 600})
	if err != nil {
		t.Fatal(err)
	}
	l.Enable("jay")
	for i := 0; i < 10; i++ {
		op := "GetZone"
		lvl := Info
		if i%3 == 0 {
			op, lvl = "Apply", Error
		}
		l.Add(Entry{Provider: "dns:hostinger", Op: op, Level: lvl, Msg: "n"})
	}
	l.Add(Entry{Provider: "acme:letsencrypt", Op: "NewOrder"})
	p := l.List(Filter{Provider: "dns:", Level: Error}, 0, 2)
	if len(p.Entries) != 2 || !p.More || p.Entries[0].Op != "Apply" {
		t.Fatalf("page: %+v", p)
	}
	p2 := l.List(Filter{Provider: "dns:", Level: Error}, p.Next, 10)
	if len(p2.Entries) != 2 || p2.More {
		t.Fatalf("page 2: %+v", p2)
	}
	last := l.State().Last
	l.Close()

	// rotation kept one old file; a restart loads both and continues seq
	l2, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	if l2.State().Enabled {
		t.Fatal("a restart must start with collection off")
	}
	p3 := l2.List(Filter{}, 0, 0)
	if len(p3.Entries) == 0 || p3.Last != last {
		t.Fatalf("reload: last %d want %d, %d entries", p3.Last, last, len(p3.Entries))
	}
	l2.Enable("jay")
	if e := l2.Add(Entry{Provider: "dns:x"}); e.Seq <= last {
		t.Fatalf("seq must continue: %d", e.Seq)
	}
}

func TestSubscribe(t *testing.T) {
	l, _ := Open("", Options{})
	l.Enable("jay")
	c, cancel := l.Subscribe()
	l.Add(Entry{Provider: "dns:x", Op: "Check"})
	e := <-c
	if e.Op != "Check" {
		t.Fatalf("%+v", e)
	}
	cancel()
	if _, ok := <-c; ok {
		t.Fatal("cancel must close")
	}
}

func TestTransportRedacts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Correlation-Id", "corr-1")
		w.Header().Set("Set-Cookie", "s=secret")
		w.WriteHeader(422)
		io.WriteString(w, `{"message":"bad","token":"abc"}`)
	}))
	defer srv.Close()
	l, _ := Open("", Options{})
	l.Enable("jay")
	cl := &http.Client{Transport: Transport(nil, l, Source{Provider: "dns:hostinger", Conn: "c1", Classify: func(int, []byte) string { return "invalid" }})}
	req, _ := http.NewRequestWithContext(WithOp(t.Context(), "Apply"), "PUT", srv.URL+"/api/x?api_key=zzz&page=2", strings.NewReader(`{"zone":[],"password":"p"}`))
	req.Header.Set("Authorization", "Bearer sekret-token")
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	if string(b) != `{"message":"bad","token":"abc"}` {
		t.Fatalf("caller must get the body unchanged: %s", b)
	}
	p := l.List(Filter{Provider: "dns:hostinger"}, 0, 0)
	if len(p.Entries) != 1 {
		t.Fatalf("%+v", p)
	}
	e := p.Entries[0]
	all := e.HTTP.URL + e.HTTP.Request + e.HTTP.Response
	for _, bad := range []string{"zzz", "sekret", `"p"`, "abc", "secret"} {
		if strings.Contains(all, bad) {
			t.Errorf("secret %q leaked: %+v", bad, e.HTTP)
		}
	}
	if e.Op != "Apply" || e.Level != Warn || e.Kind != "invalid" || e.HTTP.Status != 422 || e.HTTP.Headers["X-Correlation-Id"] != "corr-1" || e.HTTP.Headers["Set-Cookie"] != "" {
		t.Fatalf("%+v %+v", e, e.HTTP)
	}
	if !strings.Contains(e.HTTP.URL, "page=2") {
		t.Fatalf("url: %s", e.HTTP.URL)
	}
}

func TestTransportOffLogsNothing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	l, _ := Open("", Options{})
	cl := &http.Client{Transport: Transport(nil, l, Source{Provider: "dns:x"})}
	if _, err := cl.Get(srv.URL); err != nil {
		t.Fatal(err)
	}
	if l.State().Last != 0 {
		t.Fatal("logged while off")
	}
}

func TestTruncate(t *testing.T) {
	s := Truncate(strings.Repeat("가", 10), 7)
	if !strings.HasPrefix(s, "가가…") {
		t.Fatalf("%q", s)
	}
}
