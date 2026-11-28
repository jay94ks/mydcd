// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/web/sfc"
)

// hookServer is an https receiver that answers from a script of statuses
// (the last one repeats) and keeps what it got.
type hookServer struct {
	*httptest.Server
	mu       sync.Mutex
	statuses []int
	answer   string
	got      []*http.Request
	bodies   [][]byte
}

func newHookServer(t *testing.T, f *fixture) *hookServer {
	h := &hookServer{statuses: []int{200}}
	h.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		h.mu.Lock()
		h.got, h.bodies = append(h.got, r), append(h.bodies, b)
		st := h.statuses[0]
		if len(h.statuses) > 1 {
			h.statuses = h.statuses[1:]
		}
		ans := h.answer
		h.mu.Unlock()
		w.WriteHeader(st)
		_, _ = io.WriteString(w, ans)
	}))
	t.Cleanup(h.Close)
	pool := x509.NewCertPool()
	pool.AddCert(h.Certificate())
	f.srv.opt.WebhookTLS = &tls.Config{RootCAs: pool}
	f.srv.opt.WebhookAllowAddr = func(a netip.Addr) bool { return a.IsLoopback() }
	f.srv.hooks.backoff = []time.Duration{0, 0, 0}
	return h
}

func (h *hookServer) script(statuses ...int) {
	h.mu.Lock()
	h.statuses = statuses
	h.mu.Unlock()
}

func (h *hookServer) last() (*http.Request, []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.got[len(h.got)-1], h.bodies[len(h.bodies)-1]
}

func TestWebhooksExternal(t *testing.T) {
	f, _, clock := incidentFixture(t)
	hs := newHookServer(t, f)
	fakeLogin(t, f, "admin")
	for _, bad := range []map[string]any{
		{"name": "Ops", "kind": "external", "url": hs.URL, "role": "notify"},
		{"name": "ops", "kind": "external", "url": strings.Replace(hs.URL, "https", "http", 1), "role": "notify"},
		{"name": "ops", "kind": "external", "url": "https://10.0.0.1/hook", "role": "notify"},
		{"name": "ops", "kind": "external", "url": "https://u:p@example.com/hook", "role": "notify"},
		{"name": "ops", "kind": "external", "url": hs.URL, "role": "decide", "format": "slack"},
		{"name": "ops", "kind": "external", "url": hs.URL, "role": "notify", "sign": "token"},
	} {
		if code, out := f.do("POST", "/api/v1/webhooks", bad); code != 422 {
			t.Fatalf("%v: %d %v", bad, code, out)
		}
	}
	code, h := f.do("POST", "/api/v1/webhooks", map[string]any{"name": "ops", "kind": "external", "url": hs.URL + "/hook", "role": "notify"})
	sec, _ := h["secret"].(map[string]any)
	if code != 201 || h["sign"] != "hmac" || h["state"] != "ok" || sec == nil || !strings.HasPrefix(fmt.Sprint(sec["value"]), "whsec_") {
		t.Fatalf("create: %d %v", code, h)
	}
	secret := sec["value"].(string)
	if _, again := f.do("GET", "/api/v1/webhooks/ops", nil); fmt.Sprint(again["secret"]) != "map[set:true]" {
		t.Fatalf("secret shown again: %v", again)
	}
	if code, _ := f.do("POST", "/api/v1/webhooks", map[string]any{"name": "ops", "kind": "external", "url": hs.URL, "role": "notify"}); code != 409 {
		t.Fatalf("duplicate: %d", code)
	}

	// Test send: signed with the secret.
	code, out := f.do("POST", "/api/v1/webhooks/ops/test", nil)
	d, _ := out["delivery"].(map[string]any)
	if code != 200 || d["status"] != float64(200) || len(out["steps"].([]any)) != 3 {
		t.Fatalf("test: %d %v", code, out)
	}
	req, body := hs.last()
	sig := req.Header.Get("X-SFC-Signature")
	var ts int64
	var v1 string
	if _, err := fmt.Sscanf(sig, "t=%d,v1=%s", &ts, &v1); err != nil || v1 != webhookSign([]byte(secret), ts, body) || req.Header.Get("X-SFC-Event") != "test" {
		t.Fatalf("signature %q over %s", sig, body)
	}

	// Rotation: both signatures for a day.
	_, rot := f.do("POST", "/api/v1/webhooks/ops/rotate", nil)
	if rot["secret"].(map[string]any)["value"] == secret {
		t.Fatalf("rotate: %v", rot)
	}
	f.do("POST", "/api/v1/webhooks/ops/test", nil)
	if req, _ := hs.last(); strings.Count(req.Header.Get("X-SFC-Signature"), "v1=") != 2 {
		t.Fatalf("rotating signature: %s", req.Header.Get("X-SFC-Signature"))
	}

	// A notify delivery retries 5xx; three failed deliveries turn it off.
	hk, _ := f.srv.opt.Store.GetWebhook("ops")
	ctx := context.Background()
	hs.script(500, 429, 202)
	dl, _ := f.srv.deliverWebhook(ctx, hk, webhookSend{Point: "incident", Event: "incident.opened", Payload: map[string]any{}})
	if !dl.OK() || dl.Retries != 2 || dl.FirstStatus != 500 {
		t.Fatalf("retried: %+v", dl)
	}
	hs.script(500)
	for i := 0; i < 3; i++ {
		hk, _ = f.srv.opt.Store.GetWebhook("ops")
		if dl, _ = f.srv.deliverWebhook(ctx, hk, webhookSend{Point: "incident", Event: "incident.opened", Payload: map[string]any{}}); dl == nil || dl.OK() || dl.Retries != 3 {
			t.Fatalf("failing %d: %+v", i, dl)
		}
	}
	_, h = f.do("GET", "/api/v1/webhooks/ops", nil)
	st := h["stats"].(map[string]any)
	if h["enabled"] != false || h["state"] != "disabled" || h["disabledReason"] != "failures" || st["today"] != float64(4) || st["failed"] != float64(3) {
		t.Fatalf("turned off: %v", h)
	}
	hk, _ = f.srv.opt.Store.GetWebhook("ops")
	if dl, _ := f.srv.deliverWebhook(ctx, hk, webhookSend{Point: "incident", Event: "incident.opened"}); dl != nil {
		t.Fatal("sent while off")
	}
	_, ns := f.do("GET", "/api/v1/notifications", nil)
	if !strings.Contains(fmt.Sprint(ns), "webhook-off") {
		t.Fatalf("creator not told: %v", ns)
	}
	if code, h = f.do("PUT", "/api/v1/webhooks/ops", map[string]any{"revision": h["revision"], "enabled": true}); code != 200 || h["enabled"] != true {
		t.Fatalf("enable: %d %v", code, h)
	}
	_, ds := f.do("GET", "/api/v1/webhooks/ops/deliveries", nil)
	items := ds["items"].([]any)
	if len(items) != 6 || items[2].(map[string]any)["retries"] != float64(3) || items[3].(map[string]any)["firstStatus"] != float64(500) {
		t.Fatalf("deliveries: %v", ds)
	}

	// Workspace managers see neither cluster webhooks nor make them.
	fakeLogin(t, f, "alice")
	if code, _ := f.do("GET", "/api/v1/webhooks/ops", nil); code != 404 {
		t.Fatalf("alice reads cluster webhook: %d", code)
	}
	if code, _ := f.do("POST", "/api/v1/webhooks", map[string]any{"name": "mine", "kind": "external", "url": hs.URL, "role": "notify"}); code != 403 {
		t.Fatalf("alice cluster create: %d", code)
	}
	_ = clock
	fakeLogin(t, f, "admin")
	if code, _ := f.do("DELETE", "/api/v1/webhooks/ops", map[string]any{"confirmName": "ops"}); code != 200 {
		t.Fatalf("delete: %d", code)
	}
	if _, err := f.srv.opt.Seal.Get(webhookSecretKey("ops")); err == nil {
		t.Fatal("secret left sealed")
	}
}

// Sealed names of two webhooks never meet ("old-foo" vs "foo"), and a new
// webhook always gets a new secret.
func TestWebhookSecretNames(t *testing.T) {
	f, _, _ := incidentFixture(t)
	hs := newHookServer(t, f)
	fakeLogin(t, f, "admin")
	mk := func(name string) string {
		code, h := f.do("POST", "/api/v1/webhooks", map[string]any{"name": name, "kind": "external", "url": hs.URL, "role": "notify"})
		if code != 201 {
			t.Fatalf("create %s: %d %v", name, code, h)
		}
		return h["secret"].(map[string]any)["value"].(string)
	}
	sealed := func(name string) string {
		b, err := f.srv.opt.Seal.Get(webhookSecretKey(name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return string(b)
	}
	foo := mk("foo")
	f.do("POST", "/api/v1/webhooks/foo/rotate", nil)
	oldFoo := mk("old-foo")
	if oldFoo == foo || sealed("old-foo") != oldFoo {
		t.Fatal("old-foo reused foo's old secret")
	}
	f.do("POST", "/api/v1/webhooks/foo/rotate", nil)
	if sealed("old-foo") != oldFoo {
		t.Fatal("rotating foo overwrote old-foo")
	}
	if code, _ := f.do("DELETE", "/api/v1/webhooks/old-foo", map[string]any{"confirmName": "old-foo"}); code != 200 {
		t.Fatal("delete old-foo")
	}
	if _, err := f.srv.opt.Seal.Get(webhookOldSecretKey("foo")); err != nil {
		t.Fatal("deleting old-foo dropped foo's old secret")
	}
	// Deleted and made again: a new secret.
	f.do("DELETE", "/api/v1/webhooks/foo", map[string]any{"confirmName": "foo"})
	if again := mk("foo"); again == foo || sealed("foo") != again {
		t.Fatal("recreated foo kept a secret")
	}
	for _, a := range []string{"64:ff9b::a00:1", "100.64.1.1", "2001:db8::1", "198.18.0.1", "fd00::1"} {
		if (&Server{}).webhookAddrOK(netip.MustParseAddr(a)) {
			t.Fatalf("%s allowed", a)
		}
	}
	if !(&Server{}).webhookAddrOK(netip.MustParseAddr("93.184.216.34")) {
		t.Fatal("public address refused")
	}
}

func TestWebhooksInternalAndLinks(t *testing.T) {
	f, fake, _ := incidentFixture(t)
	var got sfc.ServiceCallRequest
	fake.SetServiceResponder("shop", "php-shop", "web", func(q sfc.ServiceCallRequest) sfc.ServiceResponse {
		got = q
		return sfc.ServiceResponse{Status: 202, ContentType: "application/json", Body: []byte(`{"action":"none"}`), ElapsedMS: 12, TLS: q.Port == 8443}
	})
	fakeLogin(t, f, "alice")
	target := map[string]any{"app": "php-shop", "service": "web", "port": 8080, "path": "/decide"}
	if code, _ := f.do("POST", "/api/v1/webhooks", map[string]any{"name": "bot", "kind": "internal", "target": target, "role": "decide"}); code != 422 {
		t.Fatalf("internal without workspace: %d", code)
	}
	// https inside the network: a plain port fails the handshake.
	for port, want := range map[int]string{8443: "", 8080: sfc.ServiceCallTLS} {
		name := fmt.Sprintf("tls-%d", port)
		tls := map[string]any{"app": "php-shop", "service": "web", "port": port, "path": "/decide", "scheme": "https"}
		if code, out := f.do("POST", "/api/v1/webhooks", map[string]any{"name": name, "tenant": "shop", "kind": "internal", "target": tls, "role": "notify"}); code != 201 {
			t.Fatalf("internal https: %d %v", code, out)
		}
		_, out := f.do("POST", "/api/v1/webhooks/"+name+"/test", nil)
		if e, _ := out["delivery"].(map[string]any)["error"].(string); e != want {
			t.Fatalf("https %d: %v", port, out)
		}
		f.do("DELETE", "/api/v1/webhooks/"+name, map[string]any{"confirmName": name})
	}
	code, h := f.do("POST", "/api/v1/webhooks", map[string]any{"name": "bot", "tenant": "shop", "kind": "internal", "target": target, "role": "decide",
		"sign": "token", "token": "s3cr3t-token-9876"})
	if code != 201 || fmt.Sprint(h["token"]) != "map[last4:9876 set:true]" || h["target"].(map[string]any)["scheme"] != "http" || h["secret"].(map[string]any)["set"] != false {
		t.Fatalf("create internal: %d %v", code, h)
	}
	code, out := f.do("POST", "/api/v1/webhooks/bot/test", nil)
	if code != 200 || out["delivery"].(map[string]any)["status"] != float64(202) || got.Headers["X-SFC-Token"] != "s3cr3t-token-9876" || got.Path != "/decide" ||
		!strings.Contains(fmt.Sprint(out["steps"]), "A JSON object with action, decision or result") {
		t.Fatalf("internal test: %d %v %+v", code, out, got)
	}
	fake.SetTaskReady("shop", "php-shop", "web", "1", false)
	_, out = f.do("POST", "/api/v1/webhooks/bot/test", nil)
	if e := out["delivery"].(map[string]any)["error"]; e != sfc.ServiceNoReadyTask {
		t.Fatalf("no ready task: %v", out)
	}
	code, n := f.do("POST", "/api/v1/webhooks", map[string]any{"name": "shop-chat", "tenant": "shop", "kind": "internal", "target": map[string]any{"app": "php-shop", "service": "web", "port": 8080, "path": "/chat"}, "role": "notify", "format": "slack", "sign": "none"})
	if code != 201 {
		t.Fatalf("notify webhook: %d %v", code, n)
	}

	// Links: inside the workspace, roles match the point.
	for _, bad := range []map[string]any{
		{"point": "incident", "scope": map[string]any{"tenant": "shop"}, "webhook": "shop-chat", "events": []string{}},
		{"point": "incident", "scope": map[string]any{"tenant": "shop"}, "webhook": "shop-chat", "events": []string{"exploded"}},
		{"point": "incident", "scope": map[string]any{}, "webhook": "shop-chat", "events": []string{"opened"}},
		{"point": "cd", "scope": map[string]any{"tenant": "shop", "app": "php-shop"}, "webhook": "shop-chat", "kind": "pre-sync"},
		{"point": "cd", "scope": map[string]any{"tenant": "shop", "app": "php-shop"}, "webhook": "bot", "kind": "post-sync", "onFail": "explode"},
	} {
		if code, out := f.do("POST", "/api/v1/webhook-links", bad); code != 422 && code != 403 {
			t.Fatalf("%v: %d %v", bad, code, out)
		}
	}
	if code, out := f.do("POST", "/api/v1/webhook-links", map[string]any{"point": "incident", "scope": map[string]any{"tenant": "shop", "app": "php-shop"}, "webhook": "shop-chat",
		"events": []string{"opened", "recovered"}}); code != 201 {
		t.Fatalf("incident link: %d %v", code, out)
	}
	code, pre := f.do("POST", "/api/v1/webhook-links", map[string]any{"point": "cd", "scope": map[string]any{"tenant": "shop", "app": "php-shop"}, "webhook": "bot", "kind": "pre-sync"})
	if code != 201 || pre["waitSeconds"] != float64(10) || pre["onTimeout"] != "hold" || pre["approver"].(map[string]any)["state"] != "missing" {
		t.Fatalf("pre-sync: %d %v", code, pre)
	}
	if code, _ := f.do("POST", "/api/v1/webhook-links", map[string]any{"point": "cd", "scope": map[string]any{"tenant": "shop", "app": "php-shop"}, "webhook": "bot", "kind": "pre-sync"}); code != 409 {
		t.Fatalf("second pre-sync: %d", code)
	}
	code, post := f.do("POST", "/api/v1/webhook-links", map[string]any{"point": "cd", "scope": map[string]any{"tenant": "shop", "app": "php-shop"}, "webhook": "bot", "kind": "post-sync",
		"openIncident": false})
	if code != 201 || post["when"] != "healthy" || post["onFail"] != "pause" || post["openIncident"] != nil {
		t.Fatalf("post-sync: %d %v", code, post)
	}
	_, hv := f.do("GET", "/api/v1/webhooks/bot", nil)
	if hv["links"] != float64(2) {
		t.Fatalf("links count: %v", hv)
	}

	// Viewers read the workspace's links but change nothing.
	bobLogin(t, f)
	_, ls := f.do("GET", "/api/v1/webhook-links?tenant=shop", nil)
	if len(ls["items"].([]any)) != 3 {
		t.Fatalf("bob links: %v", ls)
	}
	if code, _ := f.do("DELETE", "/api/v1/webhook-links/"+pre["id"].(string), nil); code != 404 {
		t.Fatalf("bob delete: %d", code)
	}
	if code, _ := f.do("GET", "/api/v1/webhooks/bot", nil); code != 404 {
		t.Fatalf("bob reads webhook: %d", code)
	}
	fakeLogin(t, f, "alice")
	if code, _ := f.do("DELETE", "/api/v1/webhook-links/"+pre["id"].(string), nil); code != 204 {
		t.Fatalf("alice delete: %d", code)
	}
}

// An internal webhook is sent again only when service-call never reached
// the app; an answered 429/5xx is retried for both kinds.
func TestWebhookRetryable(t *testing.T) {
	for _, c := range []struct {
		internal bool
		status   int
		code     string
		want     bool
	}{
		{true, 503, "", true}, {true, 429, "", true}, {true, 400, "", false},
		{true, 0, sfc.ServiceNoReadyTask, true}, {true, 0, sfc.ServiceCallRateLimited, true},
		{true, 0, sfc.ServiceCallTimeout, false}, {true, 0, sfc.ServiceCallRefused, false}, {true, 0, "unavailable", false}, {true, 0, sfc.ServiceCallTLS, false},
		{false, 502, "", true}, {false, 0, "timeout", true}, {false, 0, "connect", true}, {false, 0, "tls", false}, {false, 301, "redirect", false},
	} {
		if got := retryable(c.internal, c.status, c.code); got != c.want {
			t.Errorf("%+v: %v", c, got)
		}
	}
}
