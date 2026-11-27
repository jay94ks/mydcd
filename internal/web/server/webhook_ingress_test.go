// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/web/sfc"
	"github.com/jay94ks/seafield/internal/web/store"
)

func TestWebhookIngress(t *testing.T) {
	f, fake, clock := incidentFixture(t)
	hs := newHookServer(t, f)
	ctx := context.Background()
	fakeLogin(t, f, "admin")
	makeAutomation(t, f, "sfc-autofix", "a1b2c3d4-0000-4000-8000-0000000000a5", true, true)
	if code, out := f.do("POST", "/api/v1/webhooks", map[string]any{"name": "ops", "kind": "external", "url": hs.URL + "/ops", "role": "notify"}); code != 201 {
		t.Fatalf("webhook: %d %v", code, out)
	}
	gw := map[string]any{"gateway": "external"}
	app := map[string]any{"tenant": "shop", "app": "php-shop"}
	for _, bad := range []map[string]any{
		{"scope": map[string]any{"gateway": "external", "tenant": "shop"}, "events": []string{"down"}},
		{"scope": map[string]any{"gateway": "other"}, "events": []string{"down"}},
		{"scope": gw, "events": []string{"no-backends"}},
		{"scope": app, "events": []string{"down"}},
		{"scope": map[string]any{"tenant": "shop"}, "events": []string{"no-backends"}},
		{"scope": map[string]any{"tenant": "shop", "route": "r1"}, "events": []string{"no-backends"}},
		{"scope": app, "events": []string{"no-backends"}, "threshold": 2},
		{"scope": app, "events": []string{"error-rate", "latency"}, "threshold": 2},
		{"scope": app, "events": []string{"error-rate"}, "threshold": 200},
		{"scope": app, "events": []string{"error-rate"}, "minutes": -1},
	} {
		bad["point"], bad["webhook"] = "ingress", "ops"
		if code, out := f.do("POST", "/api/v1/webhook-links", bad); code != 422 {
			t.Fatalf("%v: %d %v", bad, code, out)
		}
	}
	for _, l := range []map[string]any{
		{"scope": gw, "events": []string{"down"}, "recover": true},
		{"scope": app, "events": []string{"error-rate"}, "threshold": 2, "minutes": 3, "recover": true},
		{"scope": map[string]any{"tenant": "shop", "app": "php-shop", "route": "r-other"}, "events": []string{"no-backends", "probe-failed"}},
	} {
		l["point"], l["webhook"] = "ingress", "ops"
		if code, out := f.do("POST", "/api/v1/webhook-links", l); code != 201 {
			t.Fatalf("link: %d %v", code, out)
		}
	}
	sent := func() string {
		hs.mu.Lock()
		defer hs.mu.Unlock()
		var ev []string
		for _, r := range hs.got {
			ev = append(ev, r.Header.Get("X-SFC-Event"))
		}
		sort.Strings(ev) // sent in the background, in any order
		return strings.Join(ev, ",")
	}
	round := func() {
		f.srv.watchOnce(ctx)
		f.srv.hooks.wg.Wait()
	}
	round() // start reading (incident response is off; the links keep the watcher on)

	fake.AddIngressEvent(sfc.EventIngressListenerDown, "node-a", "", "", sfc.IngressEvent{Gateway: sfc.GatewayExternal, Listener: "l-443"})
	fake.AddIngressEvent(sfc.EventIngressListenerDown, "node-a", "", "", sfc.IngressEvent{Gateway: sfc.GatewayLocal, Listener: "l-local"})
	// 1% is under the link's 2%; 5% waits 3 minutes. The web makes these
	// samples itself from the route's recent metrics (routeSamples).
	rate := func(v float64) {
		f.srv.ingressEvent(webEvent{Time: clock.Load(), Kind: webRouteMetric, Scope: "app", Tenant: "shop", App: "php-shop", Node: "node-a", Target: "shop/php-shop/r1",
			Ingress: &webIngressEvent{Gateway: sfc.GatewayExternal, RouteID: "r1", Host: "shop.example.com", Prefix: "/", Metric: metric5xx, Value: v}})
	}
	rate(0.01)
	rate(0.05)
	// Another route than the link's.
	fake.AddIngressEvent(sfc.EventIngressBackendsEmpty, "node-a", "shop", "php-shop", sfc.IngressEvent{Gateway: sfc.GatewayExternal, RouteID: "r1"})
	round()
	if s := sent(); s != "ingress.down" {
		t.Fatalf("first round: %q", s)
	}
	_, body := hs.last()
	var p map[string]any
	_ = json.Unmarshal(body, &p)
	if in := p["ingress"].(map[string]any); in["gateway"] != "external" || in["listener"] != nil || p["state"] != "firing" || p["point"] != "ingress" {
		t.Fatalf("down body: %v", p)
	}

	clock.Add(200)
	round()
	if s := sent(); s != "ingress.down,ingress.error-rate" {
		t.Fatalf("after 3 minutes: %q", s)
	}
	rate(0.05)
	rate(0.001)
	fake.AddIngressEvent(sfc.EventIngressListenerUp, "node-a", "", "", sfc.IngressEvent{Gateway: sfc.GatewayExternal, Listener: "l-443"})
	round()
	if s := sent(); s != "ingress.down,ingress.down.recovered,ingress.error-rate,ingress.error-rate.recovered" {
		t.Fatalf("recoveries: %q", s)
	}

	// A recovery before the minutes pass drops the notice.
	rate(0.05)
	round()
	rate(0.001)
	clock.Add(200)
	round()
	if s := sent(); strings.Count(s, ",") != 3 {
		t.Fatalf("dropped notice: %q", s)
	}
	// A task's health check has no route: the route link takes it.
	fake.AddEvent(sfc.FixtureEvent{Time: clock.Load(), Scope: "app", Tenant: "shop", App: "php-shop", Kind: "probe-failed", Target: "shop/php-shop/web.1"})
	round()
	if s := sent(); strings.Count(s, ",") != 4 || !strings.Contains(s, "ingress.probe-failed") {
		t.Fatalf("probe-failed: %q", s)
	}
	// group: the same block twice in 10 minutes is sent once.
	if code, out := f.do("POST", "/api/v1/webhook-links", map[string]any{"point": "ingress", "webhook": "ops", "scope": gw, "events": []string{"blocked"}, "group": true}); code != 201 {
		t.Fatalf("group link: %d %v", code, out)
	}
	for i := 0; i < 2; i++ {
		fake.AddEvent(sfc.FixtureEvent{Time: clock.Load(), Scope: "cluster", Kind: "ingress-blocked", Target: "blk-1"})
		round()
	}
	if s := sent(); strings.Count(s, "ingress.blocked") != 1 {
		t.Fatalf("group: %q", s)
	}

	_, ls := f.do("GET", "/api/v1/webhook-links?point=ingress", nil)
	var cond, last []string
	for _, it := range ls["items"].([]any) {
		l := it.(map[string]any)
		cond = append(cond, fmt.Sprint(l["condition"]))
		if x, ok := l["last"].(map[string]any); ok {
			last = append(last, fmt.Sprint(x["status"]))
		}
	}
	if !strings.Contains(strings.Join(cond, "|"), "5xx 2% 넘게 3분") || len(last) != 4 || last[0] != "200" {
		t.Fatalf("links: %v %v", cond, last)
	}

	// Gateway links are the system administrator's.
	fakeLogin(t, f, "alice")
	if code, out := f.do("POST", "/api/v1/webhook-links", map[string]any{"point": "ingress", "scope": gw, "events": []string{"down"}, "webhook": "ops"}); code != 403 {
		t.Fatalf("alice gateway link: %d %v", code, out)
	}
}

// certificate-expiring is the web's own check of the certificates the
// gateways serve (payments-wild on node-c's local gateway ends in 10 days).
func TestWebhookIngressPolled(t *testing.T) {
	f, _, clock := incidentFixture(t)
	hs := newHookServer(t, f)
	ctx := context.Background()
	fakeLogin(t, f, "admin")
	makeAutomation(t, f, "sfc-autofix", "a1b2c3d4-0000-4000-8000-0000000000a6", true, true)
	if code, out := f.do("POST", "/api/v1/webhooks", map[string]any{"name": "ops", "kind": "external", "url": hs.URL + "/ops", "role": "notify"}); code != 201 {
		t.Fatalf("webhook: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/webhook-links", map[string]any{"point": "ingress", "webhook": "ops", "scope": map[string]any{"gateway": "local"},
		"events": []string{"certificate-expiring", "limit-90", "recovered"}}); code != 201 {
		t.Fatalf("link: %d %v", code, out)
	}
	for i := 0; i < 3; i++ { // the second and third rounds read nothing new
		f.srv.watchOnce(ctx)
		f.srv.hooks.wg.Wait()
		clock.Add(int64(ingressPollEvery / time.Second))
	}
	hs.mu.Lock()
	defer hs.mu.Unlock()
	if len(hs.got) != 1 || hs.got[0].Header.Get("X-SFC-Event") != "ingress.certificate-expiring" {
		t.Fatalf("sent %d", len(hs.got))
	}
	var p map[string]any
	_ = json.Unmarshal(hs.bodies[0], &p)
	if in := p["ingress"].(map[string]any); in["node"] != "node-c" || in["gateway"] != "local" {
		t.Fatalf("body: %v", p)
	}
}

// error-rate and latency come from the routes' recent metrics, which the
// web reads itself (sfcd makes no event of them).
func TestWebhookIngressRouteMetrics(t *testing.T) {
	f, fake, _ := incidentFixture(t)
	hs := newHookServer(t, f)
	ctx := context.Background()
	fakeLogin(t, f, "admin")
	makeAutomation(t, f, "sfc-autofix", "a1b2c3d4-0000-4000-8000-0000000000a7", true, true)

	var iv *ingressView
	if err := withAdminConn(t, fake, func(c sfc.Conn) (err error) { iv, err = ingressRead(ctx, c, control.IngressQuery{}); return }); err != nil {
		t.Fatal(err)
	}
	link := &store.WebhookLink{Point: "ingress", Scope: store.WebhookLinkScope{Tenant: "shop", App: "php-shop"}, Events: []string{"error-rate"}}
	var samples []webEvent
	_ = withAdminConn(t, fake, func(c sfc.Conn) error {
		samples = f.srv.routeSamples(ctx, c, iv, []*store.WebhookLink{link}, time.Now())
		return nil
	})
	routes := map[string]bool{}
	var share float64
	for _, e := range samples {
		if e.Kind != webRouteMetric || e.Tenant != "shop" || e.App != "php-shop" || e.Ingress == nil || e.Ingress.RouteID == "" || e.Target != "shop/php-shop/"+e.Ingress.RouteID {
			t.Fatalf("sample: %+v", e)
		}
		routes[e.Ingress.RouteID] = true
		if e.Ingress.Metric == metric5xx {
			share = max(share, e.Ingress.Value)
		}
	}
	if len(routes) == 0 || len(samples) != 2*len(routes) || share <= 0 || share >= 1 {
		t.Fatalf("samples: %d over %v, worst 5xx %v", len(samples), routes, share)
	}

	// end to end: a line under the fake's share fires once, then stays.
	if code, out := f.do("POST", "/api/v1/webhooks", map[string]any{"name": "ops", "kind": "external", "url": hs.URL + "/ops", "role": "notify"}); code != 201 {
		t.Fatalf("webhook: %d %v", code, out)
	}
	if code, out := f.do("POST", "/api/v1/webhook-links", map[string]any{"point": "ingress", "webhook": "ops", "scope": map[string]any{"tenant": "shop", "app": "php-shop"},
		"events": []string{"error-rate"}, "threshold": share * 100 / 2}); code != 201 {
		t.Fatalf("link: %d %v", code, out)
	}
	for range 2 {
		f.srv.watchOnce(ctx)
		f.srv.hooks.wg.Wait()
	}
	hs.mu.Lock()
	defer hs.mu.Unlock()
	if len(hs.got) == 0 || hs.got[0].Header.Get("X-SFC-Event") != "ingress.error-rate" {
		t.Fatalf("sent %d", len(hs.got))
	}
	var p map[string]any
	_ = json.Unmarshal(hs.bodies[0], &p)
	if in := p["ingress"].(map[string]any); in["metric"] != metric5xx || in["threshold"] == nil || in["route"] == nil {
		t.Fatalf("body: %v", p)
	}
	n := len(hs.got)
	hs.mu.Unlock()
	f.srv.watchOnce(ctx) // within the minute: not read again
	f.srv.hooks.wg.Wait()
	hs.mu.Lock()
	if len(hs.got) != n {
		t.Fatalf("sent again: %d", len(hs.got))
	}
}
