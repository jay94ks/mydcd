// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/ingress"
	"github.com/jay94ks/mydcd/internal/web/mydc"
	"github.com/jay94ks/mydcd/internal/web/store"
)

// Ingress webhooks (UI-5A/5B, REQ-22 G events): the watcher hands the
// ingress events here and the notify links that cover them are sent to.
// A link with minutes waits that long before the notice, and drops it when
// the recovery comes first; with recover it also sends the recovery of a
// notice it sent. What is waiting or was sent is kept in memory only: after
// a restart, a recovery of an earlier notice is not sent. The minutes are
// counted from when the web read the event.

type ingressHookState struct {
	mu      sync.Mutex
	pending map[string]ingressPending // link/target/event → waiting notice
	fired   map[string]time.Time      // the notice went out (when)
	grouped map[string]time.Time      // group links: the last notice sent
	// ingressPoll: when it last read, and what was on (limit|cert|target).
	polledAt time.Time
	polled   map[string]bool
}

// ingressGroupWindow: a group link sends the same event of the same target
// once in this time.
const ingressGroupWindow = 10 * time.Minute

// ingressRepeat: an event without a recovery (a health check, a missing
// certificate) is sent again at most this often.
const ingressRepeat = 10 * time.Minute

func ingressHasRecovery(ev string) bool {
	return ev == "down" || ev == "no-backends" || ev == "error-rate" || ev == "latency" || ev == "blocked" || ev == "certificate-expiring" || ev == "limit-90"
}

type ingressPending struct {
	at    time.Time
	link  string
	event string
	e     webEvent
}

// ingressWebhookEvent maps a mydcd event to an ingress link event, and
// whether it is the recovery (ok false: not an ingress event).
func ingressWebhookEvent(e webEvent) (string, bool, bool) {
	route := e.Ingress != nil && e.Ingress.RouteID != ""
	switch e.Kind {
	case mydc.EventIngressListenerDown, mydc.EventIngressListenerUp:
		return "down", e.Kind == mydc.EventIngressListenerUp, !route
	case mydc.EventIngressCertMissing:
		if route {
			return "cert", false, true
		}
		return "tls-rejects", false, true
	case mydc.EventIngressSourceRejected:
		return "source-rejects", false, !route
	case mydc.EventIngressBackendsEmpty, mydc.EventIngressBackendsRestored:
		return "no-backends", e.Kind == mydc.EventIngressBackendsRestored, route
	case webRouteMetric:
		// The web's own sample of a route's recent metrics; whether it is
		// over or a recovery is each link's threshold (ingressEvent).
		if e.Ingress == nil {
			return "", false, false
		}
		ev := "error-rate"
		if e.Ingress.Metric == metricP95 {
			ev = "latency"
		}
		return ev, false, true
	case webCertExpiring, webCertRenewed:
		return "certificate-expiring", e.Kind == webCertRenewed, true
	case webLimitOver, webLimitUnder:
		return "limit-90", e.Kind == webLimitUnder, true
	case "probe-failed":
		// A task's health check (app scope): for the links of that app.
		return "probe-failed", false, e.Scope == "app" && e.Tenant != "" && e.App != ""
	case "ingress-blocked", "ingress-unblocked":
		return "blocked", e.Kind == "ingress-unblocked", true
	}
	return "", false, false
}

// ingressLinkCovers: l is for e (gateway links take events without a
// workspace on their gateway; app links the events of the app, and of the
// route when they name one and the event has one).
func ingressLinkCovers(l *store.WebhookLink, e webEvent) bool {
	if l.Scope.Gateway != "" {
		// A cluster-wide block may name no gateway: it covers both.
		// A server-wide event (connection limits are per server, not per
		// gateway) names no gateway either.
		return e.Tenant == "" && (e.Ingress != nil && (e.Ingress.Gateway == l.Scope.Gateway || e.Ingress.Gateway == "") || e.Ingress == nil && e.Kind != "probe-failed")
	}
	if e.Tenant != l.Scope.Tenant || e.App != l.Scope.App {
		return false
	}
	// Events without a route (a task's health check, a block) are the
	// app's: every link of the app takes them.
	return l.Scope.Route == "" || e.Ingress == nil || e.Ingress.RouteID == "" || e.Ingress.RouteID == l.Scope.Route
}

// ingressOver: the event passes the link's threshold (error-rate in
// percent of 5xx, latency in ms).
func ingressOver(l *store.WebhookLink, e webEvent) bool {
	if e.Ingress == nil {
		return true
	}
	limit := l.Threshold
	if limit == 0 {
		if e.Kind != webRouteMetric {
			return true
		}
		// A sample always needs a line: the defaults for a link without one.
		limit = ingressDefaultErrPct
		if e.Ingress.Metric == metricP95 {
			limit = ingressDefaultP95MS
		}
	}
	v := e.Ingress.Value
	if e.Ingress.Metric == metric5xx {
		v *= 100
	}
	return v >= limit
}

// ingressEvent handles one event read by the watcher.
func (s *Server) ingressEvent(e webEvent) {
	ev, recovered, ok := ingressWebhookEvent(e)
	if !ok {
		return
	}
	all, err := s.opt.Store.ListWebhookLinks()
	if err != nil {
		return
	}
	st := &s.hooks.ingress
	for _, l := range all {
		if l.Point != "ingress" || !slices.Contains(l.Events, ev) || !ingressLinkCovers(l, e) {
			continue
		}
		k := l.ID + "|" + e.Target + "|" + ev
		recovered := recovered
		if e.Kind == webRouteMetric {
			recovered = !ingressOver(l, e)
		}
		st.mu.Lock()
		if st.pending == nil {
			st.pending, st.fired, st.grouped = map[string]ingressPending{}, map[string]time.Time{}, map[string]time.Time{}
		}
		at := time.Unix(e.Time, 0)
		sent, was := st.fired[k]
		if was && !ingressHasRecovery(ev) && at.Sub(sent) >= ingressRepeat {
			was = false
		}
		send, sendRecover := false, false
		switch {
		case recovered:
			delete(st.pending, k)
			sendRecover = was && (l.Recover || slices.Contains(l.Events, "recovered"))
			delete(st.fired, k)
		case !ingressOver(l, e) || was:
		case l.Minutes == 0 || ev != "error-rate" && ev != "latency":
			send, st.fired[k] = true, at
		default:
			if _, waiting := st.pending[k]; !waiting {
				st.pending[k] = ingressPending{at: s.now(), link: l.ID, event: ev, e: withLinkLimit(l, e)}
			}
		}
		st.mu.Unlock()
		if send || sendRecover {
			s.sendIngress(l, ev, recovered, withLinkLimit(l, e))
		}
	}
}

// ingressDue sends the waiting notices whose minutes have passed (and
// forgets group sends past their window).
func (s *Server) ingressDue(now time.Time) {
	st := &s.hooks.ingress
	st.mu.Lock()
	for k, at := range st.grouped {
		if now.Sub(at) >= ingressGroupWindow {
			delete(st.grouped, k)
		}
	}
	for k, at := range st.fired {
		if ev := k[strings.LastIndex(k, "|")+1:]; !ingressHasRecovery(ev) && now.Sub(at) >= ingressRepeat {
			delete(st.fired, k)
		}
	}
	var due []ingressPending
	for k, p := range st.pending {
		l, err := s.opt.Store.GetWebhookLink(p.link)
		if err != nil {
			delete(st.pending, k)
			continue
		}
		if now.Sub(p.at) >= time.Duration(l.Minutes)*time.Minute {
			delete(st.pending, k)
			st.fired[k] = now
			due = append(due, p)
		}
	}
	st.mu.Unlock()
	for _, p := range due {
		if l, err := s.opt.Store.GetWebhookLink(p.link); err == nil {
			s.sendIngress(l, p.event, false, p.e)
		}
	}
}

// ingressHooksActive: some link waits for ingress events.
func (s *Server) ingressHooksActive() bool {
	all, err := s.opt.Store.ListWebhookLinks()
	if err != nil {
		return false
	}
	return slices.ContainsFunc(all, func(l *store.WebhookLink) bool { return l.Point == "ingress" })
}

var ingressEventWord = map[string]string{"down": "수신 주소 닫힘", "tls-rejects": "TLS 거부", "source-rejects": "허용 밖 출발지 거부 급증",
	"error-rate": "5xx 비율 높음", "latency": "지연 높음", "no-backends": "받을 컨테이너 없음", "probe-failed": "상태 검사 실패",
	"cert": "인증서 없음", "blocked": "긴급 차단", "balance-fallback": "분배 방식 대체", "certificate-expiring": "인증서 만료 임박",
	"limit-90": "연결 한도 90% 넘음"}

func (s *Server) sendIngress(l *store.WebhookLink, ev string, recovered bool, e webEvent) {
	h, err := s.opt.Store.GetWebhook(l.Webhook)
	if err != nil || h.Role != "notify" || !h.Enabled {
		return
	}
	if l.Group && !recovered {
		st, k, now := &s.hooks.ingress, l.ID+"|"+e.Target+"|"+ev, s.now()
		st.mu.Lock()
		last, ok := st.grouped[k]
		if !ok || now.Sub(last) >= ingressGroupWindow {
			st.grouped[k] = now
		}
		st.mu.Unlock()
		if ok && now.Sub(last) < ingressGroupWindow {
			return
		}
	}
	in := map[string]any{"node": e.Node}
	if e.Tenant != "" {
		in["tenant"] = e.Tenant
	}
	if e.App != "" {
		in["app"] = e.App
	}
	if x := e.Ingress; x != nil {
		for k, v := range map[string]string{"gateway": x.Gateway, "route": x.RouteID, "host": x.Host, "prefix": x.Prefix, "listener": x.Listener, "metric": x.Metric} {
			if v != "" {
				in[k] = v
			}
		}
		if x.Metric != "" {
			in["value"], in["threshold"] = x.Value, x.Threshold
		}
	}
	state, event, word := "firing", "ingress."+ev, ingressEventWord[ev]
	if recovered {
		state, event, word = "recovered", event+".recovered", word+" 회복"
	}
	p := map[string]any{"ingress": in, "state": state, "observedAt": rfc3339(time.Unix(e.Time, 0)), "link": l.ID, "dedupKey": e.Target + "/" + ev}
	if c := ingressCondition(l); c != "" {
		p["condition"] = c
	}
	if e.Kind == webCertExpiring || e.Kind == webCertRenewed {
		p["detail"] = e.Detail // the certificate and when it ends
	}
	where := e.Target
	if e.Ingress != nil && e.Ingress.Host != "" {
		where += " " + e.Ingress.Host + e.Ingress.Prefix
	}
	s.sendWebhookLater(h, webhookSend{Point: "ingress", Link: l.ID, Event: event, Payload: p, Summary: fmt.Sprintf("[외부 접속] %s: %s", where, word)})
}

// What the web watches itself for gateway links (no mydcd event): the
// certificates the gateway's listeners serve, and the server's connection
// use against its limits. Read at most every ingressPollEvery, only while a
// gateway link wants them; only changes are sent (and the recovery).
const (
	ingressPollEvery   = 5 * time.Minute
	ingressCertWarn    = 14 * 24 * time.Hour
	ingressLimitShare  = 0.9
	webCertExpiring    = "web-certificate-expiring"
	webCertRenewed     = "web-certificate-renewed"
	webLimitOver       = "web-limit-over"
	webLimitUnder      = "web-limit-under"
	ingressLimitMetric = "connections-share"
)

// ingressPollWanted: some gateway link wants the certificate or limit
// checks (gateways), or some app link wants error-rate/latency (metrics,
// with their links).
func (s *Server) ingressPollWanted() (gateways bool, metrics []*store.WebhookLink) {
	all, err := s.opt.Store.ListWebhookLinks()
	if err != nil {
		return false, nil
	}
	for _, l := range all {
		if l.Point != "ingress" {
			continue
		}
		if l.Scope.Gateway != "" && (slices.Contains(l.Events, "certificate-expiring") || slices.Contains(l.Events, "limit-90")) {
			gateways = true
		}
		if l.Scope.Gateway == "" && l.Scope.Tenant != "" && (slices.Contains(l.Events, "error-rate") || slices.Contains(l.Events, "latency")) {
			metrics = append(metrics, l)
		}
	}
	return gateways, metrics
}

// ingressPoll reads the ingress state as ws and turns the changes into
// events for ingressEvent.
func (s *Server) ingressPoll(ctx context.Context, ws *webSession) {
	st := &s.hooks.ingress
	now := s.now()
	gateways, metricLinks := s.ingressPollWanted()
	every := ingressPollEvery
	if len(metricLinks) > 0 {
		every = ingressMetricEvery
	}
	st.mu.Lock()
	due := now.Sub(st.polledAt) >= every
	if due {
		st.polledAt = now
	}
	st.mu.Unlock()
	if !due || !gateways && len(metricLinks) == 0 {
		return
	}
	var iv *ingressView
	var samples []webEvent
	err := ws.do(ctx, func(ctx context.Context, c mydc.Conn) error {
		var err error
		if iv, err = ingressRead(ctx, c, control.IngressQuery{}); err != nil {
			return err
		}
		samples = s.routeSamples(ctx, c, iv, metricLinks, now)
		return nil
	})
	if err != nil {
		s.log.Warn("ingress poll", "err", err)
		return
	}
	// The earliest end of a certificate each gateway of a server has
	// loaded (Runtime.Certificates).
	type gw struct{ node, kind string }
	ends := map[gw]int64{}
	names := map[gw]string{}
	for _, o := range certObservations(iv) {
		if o.o.NotAfter == 0 {
			continue
		}
		var kinds []string
		if o.lis != nil {
			kinds = []string{o.lis.Gateway}
		} else {
			for _, rt := range o.m.Spec.Routes {
				if rt.Host == o.o.Host {
					kinds = append(kinds, routeGateways(rt.Gateway)...)
				}
			}
		}
		for _, kind := range kinds {
			if kind != mydc.GatewayExternal && kind != mydc.GatewayLocal {
				continue
			}
			k := gw{o.m.Node, kind}
			if e, seen := ends[k]; !seen || o.o.NotAfter < e {
				ends[k], names[k] = o.o.NotAfter, o.o.Host
			}
		}
	}
	var events []webEvent
	flip := func(key string, on bool, e webEvent, onKind, offKind string) {
		st.mu.Lock()
		if st.polled == nil {
			st.polled = map[string]bool{}
		}
		was := st.polled[key]
		st.polled[key] = on
		st.mu.Unlock()
		switch {
		case on && !was:
			e.Kind = onKind
		case !on && was:
			e.Kind = offKind
		default:
			return
		}
		events = append(events, e)
	}
	for _, n := range iv.Nodes {
		enabled := n.Enabled != nil && *n.Enabled && len(n.Gateways) > 0
		// The connection limits are the server's, not a gateway's: one
		// event for the server, which every gateway link takes. -1 is
		// "not observed" and never counts.
		if enabled && n.MaxIngressConnections > 0 && n.Connections >= 0 {
			share := float64(n.Connections) / float64(n.MaxIngressConnections)
			flip("limit|"+n.Node, share >= ingressLimitShare, webEvent{Time: now.Unix(), Scope: "node", Node: n.Node, Target: n.Node,
				Ingress: &webIngressEvent{Metric: ingressLimitMetric, Value: share, Threshold: ingressLimitShare}}, webLimitOver, webLimitUnder)
		}
		if !enabled {
			continue
		}
		for _, g := range n.Gateways {
			if g.Gateway != mydc.GatewayExternal && g.Gateway != mydc.GatewayLocal {
				continue
			}
			target := n.Node + "/" + g.Gateway
			k := gw{n.Node, g.Gateway}
			if end, ok := ends[k]; ok {
				flip("cert|"+target, time.Unix(end, 0).Sub(now) < ingressCertWarn, webEvent{Time: now.Unix(), Scope: "node", Node: n.Node, Target: target,
					Detail: names[k] + " " + rfc3339(time.Unix(end, 0)), Ingress: &webIngressEvent{Gateway: g.Gateway}}, webCertExpiring, webCertRenewed)
			}
		}
	}
	if gateways {
		for _, e := range events {
			s.ingressEvent(e)
		}
	}
	for _, e := range samples {
		s.ingressEvent(e)
	}
}

// What the web computes for error-rate and latency links: mydcd keeps the
// last 60 s of request metrics per route (Runtime.Metrics) and makes no
// event of them (docs/reference/ingress-management.md "이벤트"). Each poll
// gives one sample per watched route and metric, summed over the app's
// servers (5xx share of all responses; the worst p95). The link's threshold
// (or the default) decides over or recovered, and its minutes the hold.
const (
	webRouteMetric       = "web-ingress-route-metric"
	ingressMetricEvery   = time.Minute
	metric5xx            = "5xx-ratio"
	metricP95            = "latency-p95-ms"
	ingressDefaultErrPct = 5    // % of responses that are 5xx
	ingressDefaultP95MS  = 1000 // ms
)

// withLinkLimit puts the line a sample was judged by into its payload (5xx
// as a share like the value).
func withLinkLimit(l *store.WebhookLink, e webEvent) webEvent {
	if e.Kind != webRouteMetric || e.Ingress == nil {
		return e
	}
	x := *e.Ingress
	limit := l.Threshold
	if limit == 0 {
		limit = ingressDefaultErrPct
		if x.Metric == metricP95 {
			limit = ingressDefaultP95MS
		}
	}
	if x.Metric == metric5xx {
		limit /= 100
	}
	x.Threshold = limit
	e.Ingress = &x
	return e
}

func (s *Server) routeSamples(ctx context.Context, c mydc.Conn, iv *ingressView, links []*store.WebhookLink, now time.Time) []webEvent {
	watched := func(m *control.IngressMapping) bool {
		return slices.ContainsFunc(links, func(l *store.WebhookLink) bool {
			return l.Scope.Tenant == m.Tenant && (l.Scope.App == "" || l.Scope.App == m.App)
		})
	}
	type acc struct {
		rt    ingress.Route
		app   *control.IngressMapping
		resp  [4]uint64
		p95   uint64
		nodes int
	}
	byRoute := map[string]*acc{}
	var order []string
	for i := range iv.Mappings {
		m := &iv.Mappings[i]
		if !watched(m) {
			continue
		}
		mt, err := ingressMetrics(ctx, c, m.Key, m.Tenant, "metrics")
		if err != nil {
			s.log.Warn("ingress poll: metrics", "key", m.Key, "err", err)
			continue
		}
		for _, rt := range m.Spec.Routes {
			k := m.Tenant + "/" + m.App + "/" + rt.ID
			a := byRoute[k]
			if a == nil {
				a = &acc{rt: rt, app: m}
				byRoute[k] = a
				order = append(order, k)
			}
			a.nodes++
			for _, x := range mt.Routes {
				if x.ID == rt.ID {
					for j := range a.resp {
						a.resp[j] += x.Responses[j]
					}
					a.p95 = max(a.p95, x.P95MS)
				}
			}
		}
	}
	var out []webEvent
	for _, k := range order {
		a := byRoute[k]
		total := a.resp[0] + a.resp[1] + a.resp[2] + a.resp[3]
		share := 0.0
		if total > 0 {
			share = float64(a.resp[3]) / float64(total)
		}
		gw := ""
		if g := routeGateways(a.rt.Gateway); len(g) == 1 {
			gw = g[0]
		}
		base := webEvent{Time: now.Unix(), Kind: webRouteMetric, Scope: "app", Tenant: a.app.Tenant, App: a.app.App, Target: k}
		if a.nodes == 1 {
			base.Node = a.app.Node
		}
		for _, mv := range []struct {
			name string
			v    float64
		}{{metric5xx, share}, {metricP95, float64(a.p95)}} {
			e := base
			e.Ingress = &webIngressEvent{Gateway: gw, RouteID: a.rt.ID, Host: a.rt.Host, Prefix: a.rt.Prefix, Metric: mv.name, Value: mv.v}
			out = append(out, e)
		}
	}
	return out
}

// routeGateways: the gateways a route's gateway field names (local by
// default, both = external and local).
func routeGateways(g string) []string {
	switch g {
	case "", mydc.GatewayLocal:
		return []string{mydc.GatewayLocal}
	case mydc.GatewayBoth:
		return []string{mydc.GatewayExternal, mydc.GatewayLocal}
	}
	return []string{g}
}

// certObs is one certificate a server's ingress has loaded, with a listener
// of its mapping serving TLS, if seen.
type certObs struct {
	m   *control.IngressMapping
	o   ingress.CertificateObservation
	lis *ingress.ListenerSnapshot
}

func certObservations(v *ingressView) []certObs {
	if v == nil {
		return nil
	}
	var out []certObs
	for i := range v.Mappings {
		m := &v.Mappings[i]
		if m.Runtime == nil {
			continue
		}
		for _, o := range m.Runtime.Certificates {
			co := certObs{m: m, o: o}
			for j := range m.Runtime.Listeners {
				if l := &m.Runtime.Listeners[j]; co.lis == nil && l.TLS {
					co.lis = l
				}
			}
			out = append(out, co)
		}
	}
	return out
}
