// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/ingress"
	"github.com/jay94ks/mydcd/internal/web/mydc"
)

// External access screens (UI-5A~5C, REQ-22,
// docs/reference/ingress-management.md): mydcd's `ingresses` mappings,
// recent request metrics (Part metrics/errors) and Raft blocks, shaped for
// the browser. mydcd decides who sees and changes what; the web only reads
// as the person and sends their blocks as their operations.

func round2(f float64) float64 { return math.Round(f*100) / 100 }

func share5xx(r [4]uint64) float64 {
	total := r[0] + r[1] + r[2] + r[3]
	if total == 0 {
		return 0
	}
	return math.Round(float64(r[3])/float64(total)*10000) / 10000
}

func listenerPort(addr string) int {
	if ap, err := netip.ParseAddrPort(addr); err == nil {
		return int(ap.Port())
	}
	return 0
}

func msTime(ms uint64) string {
	if ms == 0 {
		return ""
	}
	return rfc3339(time.UnixMilli(int64(ms)))
}

// ingressData is one screen's read: the mappings with their recent
// metrics, and the blocks with the book revision they are judged against.
type ingressData struct {
	iv            *ingressView
	metrics       map[string]*ingress.Metrics // by mapping key; missing = not read
	blocks        []control.IngressBlockView
	blockRevision uint64
}

func readIngress(ctx context.Context, c mydc.Conn, q control.IngressQuery, withMetrics bool) (*ingressData, error) {
	iv, err := ingressRead(ctx, c, q)
	if err != nil {
		return nil, err
	}
	d := &ingressData{iv: iv, metrics: map[string]*ingress.Metrics{}}
	if withMetrics {
		for _, m := range iv.Mappings {
			if mt, err := ingressMetrics(ctx, c, m.Key, m.Tenant, "metrics"); err == nil {
				d.metrics[m.Key] = mt
			}
		}
	}
	bp, err := ingressPaged(ctx, c, control.IngressQuery{Part: "blocks", Tenant: q.Tenant, Node: q.Node})
	if err != nil {
		return nil, err
	}
	d.blocks, d.blockRevision = bp.Blocks, bp.BlockRevision
	return d, nil
}

func metricOf(ms []ingress.Metric, id string) *ingress.Metric {
	for i := range ms {
		if ms[i].ID == id {
			return &ms[i]
		}
	}
	return nil
}

// blockedBy: the active block that stops this route (or backend) of m, if
// any. Wider scopes (instance, host, tenant, node) count too.
func blockedBy(m *control.IngressMapping, blocks []control.IngressBlockView, rt ingress.Route, service, backend string) string {
	for _, v := range blocks {
		b := v.Block
		if v.Removed || !v.Active {
			continue
		}
		hit := false
		switch b.Scope {
		case "route":
			hit = backend == "" && b.Key == m.Key && (b.Route == rt.ID || b.Host == rt.Host && b.Prefix == rt.Prefix)
		case "host":
			hit = backend == "" && b.Host == rt.Host && (b.Tenant == "" || b.Tenant == m.Tenant)
		case "instance":
			hit = b.Key == m.Key
		case "backend":
			hit = backend != "" && b.Key == m.Key && b.Service == service && b.Backend == backend
		case "tenant":
			hit = b.Tenant == m.Tenant
		case "node":
			hit = b.Node == m.Node
		}
		if hit && (b.Gateway == "" || b.Gateway == "both" || rt.Gateway == "both" || b.Gateway == rt.Gateway || rt.Gateway == "" && b.Gateway == "local") {
			return b.ID
		}
	}
	return ""
}

func serviceOf(spec ingress.Spec, id string) *ingress.Service {
	for i := range spec.Services {
		if spec.Services[i].ID == id {
			return &spec.Services[i]
		}
	}
	return nil
}

// balanceShape is a route's balance (app.yaml routes[].balance, else its
// service's) as the screens show it. It is read-only: mydcd takes it only
// from app.yaml.
func balanceShape(b *ingress.Balance) map[string]any {
	if b == nil {
		return map[string]any{"method": "round-robin", "locality": false, "slowStartSeconds": 0, "retry": 0, "rules": []map[string]any{}}
	}
	rules := []map[string]any{}
	for _, c := range b.Match {
		add := func(x map[string]any) {
			x["group"] = c.Group
			if c.ID != "" {
				x["id"] = c.ID
			}
			rules = append(rules, x)
		}
		for _, kv := range []struct {
			kind string
			m    map[string]ingress.ValueMatch
		}{{"header", c.Headers}, {"cookie", c.Cookies}, {"query", c.Query}} {
			for _, name := range sortedNames(kv.m) {
				vm := kv.m[name]
				x := map[string]any{"kind": kv.kind, "name": name}
				switch {
				case vm.Equal != nil:
					x["op"], x["value"] = "equals", *vm.Equal
				case vm.Prefix != nil:
					x["op"], x["value"] = "prefix", *vm.Prefix
				default:
					x["op"] = "present"
				}
				add(x)
			}
		}
		if len(c.Methods) > 0 {
			add(map[string]any{"kind": "method", "value": strings.Join(c.Methods, ",")})
		}
		for _, p := range c.Sources {
			add(map[string]any{"kind": "source", "value": p.String()})
		}
		if c.Percent != nil {
			x := map[string]any{"kind": "percent", "percent": *c.Percent}
			if c.Key != "" {
				x["key"] = c.Key
			}
			add(x)
		}
	}
	slow := b.SlowStartSeconds
	if slow == 0 && b.SlowStartMS > 0 {
		slow = (b.SlowStartMS + 999) / 1000
	}
	method := b.Method
	if method == "" {
		method = "round-robin"
	}
	v := map[string]any{"method": method, "locality": b.Locality == "same-node", "slowStartSeconds": slow, "retry": b.Retry, "rules": rules}
	if b.Key != "" {
		v["hashKey"] = b.Key
	}
	if len(b.Weights) > 0 {
		v["weights"] = b.Weights
	}
	if len(b.Groups) > 0 {
		gs := map[string]any{}
		for name, g := range b.Groups {
			x := map[string]any{}
			if len(g.Labels) > 0 {
				x["labels"] = g.Labels
			}
			if g.Version != "" {
				x["version"] = g.Version
			}
			if len(g.Backends) > 0 {
				x["backends"] = g.Backends
			}
			gs[name] = x
		}
		v["groups"] = gs
	}
	if b.Fallback != "" {
		v["fallback"] = b.Fallback
	}
	return v
}

func sortedNames[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// instanceShape is one mapping (one app on one server).
func instanceShape(m *control.IngressMapping, mt *ingress.Metrics, blocks []control.IngressBlockView) map[string]any {
	rs := m.Runtime
	routes := []map[string]any{}
	for _, rt := range m.Spec.Routes {
		svc := serviceOf(m.Spec, rt.Service)
		bal := rt.Balance
		if bal == nil && svc != nil {
			bal = svc.Balance
		}
		gw := rt.Gateway
		if gw == "" {
			gw = mydc.GatewayLocal
		}
		v := map[string]any{"id": rt.ID, "gateway": gw, "host": rt.Host, "prefix": rt.Prefix, "service": rt.Service, "balance": balanceShape(bal), "rps": 0.0,
			"balanceRevision": rt.BalanceRevision}
		if rt.BalanceRevision > 0 {
			// the management overlay replaced the app's own declaration
			ob := rt.OriginalBalance
			if ob == nil && svc != nil {
				ob = svc.Balance
			}
			v["originalBalance"] = balanceShape(ob)
		}
		if rs != nil {
			for _, l := range rs.Listeners {
				if l.Gateway == gw || gw == mydc.GatewayBoth || l.Gateway == "" {
					v["port"] = listenerPort(l.Address)
					break
				}
			}
			if certs := routeCertificates(rs.Certificates, rt.Host); len(certs) > 0 {
				v["certificates"] = certs
			}
		}
		if mt != nil {
			if x := metricOf(mt.Routes, rt.ID); x != nil {
				v["rps"], v["err5xx"], v["p95Ms"] = round2(x.Rate), share5xx(x.Responses), float64(x.P95MS)
			}
		}
		if id := blockedBy(m, blocks, rt, "", ""); id != "" {
			v["blocked"] = id
		}
		backends := []map[string]any{}
		if svc != nil {
			for _, bs := range svc.Backends {
				bv := map[string]any{"id": bs.ID, "task": bs.Task, "node": bs.Node, "address": bs.Address.String(), "port": bs.Port, "weight": bs.Weight, "generation": bs.Generation,
					"health": map[string]any{"ok": false}, "rps": 0.0}
				if rs != nil {
					for _, b := range rs.Backends {
						if b.ID == bs.ID {
							bv["task"], bv["node"], bv["address"], bv["port"], bv["weight"], bv["generation"] = b.Task, b.Node, b.Address, b.Port, b.Weight, b.Generation
							h := map[string]any{"ok": b.Healthy}
							if b.ObservedAt > 0 {
								h["at"] = msTime(b.ObservedAt)
							}
							bv["health"] = h
							if b.Draining {
								bv["draining"] = true
							}
						}
					}
				}
				if mt != nil {
					if x := metricOf(mt.Backends, bs.ID); x != nil {
						bv["rps"], bv["p95Ms"] = round2(x.Rate), float64(x.P95MS)
					}
				}
				if id := blockedBy(m, blocks, rt, rt.Service, bs.ID); id != "" {
					bv["blocked"] = id
				}
				backends = append(backends, bv)
			}
		}
		v["backends"] = backends
		routes = append(routes, v)
	}
	iv := map[string]any{"key": m.Key, "tenant": m.Tenant, "app": m.App, "node": m.Node, "generation": m.Generation, "ready": m.Ready, "routes": routes}
	if m.Draining {
		iv["draining"] = true
	}
	if m.DrainRevision > 0 {
		iv["drainRevision"] = m.DrainRevision
		if m.DrainStartedAt > 0 {
			iv["drainStartedAt"], iv["drainDeadline"] = unixTime(int64(m.DrainStartedAt)), unixTime(int64(m.DrainDeadline))
		}
		if m.LastMapping {
			iv["lastMapping"] = true
		}
	}
	if m.Error != "" {
		iv["error"] = m.Error
	}
	if m.ObservedAt > 0 {
		iv["observedAt"] = msTime(m.ObservedAt)
	}
	if rs == nil {
		iv["observed"] = false
	}
	return iv
}

// gatewayShape: a server's shared gateway as mydcd observes it. The
// configuration itself is the server's local modules.ingress setting.
func gatewayShape(g control.IngressGatewaySummary, system bool) map[string]any {
	listeners := []map[string]any{}
	seen := map[string]bool{}
	var ports []int
	rules := 0
	state := "off"
	addr := ""
	for _, l := range g.Listeners {
		rules += len(l.Hosts)
		if seen[l.ID] {
			continue
		}
		seen[l.ID] = true
		x := map[string]any{"id": l.ID, "address": l.Address, "http3": l.HTTP3, "ready": l.Ready}
		if l.Error != "" {
			x["error"] = l.Error
		}
		listeners = append(listeners, x)
		if p := listenerPort(l.Address); p != 0 && !slices.Contains(ports, p) {
			ports = append(ports, p)
		}
		if addr == "" {
			if ap, err := netip.ParseAddrPort(l.Address); err == nil {
				addr = ap.Addr().String()
			}
		}
		switch {
		case l.Error != "" || !l.Ready:
			state = "error"
		case state == "off":
			state = "listening"
		}
	}
	if ports == nil {
		ports = []int{}
	}
	v := map[string]any{"ports": ports, "rules": rules, "state": state, "listeners": listeners}
	if addr != "" {
		v["address"] = addr
	}
	if system {
		v["unmatched"], v["sourceRejected"] = g.Unmatched, g.SourceRejected
	}
	return v
}

// tenantNodes: the per-tenant×node use and limits (a tenant query's node
// summaries are that tenant's).
func tenantNodes(ctx context.Context, c mydc.Conn, tenant, node string) map[string]control.IngressNodeSummary {
	out := map[string]control.IngressNodeSummary{}
	q := control.IngressQuery{Tenant: tenant, Node: node}
	for range ingressMaxPages {
		p, err := c.QueryIngresses(ctx, q)
		if err != nil {
			return out
		}
		for _, n := range p.Nodes {
			if _, ok := out[n.Node]; !ok {
				out[n.Node] = n
			}
		}
		if p.Next == "" {
			break
		}
		q.After = p.Next
	}
	return out
}

func usePair(used, limit int) []int { return []int{used, limit} }

func shapeIngress(ctx context.Context, c mydc.Conn, d *ingressData, q control.IngressQuery, system bool) map[string]any {
	instances := []map[string]any{}
	nodeRPS := map[string]float64{}
	tenantHosts := map[string][]string{}
	tenantExternal := map[string]bool{}
	type tn struct{ tenant, node string }
	inst, rules := map[tn]int{}, map[tn]int{}
	var totalRPS, worstP95 float64
	var resp [4]uint64
	for i := range d.iv.Mappings {
		m := &d.iv.Mappings[i]
		mt := d.metrics[m.Key]
		if mt != nil {
			nodeRPS[m.Node] += mt.Instance.Rate
			totalRPS += mt.Instance.Rate
			worstP95 = max(worstP95, float64(mt.Instance.P95MS))
			for j := range resp {
				resp[j] += mt.Instance.Responses[j]
			}
		}
		k := tn{m.Tenant, m.Node}
		inst[k]++
		rules[k] += len(m.Spec.Routes)
		for _, rt := range m.Spec.Routes {
			if !slices.Contains(tenantHosts[m.Tenant], rt.Host) {
				tenantHosts[m.Tenant] = append(tenantHosts[m.Tenant], rt.Host)
			}
			if rt.Gateway == mydc.GatewayExternal || rt.Gateway == mydc.GatewayBoth {
				tenantExternal[m.Tenant] = true
			}
		}
		instances = append(instances, instanceShape(m, mt, d.blocks))
	}
	nodes := []map[string]any{}
	for _, n := range d.iv.Nodes {
		module := "unknown"
		if n.Enabled != nil {
			module = map[bool]string{true: "on", false: "off"}[*n.Enabled]
		}
		nv := map[string]any{"node": n.Node, "module": module, "connections": n.Connections, "connectionLimit": n.MaxIngressConnections, "rps": round2(nodeRPS[n.Node])}
		for _, g := range n.Gateways {
			if g.Gateway == mydc.GatewayExternal || g.Gateway == mydc.GatewayLocal {
				nv[g.Gateway] = gatewayShape(g, system)
			}
		}
		if n.Configuration != nil {
			nv["configuration"] = nodeGatewaysShape(*n.Configuration)
		}
		nodes = append(nodes, nv)
	}
	names := sortedNames(tenantHosts)
	tl := []map[string]any{}
	for _, t := range names {
		sums := map[string]control.IngressNodeSummary{}
		if q.Tenant == t {
			for _, n := range d.iv.Nodes {
				sums[n.Node] = n
			}
		} else {
			sums = tenantNodes(ctx, c, t, q.Node)
		}
		usage := []map[string]any{}
		for _, node := range sortedNames(sums) {
			n := sums[node]
			usage = append(usage, map[string]any{"node": node, "instances": inst[tn{t, node}], "rules": rules[tn{t, node}],
				"requests": usePair(n.Requests, n.MaxIngressRequests), "connections": usePair(n.Connections, n.MaxIngressConnections),
				"bufferMiB": usePair(n.BufferBytes>>20, n.IngressBufferBytes>>20)})
		}
		hosts := tenantHosts[t]
		sort.Strings(hosts)
		tl = append(tl, map[string]any{"tenant": t, "hosts": hosts, "usage": usage, "external": tenantExternal[t]})
	}
	return map[string]any{"nodes": nodes, "instances": instances, "tenants": tl,
		"summary": map[string]any{"rps": round2(totalRPS), "err5xx": share5xx(resp), "p95Ms": round2(worstP95)}}
}

func (s *Server) isSystemAdmin(ctx context.Context, c mydc.Conn) bool {
	who, err := c.Whoami(ctx)
	return err == nil && who.User.SystemAdmin
}

// GET /ingress?node=&tenant= → {nodes, instances, tenants, summary, observedAt}
func (s *Server) handleIngress(w http.ResponseWriter, r *http.Request, ws *webSession) {
	node, tenant := r.URL.Query().Get("node"), r.URL.Query().Get("tenant")
	if node != "" && !safeParamRE.MatchString(node) || tenant != "" && !safeParamRE.MatchString(tenant) {
		writeError(w, http.StatusBadRequest, "bad-request", "node and tenant: names")
		return
	}
	ctx, cancel := s.callCtx(r)
	defer cancel()
	var out map[string]any
	err := ws.do(ctx, func(ctx context.Context, c mydc.Conn) error {
		q := control.IngressQuery{Node: node, Tenant: tenant}
		d, err := readIngress(ctx, c, q, true)
		if err != nil {
			return err
		}
		out = shapeIngress(ctx, c, d, q, s.isSystemAdmin(ctx, c))
		return nil
	})
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	out["observedAt"] = rfc3339(s.now())
	writeJSON(w, http.StatusOK, out)
}

// GET /t/{t}/apps/{app}/ingress?node= → {instance, metrics, errors, balanceHistory}
func (s *Server) handleAppIngress(w http.ResponseWriter, r *http.Request, ws *webSession) {
	tenant, app, node := r.PathValue("t"), r.PathValue("app"), r.URL.Query().Get("node")
	if node != "" && !safeParamRE.MatchString(node) {
		writeError(w, http.StatusBadRequest, "bad-request", "node: a name")
		return
	}
	ctx, cancel := s.callCtx(r)
	defer cancel()
	var out map[string]any
	err := ws.do(ctx, func(ctx context.Context, c mydc.Conn) error {
		d, err := readIngress(ctx, c, control.IngressQuery{Tenant: tenant, App: app, Node: node}, true)
		if err != nil {
			return err
		}
		if len(d.iv.Mappings) == 0 {
			return &httpErr{http.StatusNotFound, "not-found", "this app has no external access instance"}
		}
		m := &d.iv.Mappings[0]
		mt := d.metrics[m.Key]
		metrics := map[string]any{}
		if mt != nil {
			x := mt.Instance
			metrics["rps"] = round2(x.Rate)
			metrics["codes"] = fmt.Sprintf("2xx %d · 3xx %d · 4xx %d · 5xx %d · 차단 %d", x.Responses[0], x.Responses[1], x.Responses[2], x.Responses[3], x.Blocked)
			metrics["latency"] = fmt.Sprintf("p50 %dms · p95 %dms · p99 %dms", x.P50MS, x.P95MS, x.P99MS)
			var pf []string
			for _, k := range sortedNames(x.Failures) {
				pf = append(pf, fmt.Sprintf("%s %d", k, x.Failures[k]))
			}
			metrics["proxyFailures"] = strings.Join(pf, " · ")
			if len(pf) == 0 {
				metrics["proxyFailures"] = "없음"
			}
			metrics["windowSeconds"] = mt.WindowSeconds
		}
		if m.Runtime != nil {
			metrics["connections"] = usePair(m.Runtime.Connections, m.Spec.MaxConnections)
			metrics["concurrent"] = usePair(m.Runtime.Requests, m.Spec.MaxRequests)
		}
		errs := []map[string]any{}
		if em, err := ingressMetrics(ctx, c, m.Key, tenant, "errors"); err == nil {
			for _, e := range em.Errors {
				reason := e.Failure
				if e.Block != "" {
					reason = "blocked:" + e.Block
				}
				errs = append(errs, map[string]any{"at": msTime(e.At), "status": e.Status, "method": e.Method, "path": e.Path,
					"task": e.Backend, "reason": reason, "ms": float64(e.DurationMS), "source": e.Source})
			}
		}
		// The history is extra: without it the screen still shows the rest.
		bh, err := balanceHistory(ctx, c, tenant, app)
		if err != nil {
			s.log.Warn("ingress balance history", "err", err, "tenant", tenant, "app", app)
			bh = []map[string]any{}
		}
		out = map[string]any{"instance": instanceShape(m, mt, d.blocks), "metrics": metrics, "errors": errs, "balanceHistory": bh}
		return nil
	})
	if err != nil {
		s.writeOpOutcome(w, ws, nil, 0, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// blockNodes: per server, which blocks mydcd reports applied there and the
// block book revision that server's owners have installed (the lowest of
// its mappings; unobserved = no entry).
type blockNodes struct {
	apps      map[string]map[string]ingress.BlockApplication // block ID → node → application
	installed map[string]uint64                              // node → Runtime.BlockRevision
	nodes     []string
}

func readBlockNodes(ctx context.Context, c mydc.Conn, tenant string) blockNodes {
	out := blockNodes{apps: map[string]map[string]ingress.BlockApplication{}, installed: map[string]uint64{}}
	iv, err := ingressRead(ctx, c, control.IngressQuery{Tenant: tenant})
	if err != nil {
		return out
	}
	unseen := map[string]bool{}
	for _, m := range iv.Mappings {
		if !slices.Contains(out.nodes, m.Node) {
			out.nodes = append(out.nodes, m.Node)
		}
		if m.Runtime == nil {
			unseen[m.Node] = true
			continue
		}
		if r, ok := out.installed[m.Node]; !ok || m.Runtime.BlockRevision < r {
			out.installed[m.Node] = m.Runtime.BlockRevision
		}
	}
	for n := range unseen {
		delete(out.installed, n)
	}
	for _, n := range out.nodes {
		p, err := ingressPaged(ctx, c, control.IngressQuery{Part: "blocks", Tenant: tenant, Node: n})
		if err != nil {
			continue
		}
		for _, v := range p.Blocks {
			for _, a := range v.Applications {
				if out.apps[v.Block.ID] == nil {
					out.apps[v.Block.ID] = map[string]ingress.BlockApplication{}
				}
				out.apps[v.Block.ID][a.Node] = a
			}
		}
	}
	return out
}

// blockShape shapes a mydcd block for the screen. state: active, or
// lifting while a lifted block is not yet installed on every server
// (Runtime.BlockRevision below the page's BlockRevision, or unobserved).
func blockShape(v control.IngressBlockView, bn blockNodes, bookRevision uint64, names map[string]string) (map[string]any, bool) {
	b := v.Block
	lifting := false
	if v.Removed {
		for _, n := range bn.nodes {
			if r, ok := bn.installed[n]; !ok || r < bookRevision {
				lifting = true
			}
		}
		if !lifting {
			return nil, false
		}
	} else if !v.Active {
		return nil, false
	}
	kind := map[string]string{"backend": "task", "instance": "app"}[b.Scope]
	if kind == "" {
		kind = b.Scope
	}
	scope := map[string]any{"kind": kind}
	for k, val := range map[string]string{"tenant": b.Tenant, "app": b.App, "node": b.Node, "key": b.Key} {
		if val != "" {
			scope[k] = val
		}
	}
	switch b.Scope {
	case "route":
		scope["route"], scope["host"], scope["prefix"] = b.Route, b.Host, b.Prefix
	case "host":
		scope["host"] = b.Host
	case "backend":
		scope["task"], scope["service"] = b.Backend, b.Service
	case "source":
		scope["sources"] = []string{b.Source}
		if len(b.Apps) == 1 {
			scope["app"] = b.Apps[0]
		} else if len(b.Apps) > 1 {
			scope["apps"] = b.Apps
		}
	}
	if b.Gateway != "" {
		g := b.Gateway
		if g == mydc.GatewayBoth {
			g = "all"
		}
		scope["gateway"] = g
	}
	resp := any(b.Response)
	switch b.Response {
	case "503":
		resp = 503
	case "403":
		resp = 403
	case "reset":
		resp = "drop"
	}
	nodes := []map[string]any{}
	var blocked uint64
	for _, n := range bn.nodes {
		a, applied := bn.apps[b.ID][n]
		if !applied && !v.Removed {
			continue // not a server this block maps to (or not reported)
		}
		x := map[string]any{"node": n, "state": "pending"}
		switch {
		case v.Removed:
			if r, ok := bn.installed[n]; !ok {
				x["state"] = "unobserved"
			} else if r >= bookRevision {
				x["state"] = "lifted"
			}
		case a.Applied:
			x["state"] = "applied"
			if a.AppliedAt > b.CreatedAt {
				x["ms"] = (a.AppliedAt - b.CreatedAt) * 1000
			}
		}
		if a.Error != "" {
			x["error"] = a.Error
		}
		blocked += a.BlockedRequests
		nodes = append(nodes, x)
	}
	by := b.Actor
	if n := names[b.Actor]; n != "" {
		by = n
	}
	out := map[string]any{"id": b.ID, "scope": scope, "response": resp, "by": by, "at": rfc3339(time.Unix(int64(b.CreatedAt), 0)), "reason": b.Reason,
		"nodes": nodes, "blockedRequests": blocked, "revision": v.Revision, "killConnections": b.CutExisting, "state": "active"}
	if lifting {
		out["state"] = "lifting"
	}
	if b.ExpiresAt > 0 {
		out["until"] = rfc3339(time.Unix(int64(b.ExpiresAt), 0))
	}
	if v.TargetMissing {
		out["targetMissing"] = true
	}
	return out, true
}

// GET /ingress/blocks?tenant= → {items}
func (s *Server) handleIngressBlocks(w http.ResponseWriter, r *http.Request, ws *webSession) {
	tenant := r.URL.Query().Get("tenant")
	if tenant != "" && !safeParamRE.MatchString(tenant) {
		writeError(w, http.StatusBadRequest, "bad-request", "tenant: a name")
		return
	}
	ctx, cancel := s.callCtx(r)
	defer cancel()
	items := []map[string]any{}
	err := ws.do(ctx, func(ctx context.Context, c mydc.Conn) error {
		p, err := ingressPaged(ctx, c, control.IngressQuery{Part: "blocks", Tenant: tenant})
		if err != nil {
			return err
		}
		bn := readBlockNodes(ctx, c, tenant)
		names := usernames(ctx, c)
		for _, v := range p.Blocks {
			if x, ok := blockShape(v, bn, p.BlockRevision, names); ok {
				items = append(items, x)
			}
		}
		return nil
	})
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

type ingressBlockReq struct {
	OpID  string `json:"opId"`
	Scope struct {
		Kind    string   `json:"kind"`
		Tenant  string   `json:"tenant"`
		App     string   `json:"app"`
		Node    string   `json:"node"`
		Host    string   `json:"host"`
		Prefix  string   `json:"prefix"`
		Route   string   `json:"route"`
		Task    string   `json:"task"`
		Sources []string `json:"sources"`
		Gateway string   `json:"gateway"`
	} `json:"scope"`
	Response any    `json:"response"`
	Minutes  int    `json:"minutes"`
	Until    string `json:"until"`
	// UntilMidnight is refused: midnight is the person's, so the browser
	// sends it as until.
	UntilMidnight   bool   `json:"untilMidnight"`
	Reason          string `json:"reason"`
	KillConnections bool   `json:"killConnections"`
}

// blockID: mydcd takes the block ID from the caller and never reuses one;
// one per web op.
func blockID(opID string) string { return "web-" + strings.ReplaceAll(opID, "-", "") }

// POST /ingress/blocks {opId, scope, response, minutes?|until?, reason, killConnections} → {op}
// The block's ID is web-<opId without dashes>.
func (s *Server) handleCreateIngressBlock(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req ingressBlockReq
	if !readJSON(w, r, &req) {
		return
	}
	sc := req.Scope
	b := ingress.Block{Tenant: sc.Tenant, Reason: strings.TrimSpace(req.Reason), CutExisting: req.KillConnections}
	switch fmt.Sprint(req.Response) {
	case "503":
		b.Response = "503"
	case "403":
		b.Response = "403"
	case "drop":
		b.Response = "reset"
	default:
		writeError(w, http.StatusUnprocessableEntity, "invalid", "response: 503, 403 or drop")
		return
	}
	if b.Reason == "" || len([]rune(b.Reason)) > 200 || strings.ContainsAny(b.Reason, "\r\n") {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "reason: 1 to 200 characters on one line")
		return
	}
	now := s.now()
	switch {
	case req.UntilMidnight:
		writeError(w, http.StatusUnprocessableEntity, "invalid", "untilMidnight: send until (the person's midnight, RFC 3339) instead")
		return
	case req.Minutes < 0 || req.Minutes > 0 && req.Until != "":
		writeError(w, http.StatusUnprocessableEntity, "invalid", "minutes: 0 (no end) or more, and not with until")
		return
	case req.Until != "":
		t, err := time.Parse(time.RFC3339, req.Until)
		if err != nil || !t.After(now) || t.Sub(now) > 7*24*time.Hour {
			writeError(w, http.StatusUnprocessableEntity, "invalid", "until: RFC 3339, in the next 7 days")
			return
		}
		b.ExpiresAt = uint64(t.Unix())
	case req.Minutes > 0:
		if req.Minutes > 7*24*60 {
			writeError(w, http.StatusUnprocessableEntity, "invalid", "minutes: at most 7 days")
			return
		}
		b.ExpiresAt = uint64(now.Add(time.Duration(req.Minutes) * time.Minute).Unix())
	}
	switch sc.Gateway {
	case "", mydc.GatewayExternal, mydc.GatewayLocal:
		b.Gateway = sc.Gateway
	case "all":
		b.Gateway = mydc.GatewayBoth
	default:
		writeError(w, http.StatusUnprocessableEntity, "invalid", "scope.gateway: external, local or all")
		return
	}
	needMapping := false
	switch sc.Kind {
	case "route":
		b.Scope, needMapping = "route", true
	case "task":
		b.Scope, needMapping = "backend", true
		if sc.Task == "" {
			writeError(w, http.StatusUnprocessableEntity, "invalid", "scope.task: the backend to block")
			return
		}
	case "app":
		b.Scope, needMapping = "instance", true
	case "host":
		b.Scope, b.Host = "host", sc.Host
	case "source":
		if len(sc.Sources) != 1 {
			writeError(w, http.StatusUnprocessableEntity, "invalid", "scope.sources: one IP or CIDR per block")
			return
		}
		p, err := netip.ParsePrefix(sc.Sources[0])
		if err != nil {
			if a, aerr := netip.ParseAddr(sc.Sources[0]); aerr == nil {
				p, err = a.Prefix(a.BitLen())
			}
		}
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, "invalid", "scope.sources: an IP or CIDR")
			return
		}
		if p.Bits() == 0 {
			writeError(w, http.StatusUnprocessableEntity, "invalid", "scope.sources: 0.0.0.0/0 and ::/0 are refused; block the app instead")
			return
		}
		b.Scope, b.Source = "source", p.Masked().String()
		if sc.App != "" {
			b.Apps = []string{sc.App}
		}
	case "node":
		b.Scope, b.Node, b.Tenant = "node", sc.Node, ""
	case "tenant":
		b.Scope = "tenant"
	case "gateway":
		b.Scope, b.Gateway, b.Tenant = "gateway", sc.Gateway, ""
	default:
		writeError(w, http.StatusUnprocessableEntity, "invalid", "scope.kind: route, host, task, app, source, node, tenant or gateway")
		return
	}
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c mydc.Conn, _ mydc.Session) (string, any, uint64, string, error) {
		b.ID = blockID(req.OpID)
		if needMapping {
			if err := s.blockMapping(ctx, c, &b, sc.App, sc.Node, sc.Route, sc.Host, sc.Prefix, sc.Task); err != nil {
				return "", nil, 0, "", err
			}
		}
		// Actor and CreatedAt are mydcd's, from the signed original.
		probe := b
		probe.Actor, probe.CreatedAt = "probe", uint64(now.Unix())
		if !probe.Valid() {
			return "", nil, 0, "", invalid("scope: these values do not make a block (" + sc.Kind + ")")
		}
		return mydc.ActionIngressBlock, control.IngressBlockChange{Block: b}, 0, "ingress/block/" + b.ID, nil
	})
}

// blockMapping fills the mapping Key (and route/backend) of an instance,
// route or backend block: one app on one server.
func (s *Server) blockMapping(ctx context.Context, c mydc.Conn, b *ingress.Block, app, node, route, host, prefix, task string) error {
	if app == "" || b.Tenant == "" {
		return invalid("scope: tenant and app")
	}
	iv, err := ingressRead(ctx, c, control.IngressQuery{Tenant: b.Tenant, App: app, Node: node})
	if err != nil {
		return err
	}
	switch len(iv.Mappings) {
	case 0:
		return invalid("scope: the app has no external access instance there")
	case 1:
	default:
		return invalid("scope.node: the app runs on several servers; block it on one")
	}
	m := iv.Mappings[0]
	b.App, b.Key = m.App, m.Key
	switch b.Scope {
	case "route":
		for _, rt := range m.Spec.Routes {
			if route != "" && rt.ID == route || route == "" && rt.Host == host && rt.Prefix == prefix {
				b.Route, b.Host, b.Prefix = rt.ID, rt.Host, rt.Prefix
				return nil
			}
		}
		return invalid("scope: no such route rule (blocks only take existing rules)")
	case "backend":
		for _, svc := range m.Spec.Services {
			for _, bs := range svc.Backends {
				if bs.ID == task || bs.Task == task {
					b.Service, b.Backend = svc.ID, bs.ID
					return nil
				}
			}
		}
		return invalid("scope.task: no such backend of the app")
	}
	return nil
}

func (s *Server) findBlock(ctx context.Context, c mydc.Conn, id string) (*control.IngressBlockView, error) {
	p, err := ingressPaged(ctx, c, control.IngressQuery{Part: "blocks"})
	if err != nil {
		return nil, err
	}
	for i := range p.Blocks {
		if v := &p.Blocks[i]; v.Block.ID == id && !v.Removed {
			return v, nil
		}
	}
	return nil, &httpErr{http.StatusNotFound, "not-found", "no such block"}
}

// PUT /ingress/blocks/{id} {opId, minutes, revision} → {op}: extend. Only a
// block with an end can be extended, and only later.
func (s *Server) handleExtendIngressBlock(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID     string `json:"opId"`
		Minutes  int    `json:"minutes"`
		Revision uint64 `json:"revision"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if req.Minutes < 1 || req.Minutes > 7*24*60 {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "minutes: 1 to 7 days")
		return
	}
	id := r.PathValue("id")
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c mydc.Conn, _ mydc.Session) (string, any, uint64, string, error) {
		v, err := s.findBlock(ctx, c, id)
		if err != nil {
			return "", nil, 0, "", err
		}
		if v.Revision != req.Revision {
			return "", nil, 0, "", &httpErr{http.StatusConflict, "stale", "the block changed; read it again"}
		}
		if v.Block.ExpiresAt == 0 {
			return "", nil, 0, "", invalidCode("no-end", "the block has no end; nothing to extend")
		}
		from := s.now()
		if t := time.Unix(int64(v.Block.ExpiresAt), 0); t.After(from) {
			from = t
		}
		return mydc.ActionIngressBlockExtend, control.IngressBlockSelection{ID: id, ExpiresAt: uint64(from.Add(time.Duration(req.Minutes) * time.Minute).Unix())}, v.Revision, "ingress/block/" + id, nil
	})
}

// DELETE /ingress/blocks/{id} {opId} → {op}: lift it. The list shows it as
// lifting until every server has installed the book that lifted it.
func (s *Server) handleDeleteIngressBlock(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID string `json:"opId"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	id := r.PathValue("id")
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c mydc.Conn, _ mydc.Session) (string, any, uint64, string, error) {
		v, err := s.findBlock(ctx, c, id)
		if err != nil {
			return "", nil, 0, "", err
		}
		return mydc.ActionIngressUnblock, control.IngressBlockSelection{ID: id}, v.Revision, "ingress/block/" + id, nil
	})
}

// routeCertificates is a route host's loaded certificates, one per key
// family, ECDSA first (the observations are sorted so). A host with no
// loaded pair is one entry with only the error.
func routeCertificates(obs []ingress.CertificateObservation, host string) []map[string]any {
	var out []map[string]any
	for _, co := range obs {
		if co.Host != host {
			continue
		}
		cv := map[string]any{}
		if co.Fingerprint != ([32]byte{}) {
			cv["id"], cv["alg"] = fpHex(co.Fingerprint), co.Family
		}
		if co.Error != "" {
			cv["error"] = co.Error
		}
		if len(cv) > 0 {
			out = append(out, cv)
		}
	}
	return out
}
