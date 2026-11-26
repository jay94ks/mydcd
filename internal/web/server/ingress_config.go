// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/ingress"
	"github.com/jay94ks/mydcd/internal/web/mydc"
)

// Ingress settings (UI-5A/5B, REQ-62~65 real shape): gateways of a server,
// a route's balance, draining an app's instances, and the change history.
// The changes go to mydcd as actions (mydcd checks who may and what is
// valid); the history is read from mydcd each time.

type listenerReq struct {
	ID      string `json:"id"`
	Address string `json:"address"`
	TLS     bool   `json:"tls"`
	HTTP3   bool   `json:"http3"`
}

type gatewayReq struct {
	Enabled   bool           `json:"enabled"`
	Address   string         `json:"address"`
	Addresses []string       `json:"addresses"`
	Iface     string         `json:"iface"`
	Ports     []int          `json:"ports"`
	Sources   []string       `json:"sources"`
	Listeners *[]listenerReq `json:"listeners"`
}

// gateway: the request side as mydcd's ingress.Gateway. Listeners left out
// keep the side's current ones (cur).
func (g *gatewayReq) gateway(local bool, cur ingress.Gateway) (*ingress.Gateway, string) {
	if g == nil {
		return nil, ""
	}
	if g.Iface != "" {
		return nil, "iface: not supported; give address"
	}
	addrs := slices.Clone(g.Addresses)
	if g.Address != "" {
		if len(addrs) > 0 {
			return nil, "address or addresses, not both"
		}
		addrs = []string{g.Address}
	}
	if !local && len(g.Sources) > 0 {
		return nil, "sources: the local gateway only"
	}
	out := &ingress.Gateway{Enabled: g.Enabled, Addresses: []netip.Addr{}, Ports: []uint16{}, Listeners: []ingress.Listener{}}
	for _, a := range addrs {
		ip, err := netip.ParseAddr(a)
		if err != nil {
			return nil, "addresses: IP addresses"
		}
		out.Addresses = append(out.Addresses, ip)
	}
	for _, p := range g.Ports {
		if p < 1 || p > 65535 {
			return nil, "ports: 1..65535"
		}
		out.Ports = append(out.Ports, uint16(p))
	}
	for _, src := range g.Sources {
		pr, err := netip.ParsePrefix(src)
		if err != nil {
			return nil, "sources: CIDRs"
		}
		out.AllowedSources = append(out.AllowedSources, pr)
	}
	if g.Listeners == nil {
		out.Listeners = slices.Clone(cur.Listeners)
	} else {
		for _, l := range *g.Listeners {
			out.Listeners = append(out.Listeners, ingress.Listener{ID: l.ID, Address: l.Address, TLS: l.TLS, HTTP3: l.HTTP3})
		}
	}
	return out, ""
}

// gatewayConfigShape: one side of a gateway configuration as the screens
// show it.
func gatewaySideShape(g ingress.Gateway, local bool) map[string]any {
	addrs, ports, listeners := []string{}, []int{}, []map[string]any{}
	for _, a := range g.Addresses {
		addrs = append(addrs, a.String())
	}
	for _, p := range g.Ports {
		ports = append(ports, int(p))
	}
	for _, l := range g.Listeners {
		x := map[string]any{"id": l.ID, "address": l.Address, "http3": l.HTTP3}
		if l.TLS {
			x["tls"] = true
		}
		listeners = append(listeners, x)
	}
	v := map[string]any{"enabled": g.Enabled, "addresses": addrs, "ports": ports, "listeners": listeners}
	if local {
		srcs := []string{}
		for _, p := range g.AllowedSources {
			srcs = append(srcs, p.String())
		}
		v["sources"] = srcs
	}
	return v
}

func gatewayConfigShape(c ingress.GatewayConfiguration) map[string]any {
	return map[string]any{"external": gatewaySideShape(c.External, false), "local": gatewaySideShape(c.Local, true)}
}

// nodeGatewaysShape: mydcd's NodeGatewaysView (target and applied revision).
func nodeGatewaysShape(v control.NodeGatewaysView) map[string]any {
	out := gatewayConfigShape(v.Configuration)
	out["source"], out["revision"], out["appliedRevision"] = v.Source, v.Revision, v.AppliedRevision
	if v.Error != "" {
		out["error"] = v.Error
	}
	return out
}

// nodeGateways: Part gateways for one server (system administrator).
func nodeGateways(ctx context.Context, c mydc.Conn, node string) (control.NodeGatewaysView, error) {
	p, err := c.QueryIngresses(ctx, control.IngressQuery{Node: node, Part: "gateways"})
	if err != nil {
		return control.NodeGatewaysView{}, err
	}
	for _, v := range p.NodeGateways {
		if v.Node == node {
			return v, nil
		}
	}
	return control.NodeGatewaysView{}, &httpErr{http.StatusNotFound, "not-found", "node " + node}
}

// GET /nodes/{n}/gateways → nodeGatewaysShape.
func (s *Server) handleGetGateways(w http.ResponseWriter, r *http.Request, ws *webSession) {
	node := r.PathValue("n")
	if !safeParamRE.MatchString(node) {
		writeError(w, http.StatusBadRequest, "bad-request", "node: a name")
		return
	}
	read(s, w, r, ws, func(ctx context.Context, c mydc.Conn) (map[string]any, error) {
		v, err := nodeGateways(ctx, c, node)
		if err != nil {
			return nil, err
		}
		return nodeGatewaysShape(v), nil
	})
}

// PUT /nodes/{n}/gateways {opId, revision?, external?, local?} → {op}
// (set-node-gateways, control.NodeGatewaysChange without Evidence: the
// client's Prepare asks mydcd for it). Expected = the node's gateway record
// revision (0 before the first cluster setting), default the current one.
func (s *Server) handlePutGateways(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID     string      `json:"opId"`
		Revision *uint64     `json:"revision"`
		External *gatewayReq `json:"external"`
		Local    *gatewayReq `json:"local"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	node := r.PathValue("n")
	if !safeParamRE.MatchString(node) {
		writeError(w, http.StatusBadRequest, "bad-request", "node: a name")
		return
	}
	msg := ""
	if req.External == nil && req.Local == nil {
		msg = "external or local"
	} else if _, m := req.External.gateway(false, ingress.Gateway{}); m != "" {
		msg = m
	} else if _, m := req.Local.gateway(true, ingress.Gateway{}); m != "" {
		msg = m
	}
	if msg != "" {
		writeError(w, http.StatusUnprocessableEntity, "invalid", msg)
		return
	}
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c mydc.Conn, _ mydc.Session) (string, any, uint64, string, error) {
		cur, err := nodeGateways(ctx, c, node)
		if err != nil {
			return "", nil, 0, "", err
		}
		q := control.NodeGatewaysChange{Node: node}
		q.External, _ = req.External.gateway(false, cur.Configuration.External)
		q.Local, _ = req.Local.gateway(true, cur.Configuration.Local)
		if control.MergeNodeGateways(cur.Configuration, q.External, q.Local).Validate() != nil {
			return "", nil, 0, "", invalid("gateways: an enabled side needs addresses, ports and listeners on them; addresses not 0.0.0.0/::, not shared between sides")
		}
		expected := cur.Revision
		if req.Revision != nil {
			expected = *req.Revision
		}
		return mydc.ActionSetNodeGateways, q, expected, "node/" + node + "/gateways", nil
	})
}

type balanceRule struct {
	ID      string `json:"id,omitempty"`
	Kind    string `json:"kind"`
	Name    string `json:"name,omitempty"`
	Op      string `json:"op,omitempty"`
	Value   string `json:"value,omitempty"`
	Percent int    `json:"percent,omitempty"`
	Key     string `json:"key,omitempty"`
	Group   string `json:"group"`
}

type balanceGroup struct {
	Labels   map[string]string `json:"labels"`
	Version  string            `json:"version"`
	Backends []string          `json:"backends"`
}

type balanceReq struct {
	Method           string                  `json:"method"`
	HashKey          string                  `json:"hashKey"`
	Locality         bool                    `json:"locality"`
	SlowStartSeconds int                     `json:"slowStartSeconds"`
	Retry            int                     `json:"retry"`
	PerTaskLimit     int                     `json:"perTaskLimit"`
	Weights          map[string]int          `json:"weights"`
	Rules            []balanceRule           `json:"rules"`
	Groups           map[string]balanceGroup `json:"groups"`
	Fallback         string                  `json:"fallback"`
}

// balance: the request as mydcd's ingress.Balance (balanceShape's inverse).
// Each rule is one condition; mydcd's Validate is the last word.
func (b *balanceReq) balance() (ingress.Balance, string) {
	out := ingress.Balance{Method: b.Method, Key: b.HashKey, SlowStartSeconds: b.SlowStartSeconds, Retry: b.Retry, Weights: b.Weights, Fallback: b.Fallback}
	if b.PerTaskLimit != 0 {
		return out, "balance.perTaskLimit: mydcd has no per-task limit"
	}
	if b.Locality {
		out.Locality = "same-node"
	}
	if len(b.Groups) > 0 {
		out.Groups = map[string]ingress.BackendGroup{}
		for name, g := range b.Groups {
			out.Groups[name] = ingress.BackendGroup{Labels: g.Labels, Version: g.Version, Backends: g.Backends}
		}
	}
	for i, m := range b.Rules {
		c := ingress.BalanceCondition{ID: m.ID, Group: m.Group}
		if _, ok := out.Groups[m.Group]; !ok {
			// "key=value": a group of the backends with that label
			if k, val, cut := strings.Cut(m.Group, "="); cut && k != "" && val != "" {
				id := groupID(k + "-" + val)
				if out.Groups == nil {
					out.Groups = map[string]ingress.BackendGroup{}
				}
				out.Groups[id] = ingress.BackendGroup{Labels: map[string]string{k: val}}
				c.Group = id
			}
		}
		if c.ID == "" {
			c.ID = fmt.Sprintf("rule-%d", i+1)
		}
		vm := ingress.ValueMatch{}
		switch m.Op {
		case "equals":
			v := m.Value
			vm.Equal = &v
		case "prefix":
			v := m.Value
			vm.Prefix = &v
		case "present", "":
			vm.Present = true
		default:
			return out, "balance.rules.op: equals, prefix or present"
		}
		switch m.Kind {
		case "header":
			c.Headers = map[string]ingress.ValueMatch{m.Name: vm}
		case "cookie":
			c.Cookies = map[string]ingress.ValueMatch{m.Name: vm}
		case "query":
			c.Query = map[string]ingress.ValueMatch{m.Name: vm}
		case "method":
			c.Methods = strings.Split(strings.ToUpper(m.Value), ",")
		case "source":
			pr, err := netip.ParsePrefix(m.Value)
			if err != nil {
				return out, "balance.rules: source value is a CIDR"
			}
			c.Sources = []netip.Prefix{pr}
		case "percent":
			p := m.Percent
			c.Percent, c.Key = &p, m.Key
		default:
			return out, "balance.rules: kind header, cookie, query, method, source or percent"
		}
		out.Match = append(out.Match, c)
	}
	if err := out.Validate(); err != nil {
		return out, "balance: " + err.Error()
	}
	return out, ""
}

// groupID: a label as a group name (letters, digits, - . _).
func groupID(s string) string {
	b := []byte(s)
	for i, ch := range b {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '.' || ch == '_') {
			b[i] = '-'
		}
	}
	if len(b) > 64 {
		b = b[:64]
	}
	return string(b)
}

// PUT /t/{t}/apps/{app}/ingress/balance {opId, route, revision?, balance} →
// {op} (set-ingress-balance). Expected = the route's balanceRevision (0 =
// still the app's own declaration), default the current one.
func (s *Server) handlePutIngressBalance(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID     string     `json:"opId"`
		Route    string     `json:"route"`
		Revision *uint64    `json:"revision"`
		Balance  balanceReq `json:"balance"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if !safeParamRE.MatchString(req.Route) {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "route: the route id")
		return
	}
	b, msg := req.Balance.balance()
	if msg != "" {
		writeError(w, http.StatusUnprocessableEntity, "invalid", msg)
		return
	}
	tenant, app := r.PathValue("t"), r.PathValue("app")
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c mydc.Conn, _ mydc.Session) (string, any, uint64, string, error) {
		expected := uint64(0)
		if req.Revision != nil {
			expected = *req.Revision
		} else {
			found := false
			d, err := readIngress(ctx, c, control.IngressQuery{Tenant: tenant, App: app}, false)
			if err != nil {
				return "", nil, 0, "", err
			}
			for _, m := range d.iv.Mappings {
				for _, rt := range m.Spec.Routes {
					if rt.ID == req.Route {
						expected, found = max(expected, rt.BalanceRevision), true
					}
				}
			}
			if !found {
				return "", nil, 0, "", invalid("route: not a route of this app")
			}
		}
		return mydc.ActionSetIngressBalance, control.IngressBalanceChange{Tenant: tenant, App: app, Route: req.Route, Balance: b}, expected,
			"app/" + app + "/ingress/" + req.Route, nil
	})
}

// drainRevision: the revision of the (tenant, app, node) drain record.
// mydcd does not show records by key (a mapping's DrainRevision is the
// record that wins there, app-wide or the node's), so it is the number of
// accepted drain/undrain changes of exactly that key in the history, which
// mydcd never trims (it refuses changes when full).
func drainRevision(ctx context.Context, c mydc.Conn, tenant, app, node string) (uint64, error) {
	q := control.IngressQuery{Tenant: tenant, App: app, Part: "history"}
	n := uint64(0)
	for range ingressHistoryPages {
		p, err := c.QueryIngresses(ctx, q)
		if err != nil {
			return 0, err
		}
		for _, h := range p.History {
			if (h.Action == mydc.ActionDrainIngress || h.Action == mydc.ActionUndrainIngress) && h.Tenant == tenant && h.App == app && h.Node == node {
				n++
			}
		}
		if p.Next == "" {
			return n, nil
		}
		q.After = p.Next
	}
	return 0, &httpErr{http.StatusConflict, "history-long", "too much history to find the drain revision; send revision"}
}

// POST /t/{t}/apps/{app}/ingress/drain {opId, node?, drainSeconds?,
// revision?} → {op}; DELETE (same body without drainSeconds) takes them
// back. Expected = that (app, node) drain record's revision (0 = none yet).
func (s *Server) handleIngressDrain(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID         string  `json:"opId"`
		Node         string  `json:"node"`
		DrainSeconds int     `json:"drainSeconds"`
		Revision     *uint64 `json:"revision"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if req.Node != "" && !safeParamRE.MatchString(req.Node) || req.DrainSeconds < 0 || req.DrainSeconds > 3600 {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "node: a name; drainSeconds: 0 (30) to 3600")
		return
	}
	action := mydc.ActionDrainIngress
	if r.Method == http.MethodDelete {
		action, req.DrainSeconds = mydc.ActionUndrainIngress, 0
	}
	tenant, app := r.PathValue("t"), r.PathValue("app")
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c mydc.Conn, _ mydc.Session) (string, any, uint64, string, error) {
		expected := uint64(0)
		if req.Revision != nil {
			expected = *req.Revision
		} else {
			var err error
			if expected, err = drainRevision(ctx, c, tenant, app, req.Node); err != nil {
				return "", nil, 0, "", err
			}
		}
		return action, control.IngressDrainChange{Tenant: tenant, App: app, Node: req.Node, DrainSeconds: uint64(req.DrainSeconds)}, expected, "app/" + app + "/ingress", nil
	})
}

// ingressHistoryPages bounds the history read for one answer (8 rows a
// page).
const ingressHistoryPages = 64

var ingressActionWord = map[string]string{mydc.ActionSetNodeGateways: "게이트웨이 설정", mydc.ActionSetIngressBalance: "분배 방식 변경",
	mydc.ActionDrainIngress: "비우기", mydc.ActionUndrainIngress: "비우기 해제", mydc.ActionIngressBlock: "긴급 차단",
	mydc.ActionIngressUnblock: "차단 해제", mydc.ActionIngressBlockExtend: "차단 연장", "set-ingress-host-policy": "호스트 정책 변경"}

// historyValue: a history Detail / Previous as the screens show it.
func historyValue(action string, raw []byte) any {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	switch action {
	case mydc.ActionSetNodeGateways:
		var c ingress.GatewayConfiguration
		if json.Unmarshal(raw, &c) == nil {
			return gatewayConfigShape(c)
		}
	case mydc.ActionSetIngressBalance:
		var b ingress.Balance
		if json.Unmarshal(raw, &b) == nil {
			return balanceShape(&b)
		}
	case mydc.ActionDrainIngress, mydc.ActionUndrainIngress:
		var d struct {
			Draining, LastMapping  bool
			DrainSeconds, Deadline uint64
		}
		if json.Unmarshal(raw, &d) == nil {
			v := map[string]any{"draining": d.Draining, "drainSeconds": d.DrainSeconds}
			if d.LastMapping {
				v["lastMapping"] = true
			}
			if d.Deadline > 0 {
				v["deadline"] = unixTime(int64(d.Deadline))
			}
			return v
		}
	}
	var v any
	if json.Unmarshal(raw, &v) == nil {
		return camelValue(v)
	}
	return nil
}

// camelValue lower-cases the first letter of mydcd's JSON keys.
func camelValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, e := range x {
			if k != "" {
				k = strings.ToLower(k[:1]) + k[1:]
			}
			out[k] = camelValue(e)
		}
		return out
	case []any:
		for i := range x {
			x[i] = camelValue(x[i])
		}
	}
	return v
}

func ingressHistoryView(e control.IngressHistoryView, names map[string]string) map[string]any {
	what := ingressActionWord[e.Action]
	if what == "" {
		what = e.Action
	}
	by := e.Actor
	if n := names[e.Actor]; n != "" {
		by = n
	}
	v := map[string]any{"at": rfc3339(time.Unix(e.At, 0)), "what": what, "by": by, "action": e.Action, "request": e.Request}
	for k, x := range map[string]string{"tenant": e.Tenant, "app": e.App, "node": e.Node, "route": e.Route, "gateway": e.Gateway} {
		if x != "" {
			v[k] = x
		}
	}
	if d := historyValue(e.Action, e.Detail); d != nil {
		v["detail"] = d
	}
	if p := historyValue(e.Action, e.Previous); p != nil {
		v["previous"] = p
	}
	if e.Action == mydc.ActionSetIngressBalance {
		var now, before ingress.Balance
		if json.Unmarshal(e.Detail, &now) == nil {
			from := "앱 선언"
			if len(e.Previous) > 0 && string(e.Previous) != "null" && json.Unmarshal(e.Previous, &before) == nil {
				from = methodOr(before.Method)
			}
			v["what"] = what + ": " + from + " → " + methodOr(now.Method)
		}
	}
	return v
}

func methodOr(m string) string {
	if m == "" {
		return "round-robin"
	}
	return m
}

// GET /ingress/history?tenant=&app=&node=&after= → {items, next}: mydcd's
// page (newest first, 8 rows). Without a tenant it is the system
// administrator's whole history (mydcd decides).
func (s *Server) handleIngressHistory(w http.ResponseWriter, r *http.Request, ws *webSession) {
	qs := r.URL.Query()
	tenant, app, node, after := qs.Get("tenant"), qs.Get("app"), qs.Get("node"), qs.Get("after")
	if tenant != "" && !safeParamRE.MatchString(tenant) || app != "" && (tenant == "" || !safeParamRE.MatchString(app)) ||
		node != "" && !safeParamRE.MatchString(node) || len(after) > 512 {
		writeError(w, http.StatusBadRequest, "bad-request", "tenant, app inside it, node, after")
		return
	}
	read(s, w, r, ws, func(ctx context.Context, c mydc.Conn) (map[string]any, error) {
		p, err := c.QueryIngresses(ctx, control.IngressQuery{Tenant: tenant, App: app, Node: node, Part: "history", After: after})
		if err != nil {
			return nil, err
		}
		names := usernames(ctx, c)
		items := []map[string]any{}
		for _, e := range p.History {
			items = append(items, ingressHistoryView(e, names))
		}
		return map[string]any{"items": items, "next": p.Next}, nil
	})
}

// balanceHistory: the app's balance changes on the newest history pages,
// newest first ({at, what, by, route}).
func balanceHistory(ctx context.Context, c mydc.Conn, tenant, app string) ([]map[string]any, error) {
	q := control.IngressQuery{Tenant: tenant, App: app, Part: "history"}
	out := []map[string]any{}
	names := usernames(ctx, c)
	for range 8 {
		p, err := c.QueryIngresses(ctx, q)
		if err != nil {
			return nil, err
		}
		for _, e := range p.History {
			if e.Action == mydc.ActionSetIngressBalance {
				v := ingressHistoryView(e, names)
				out = append(out, map[string]any{"at": v["at"], "what": v["what"], "by": v["by"], "route": e.Route})
			}
		}
		if p.Next == "" {
			break
		}
		q.After = p.Next
	}
	return out, nil
}
