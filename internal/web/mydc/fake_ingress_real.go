// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/ingress"
)

// REQ-22 in mydcd's real shape (docs/reference/ingress-management.md,
// ingress-gateways.md, unix-sockets.md): one `ingresses` read
// (control.IngressQuery{Node, Tenant, App, Key, Part, After, Offset} →
// control.IngressPage), the Raft blocks ingress-block {control.
// IngressBlockChange} / ingress-unblock · ingress-block-extend {control.
// IngressBlockSelection} and set-ingress-host-policy {control.
// IngressHostPolicyChange} under control/ingress-management.
//
// Fake-only:
//   - Mappings come from the old mock's instances (fixture Ingresses): key
//     ingress/app/{tenant}/{app}/{node}, Owner = FixtureKey(node), Revision
//     = Generation. Shared fixture listeners become Spec listeners
//     {ID, Shared: ID} and the node's shared gateway listeners; routes keep
//     host/prefix/gateway, backends are grouped by service (no Balance).
//   - Runtime is synthetic and steady: listeners and backends as seeded,
//     Certificates from the seeded ingress certificate observations of that
//     node and host, metrics/errors from the old mock's generators.
//   - Every owner installs the block book at once: Runtime.BlockRevision is
//     the book revision (= IngressPage.BlockRevision) and every active block is Applied on each node it
//     maps to (AppliedAt = CreatedAt, BlockedRequests from a hash), unless
//     HoldIngressBlocks froze that node (fake_ingress_runtime.go).
//   - Quotas per tenant×node: 8 instances, 16 listeners, 4000 connections,
//     2000 requests, 64 MiB buffer.
//   - set-node-gateways / set-ingress-balance / drain-ingress and the
//     ingress history (no mydcd counterpart) stay until the screens are
//     decided; a real block / unblock / extend is added to that history.

const ActionSetIngressHostPolicy = "set-ingress-host-policy"

type ingressRealState struct {
	revision uint64
	blocks   []control.IngressBlockRecord
	policies []control.IngressHostPolicyRecord
	// Fake-only knobs (fake_ingress_runtime.go).
	held         map[string]heldBlocks     // node → frozen installed policy
	routeMetrics map[string]ingress.Metric // mapping key \x00 route
	// REQ-62~65 real records (fake_ingress_operations_real.go).
	gateways  []control.NodeGatewaysRecord
	balances  []control.IngressBalanceRecord
	drains    []control.IngressDrainRecord
	history   []control.IngressHistoryRecord
	gwApplied map[string]uint64
	gwError   map[string]string
}

func ingressRealKey(in IngressInstance) string {
	return "ingress/app/" + in.Tenant + "/" + in.App + "/" + in.Node
}

func (w *world) ingressSpec(in IngressInstance) ingress.Spec {
	s := ingress.Spec{Schema: 1, Owner: hex.EncodeToString(pub32p(in.Node)), Tenant: in.Tenant, App: in.App,
		MaxRequests: 256, MaxConnections: 512, MaxHeaderBytes: 32 << 10, BufferBytes: 4 << 20, MaxBodyBytes: 16 << 20,
		RequestTimeoutMS: 30000, DialTimeoutMS: 3000, ResponseHeaderTimeoutMS: 10000, HealthIntervalMS: 5000}
	s.Lifecycle.Drain = in.Draining
	for _, l := range in.Listeners {
		if l.Shared {
			s.Listeners = append(s.Listeners, ingress.Listener{ID: l.ID, Shared: l.ID})
		} else {
			s.Listeners = append(s.Listeners, ingress.Listener{ID: l.ID, Address: l.Address, TLS: l.TLS, HTTP3: l.HTTP3})
		}
	}
	for _, r := range in.Routes {
		s.Routes = append(s.Routes, ingress.Route{ID: r.ID, Host: r.Host, Prefix: r.Prefix, Service: r.Service, Gateway: r.Gateway})
	}
	byService := map[string]*ingress.Service{}
	var order []string
	for _, b := range in.Backends {
		svc := byService[b.Service]
		if svc == nil {
			svc = &ingress.Service{ID: b.Service}
			byService[b.Service] = svc
			order = append(order, b.Service)
		}
		addr, _ := netip.ParseAddr(b.Address)
		svc.Backends = append(svc.Backends, ingress.BackendSpec{ID: b.Task, Task: b.Task, Network: b.Network, Node: b.Node, Generation: b.Generation,
			Address: addr, Port: uint16(b.Port), Weight: b.Weight, HealthPath: "/"})
	}
	for _, id := range order {
		s.Services = append(s.Services, *byService[id])
	}
	return s
}

func pub32p(node string) []byte {
	p := pub32(FixtureKey(node))
	return p[:]
}

func (w *world) ingressSnapshot(in IngressInstance, row control.IngressMapping, now int64) ingress.InstanceSnapshot {
	ms := uint64(now) * 1000
	s := ingress.InstanceSnapshot{Generation: row.Generation, Revision: row.Revision, ObservedAt: ms, Ready: in.Ready, Draining: in.Draining, Error: in.Error,
		Connections: 6*len(in.Listeners) + int(seed(in.App+in.Node)%20), Requests: 2 + int(seed(in.Node+in.App)%12)}
	for _, l := range in.Listeners {
		s.Listeners = append(s.Listeners, ingress.ListenerSnapshot{ID: l.ID, Address: l.Address, Gateway: l.Gateway, TLS: l.TLS, HTTP3: l.HTTP3, State: l.State})
	}
	hosts := map[string]bool{}
	for _, r := range in.Routes {
		hosts[r.Host] = true
	}
	for _, o := range w.ingressCerts {
		if o.Node != in.Node || !hosts[o.Host] {
			continue
		}
		c := ingress.CertificateObservation{Host: o.Host, Fingerprint: o.Fingerprint, NotAfter: o.NotAfter, LoadedAt: o.LoadedAt, Error: o.LastError}
		if o.Missing && c.Error == "" {
			c.Error = "CERTIFICATE_MISSING"
		}
		s.Certificates = append(s.Certificates, c)
	}
	sort.Slice(s.Certificates, func(i, j int) bool { return s.Certificates[i].Host < s.Certificates[j].Host })
	for _, b := range in.Backends {
		s.Backends = append(s.Backends, ingress.BackendSnapshot{ID: b.Task, Task: b.Task, Node: b.Node, Network: b.Network, Address: b.Address,
			Port: uint16(b.Port), Weight: b.Weight, Generation: b.Generation, Healthy: b.Healthy, ObservedAt: uint64(b.LastCheckAt) * 1000})
	}
	rev, installed, _ := w.installedBlocks(in.Node)
	s.BlockRevision = rev
	for _, r := range installed {
		if !r.Removed && r.Block.Active(uint64(now)) && realBlockMaps(r.Block, row) {
			s.Blocks = append(s.Blocks, w.blockApplication(r.Block, in.Node))
		}
	}
	s.Metrics = ingressRealMetrics(in, now)
	for i, m := range s.Metrics.Routes {
		if o, ok := w.ireal.routeMetrics[row.Key+"\x00"+m.ID]; ok {
			s.Metrics.Routes[i] = o
		}
	}
	return s
}

func (w *world) blockApplication(b ingress.Block, node string) ingress.BlockApplication {
	if !w.blockInstalled(b.ID, node) {
		return ingress.BlockApplication{ID: b.ID, Node: node}
	}
	return ingress.BlockApplication{ID: b.ID, Node: node, Applied: true, AppliedAt: b.CreatedAt, BlockedRequests: seed(b.ID+node) % 500}
}

func realMetric(id string, set IngressMetricSet) ingress.Metric {
	total := set.C2xx + set.C3xx + set.C4xx + set.C5xx + set.Blocked
	m := ingress.Metric{ID: id, Requests: total, Blocked: set.Blocked, ReceivedBytes: set.BytesIn, SentBytes: set.BytesOut, Rate: set.RatePerSec,
		Responses: [4]uint64{set.C2xx, set.C3xx, set.C4xx, set.C5xx}, P50MS: uint64(set.P50MS), P95MS: uint64(set.P95MS), P99MS: uint64(set.P99MS),
		OpenConnections: uint64(set.Connections)}
	if len(set.ProxyFailures) > 0 {
		m.Failures = map[string]uint64{}
		for k, v := range set.ProxyFailures {
			m.Failures[k] = v
		}
	}
	return m
}

// ingressRealMetrics: the last 60 s (the old mock's "1m" window) and its
// error samples, path without query, source masked.
func ingressRealMetrics(in IngressInstance, now int64) ingress.Metrics {
	m := ingress.Metrics{ConnectionKind: "upstream-live", WindowSeconds: 60}
	m.Instance = realMetric("instance", metricSets(in.Node+in.Tenant+in.App, false, false)[0])
	for _, r := range in.Routes {
		m.Routes = append(m.Routes, realMetric(r.ID, metricSets(in.Node+r.ID, false, false)[0]))
	}
	for _, b := range in.Backends {
		m.Backends = append(m.Backends, realMetric(b.Task, metricSets(in.Node+b.Task, false, !b.Healthy)[0]))
	}
	gws := map[string]bool{}
	for _, l := range in.Listeners {
		gws[l.Gateway] = true
	}
	for _, g := range sortedKeys(gws) {
		m.Gateways = append(m.Gateways, realMetric(g, metricSets(in.Node+g, false, false)[0]))
	}
	for i := 0; i < 24 && len(in.Routes) > 0; i++ {
		r := in.Routes[i%len(in.Routes)]
		e := ingress.ErrorSample{At: uint64(now-int64(i)*37) * 1000, Method: "GET", Host: r.Host, Path: strings.TrimSuffix(r.Prefix, "/") + fmt.Sprintf("/item/%d", i),
			Status: 404, DurationMS: uint64(3 + i), Source: fmt.Sprintf("198.51.%d.0/24", 100+i%5)}
		switch {
		case i%6 == 5:
			e.Status, e.Failure, e.DurationMS = 502, "connect", 1000
			if len(in.Backends) > 0 {
				e.Backend = in.Backends[0].Task
			}
		case i%4 == 3:
			e.Method, e.Status, e.Path = "POST", 400, r.Prefix
		}
		m.Errors = append(m.Errors, e)
	}
	return m
}

func realBlockMaps(b ingress.Block, row control.IngressMapping) bool {
	if b.Node != "" && b.Node != row.Node || b.Tenant != "" && b.Tenant != row.Tenant || b.App != "" && b.App != row.App || b.Key != "" && b.Key != row.Key {
		return false
	}
	switch b.Scope {
	case "host", "route":
		for _, r := range row.Spec.Routes {
			if r.Host == b.Host && (b.Scope == "host" || r.Prefix == b.Prefix) {
				return true
			}
		}
		return false
	case "backend":
		for _, svc := range row.Spec.Services {
			if svc.ID == b.Service {
				for _, k := range svc.Backends {
					if k.ID == b.Backend {
						return true
					}
				}
			}
		}
		return false
	case "source":
		return len(b.Apps) == 0 || slices.Contains(b.Apps, row.App)
	}
	return true
}

func (w *world) realMappings() []control.IngressMapping {
	var out []control.IngressMapping
	for _, in := range w.ing.instances {
		out = append(out, control.IngressMapping{Key: ingressRealKey(in), Tenant: in.Tenant, App: in.App, Node: in.Node, Owner: pub32(FixtureKey(in.Node)),
			Generation: in.Generation, Revision: in.Generation, Draining: in.Draining, Spec: w.ingressSpec(in)})
	}
	slices.SortFunc(out, func(a, b control.IngressMapping) int { return strings.Compare(a.Key, b.Key) })
	return out
}

func (w *world) realBlockTargetMissing(b ingress.Block) bool {
	if b.Scope == "node" || b.Scope == "tenant" || b.Scope == "source" || b.Scope == "gateway" {
		return false
	}
	for _, row := range w.realMappings() {
		if realBlockMaps(b, row) {
			return false
		}
	}
	return true
}

func (w *world) realBlockView(r control.IngressBlockRecord, now int64) control.IngressBlockView {
	return control.IngressBlockView{Block: r.Block, Revision: r.Revision, Removed: r.Removed, Active: !r.Removed && r.Block.Active(uint64(now)), TargetMissing: w.realBlockTargetMissing(r.Block)}
}

const (
	fakeIngressMaxInstances   = 8
	fakeIngressMaxListeners   = 16
	fakeIngressMaxConnections = 4000
	fakeIngressMaxRequests    = 2000
	fakeIngressBufferBytes    = 64 << 20
)

func addQuota(s *control.IngressNodeSummary) {
	s.MaxIngressInstances += fakeIngressMaxInstances
	s.MaxIngressListeners += fakeIngressMaxListeners
	s.MaxIngressConnections += fakeIngressMaxConnections
	s.MaxIngressRequests += fakeIngressMaxRequests
	s.IngressBufferBytes += fakeIngressBufferBytes
}

// gatewaySummaries: the node's shared listeners, one bounded sequence of
// listener/host bindings per gateway (4 a page by offset).
func (w *world) gatewaySummaries(node string, system bool, visible func(tenant, app string) bool, offset uint32) []control.IngressGatewaySummary {
	type listener struct {
		obs   ingress.SharedGatewayObservation
		hosts []ingress.SharedHostObservation
	}
	byID := map[string]*listener{}
	for _, in := range w.ing.instances {
		if in.Node != node {
			continue
		}
		for _, l := range in.Listeners {
			if !l.Shared {
				continue
			}
			x := byID[l.ID]
			if x == nil {
				x = &listener{obs: ingress.SharedGatewayObservation{ID: l.ID, Gateway: l.Gateway, Address: l.Address, HTTP3: l.HTTP3, Ready: l.State == "listening"}}
				byID[l.ID] = x
			}
			for _, r := range in.Routes {
				if r.Gateway == l.Gateway || r.Gateway == GatewayBoth {
					x.hosts = append(x.hosts, ingress.SharedHostObservation{Host: r.Host, Prefix: r.Prefix, Tenant: in.Tenant, App: in.App})
				}
			}
		}
	}
	var out []control.IngressGatewaySummary
	for _, kind := range []string{GatewayExternal, GatewayLocal} {
		e := control.IngressGatewaySummary{Gateway: kind, Offset: offset}
		configured := false
		for _, g := range w.ing.gateways[node] {
			if g.Kind == kind {
				configured = true
				if system {
					e.SourceRejected += g.RejectedSources
					e.Unmatched += seed(node+kind) % 40
				}
			}
		}
		add := func(x *listener, h *ingress.SharedHostObservation) {
			i := e.BindingsTotal
			e.BindingsTotal++
			if i < int(offset) || i >= int(offset)+4 {
				return
			}
			row := x.obs
			if h != nil {
				row.Hosts = []ingress.SharedHostObservation{*h}
			}
			e.Listeners = append(e.Listeners, row)
		}
		for _, id := range sortedKeys(byID) {
			x := byID[id]
			if x.obs.Gateway != kind {
				continue
			}
			sort.Slice(x.hosts, func(i, j int) bool { return x.hosts[i].Host+x.hosts[i].Prefix < x.hosts[j].Host+x.hosts[j].Prefix })
			if len(x.hosts) == 0 && system {
				add(x, nil)
			}
			for _, h := range x.hosts {
				if system || visible(h.Tenant, h.App) {
					add(x, &h)
				}
			}
		}
		if int(offset)+4 < e.BindingsTotal {
			e.Next = offset + 4
		}
		if configured && (system || e.BindingsTotal > 0) {
			out = append(out, e)
		}
	}
	return out
}

// QueryIngresses: `ingresses`. Part mappings (default, one mapping a page,
// After = the previous Next key; inside it Offset/Next pages listeners,
// routes, backends, blocks and certificates by 4), metrics (dimensions by
// 4), errors (16), blocks (8 by Offset) or policies (4 by Offset).
func (c *fakeConn) QueryIngresses(ctx context.Context, q control.IngressQuery) (control.IngressPage, error) {
	const m = "ingresses"
	if !q.Valid() {
		return control.IngressPage{}, fail(m, CodeInvalid, "ingress query")
	}
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return control.IngressPage{}, err
	}
	defer c.unlock()
	w := c.f.w
	now := c.f.now().Unix()
	if q.Tenant != "" && !w.canRead(user, q.Tenant) {
		return control.IngressPage{}, fail(m, CodeDenied, "")
	}
	system := w.admin(user)
	allowed := func(tenant string) bool { return system || w.canRead(user, tenant) }
	out := control.IngressPage{Schema: 1, Index: w.root, Epoch: w.ledgerEpoch, RootRevision: w.keyRoot(control.IngressManagementKey), BlockRevision: w.ireal.revision}
	switch q.Part {
	case "history":
		if q.Tenant == "" && !system {
			return control.IngressPage{}, fail(m, CodeDenied, "")
		}
		var err error
		if out.History, out.Next, err = w.ingressHistoryPage(user, q, system); err != nil {
			return control.IngressPage{}, fail(m, CodeInvalid, err.Error())
		}
		return out, nil
	case "gateways":
		if !system || q.Node == "" || q.Tenant != "" || q.App != "" {
			return control.IngressPage{}, fail(m, CodeDenied, "")
		}
		if w.memberIndex(q.Node) < 0 {
			return control.IngressPage{}, fail(m, CodeInvalid, "node")
		}
		if ck := q.Check; ck != nil {
			out.GatewayEvidence, out.GatewayCheckError = w.gatewayEvidence(q.Node, ck.Request, user, c.session.Key, ck.Expected, now, ck.External, ck.Local)
		}
		v := w.nodeGatewaysView(q.Node)
		out.NodeGateways = []control.NodeGatewaysView{v}
		out.Nodes = []control.IngressNodeSummary{{Node: q.Node, Owner: pub32(FixtureKey(q.Node)), Configuration: &v}}
		return out, nil
	}
	mb := w.ireal.management()
	for _, r := range w.ireal.blocks {
		b := r.Block
		if (system || b.Tenant != "" && allowed(b.Tenant)) && (q.Tenant == "" || b.Tenant == q.Tenant) && (q.Node == "" || b.Node == "" || b.Node == q.Node) {
			out.Blocks = append(out.Blocks, w.realBlockView(r, now))
		}
	}
	for _, h := range w.ireal.policies {
		if (q.Tenant == "" || q.Tenant == h.Tenant) && allowed(h.Tenant) {
			out.HostPolicies = append(out.HostPolicies, control.IngressHostPolicyView{Tenant: h.Tenant, Policy: h.Policy, Revision: h.Revision})
		}
	}
	instances := map[string]IngressInstance{}
	for _, in := range w.ing.instances {
		instances[ingressRealKey(in)] = in
	}
	summaries := map[string]control.IngressNodeSummary{}
	quota := map[string]bool{}
	listenerSeen := map[string]bool{}
	for _, row := range w.realMappings() {
		if !allowed(row.Tenant) || q.Node != "" && row.Node != q.Node || q.Tenant != "" && row.Tenant != q.Tenant || q.App != "" && row.App != q.App || q.Key != "" && row.Key != q.Key {
			continue
		}
		mb.ApplyMapping(&row)
		for _, r := range w.ireal.blocks {
			if !r.Removed && realBlockMaps(r.Block, row) {
				row.Blocks = append(row.Blocks, w.realBlockView(r, now))
			}
		}
		s := summaries[row.Node]
		s.Node, s.Owner = row.Node, row.Owner
		s.Instances++
		s.Listeners += countIngressListeners(row.Node, row.Spec.Listeners, listenerSeen)
		s.BufferBytes += row.Spec.BufferBytes
		in := instances[row.Key]
		s.Connections += 6*len(in.Listeners) + int(seed(in.App+in.Node)%20)
		s.Requests += 2 + int(seed(in.Node+in.App)%12)
		qt := q.Tenant
		if !system && qt == "" {
			qt = row.Tenant
		}
		if !quota[row.Node+"/"+qt] {
			addQuota(&s)
			quota[row.Node+"/"+qt] = true
		}
		summaries[row.Node] = s
		if row.Key > q.After && len(out.Mappings) < 1 {
			out.Mappings = append(out.Mappings, row)
		} else if row.Key > q.After && out.Next == "" {
			out.Next = out.Mappings[0].Key
		}
	}
	visible := func(tenant, app string) bool {
		return allowed(tenant) && (q.Tenant == "" || q.Tenant == tenant) && (q.App == "" || q.App == app)
	}
	enabled := true
	finish := func(s *control.IngressNodeSummary) {
		s.Enabled = &enabled
		s.Gateways = w.gatewaySummaries(s.Node, system, visible, q.Offset)
		if system {
			v := w.nodeGatewaysView(s.Node)
			s.Configuration = &v
		}
	}
	for _, row := range out.Mappings {
		if s, ok := summaries[row.Node]; ok {
			finish(&s)
			out.Nodes = append(out.Nodes, s)
			delete(summaries, row.Node)
		}
	}
	if q.Node != "" && len(out.Nodes) == 0 && q.Part != "blocks" && q.Part != "policies" && w.memberExists(q.Node) {
		var tenants []string
		switch {
		case q.Tenant != "":
			tenants = []string{q.Tenant}
		case system:
			tenants = []string{""}
		default:
			for _, t := range sortedKeys(w.tenants) {
				if w.canRead(user, t) {
					tenants = append(tenants, t)
				}
			}
		}
		if len(tenants) > 0 {
			s := control.IngressNodeSummary{Node: q.Node, Owner: pub32(FixtureKey(q.Node))}
			for range tenants {
				addQuota(&s)
			}
			finish(&s)
			out.Nodes = append(out.Nodes, s)
		}
	}
	for i := range out.Mappings {
		row := &out.Mappings[i]
		snap := w.ingressSnapshot(instances[row.Key], *row, now)
		if q.Part != "metrics" && q.Part != "errors" {
			snap.Metrics = ingress.Metrics{}
		}
		row.Runtime = &snap
		row.Ready, row.Draining, row.Error, row.ObservedAt = snap.Ready, snap.Draining, snap.Error, snap.ObservedAt
		pageRealIngressMapping(row, q)
	}
	switch q.Part {
	case "policies":
		start := min(int(q.Offset), len(out.HostPolicies))
		end := min(start+4, len(out.HostPolicies))
		out.Next = ""
		if end < len(out.HostPolicies) {
			out.Next = fmt.Sprint(end)
		}
		out.HostPolicies = slices.Clone(out.HostPolicies[start:end])
		out.Blocks, out.Mappings, out.Nodes = nil, nil, nil
		return out, nil
	case "blocks":
		out.HostPolicies = nil
		out.Next = ""
		start := min(int(q.Offset), len(out.Blocks))
		end := min(start+8, len(out.Blocks))
		if end < len(out.Blocks) {
			out.Next = fmt.Sprint(end)
		}
		out.Blocks = slices.Clone(out.Blocks[start:end])
		out.Mappings, out.Nodes = nil, nil
		if q.Node != "" && len(out.Blocks) > 0 {
			s := control.IngressNodeSummary{Node: q.Node, Owner: pub32(FixtureKey(q.Node)), Enabled: &enabled}
			out.Nodes = []control.IngressNodeSummary{s}
			for i := range out.Blocks {
				v := &out.Blocks[i]
				if v.Active && w.blockOnNode(v.Block, q.Node) {
					v.Applications = []ingress.BlockApplication{w.blockApplication(v.Block, q.Node)}
				}
			}
		}
		return out, nil
	}
	out.HostPolicies, out.Blocks = nil, nil
	return out, nil
}

func (w *world) memberExists(node string) bool {
	return slices.ContainsFunc(w.members, func(m FixtureMember) bool { return m.ID == node })
}

func (w *world) blockOnNode(b ingress.Block, node string) bool {
	if b.Node != "" && b.Node != node {
		return false
	}
	if b.Scope == "node" || b.Scope == "gateway" {
		return true
	}
	for _, row := range w.realMappings() {
		if row.Node == node && realBlockMaps(b, row) {
			return true
		}
	}
	return false
}

// pageRealIngressMapping is mydcd's pageIngressMapping (internal/app).
func pageRealIngressMapping(row *control.IngressMapping, q control.IngressQuery) {
	start := int(q.Offset)
	row.Offset = q.Offset
	row.ListenersTotal, row.RoutesTotal = len(row.Spec.Listeners), len(row.Spec.Routes)
	var all []ingress.BackendSpec
	for _, svc := range row.Spec.Services {
		all = append(all, svc.Backends...)
	}
	row.BackendsTotal = len(all)
	row.BlocksTotal = len(row.Blocks)
	if row.Runtime != nil {
		row.CertificatesTotal = len(row.Runtime.Certificates)
	}
	limit := max(row.ListenersTotal, row.RoutesTotal, row.BackendsTotal, row.BlocksTotal, row.CertificatesTotal)
	end := start + 4
	if end < limit {
		row.Next = uint32(end)
	}
	cut := func(n int) (int, int) { return min(start, n), min(end, n) }
	a, b := cut(len(row.Spec.Listeners))
	row.Spec.Listeners = slices.Clone(row.Spec.Listeners[a:b])
	a, b = cut(len(row.Spec.Routes))
	row.Spec.Routes = slices.Clone(row.Spec.Routes[a:b])
	selected := map[string]bool{}
	a, b = cut(len(all))
	for _, k := range all[a:b] {
		selected[k.ID] = true
	}
	var services []ingress.Service
	for _, svc := range row.Spec.Services {
		next := svc
		next.Backends = nil
		for _, k := range svc.Backends {
			if selected[k.ID] {
				next.Backends = append(next.Backends, k)
			}
		}
		if len(next.Backends) > 0 {
			services = append(services, next)
		}
	}
	row.Spec.Services = services
	a, b = cut(len(row.Blocks))
	row.Blocks = slices.Clone(row.Blocks[a:b])
	if row.Runtime == nil {
		return
	}
	s := row.Runtime
	a, b = cut(len(s.Certificates))
	s.Certificates = slices.Clone(s.Certificates[a:b])
	a, b = cut(len(s.Listeners))
	s.Listeners = slices.Clone(s.Listeners[a:b])
	a, b = cut(len(s.Backends))
	s.Backends = slices.Clone(s.Backends[a:b])
	a, b = cut(len(s.Blocks))
	s.Blocks = slices.Clone(s.Blocks[a:b])
	mt := &s.Metrics
	switch q.Part {
	case "errors":
		mt.Routes, mt.Backends, mt.Gateways, mt.Conditions = nil, nil, nil, nil
		n := len(mt.Errors)
		mt.Errors = slices.Clone(mt.Errors[min(start, n):min(start+16, n)])
		row.Next = 0
		if start+16 < n {
			row.Next = uint32(start + 16)
		}
	case "metrics":
		mt.Errors = nil
		most := max(len(mt.Routes), len(mt.Backends), len(mt.Gateways), len(mt.Conditions))
		row.Next = 0
		if end < most {
			row.Next = uint32(end)
		}
		for _, p := range []*[]ingress.Metric{&mt.Routes, &mt.Backends, &mt.Gateways, &mt.Conditions} {
			a, b = cut(len(*p))
			*p = slices.Clone((*p)[a:b])
		}
	}
}

// --- actions ---

func validHostPolicy(p ingress.HostPolicy) bool {
	raw, err := json.Marshal(p)
	if err != nil || len(raw) > 24<<10 || len(p.ExternalHosts) > 256 || len(p.LocalHosts) > 256 {
		return false
	}
	for _, h := range append(slices.Clone(p.ExternalHosts), p.LocalHosts...) {
		if _, err := ingress.NewTable([]ingress.Route{{ID: "host", Host: h, Prefix: "/", Service: "target"}}); err != nil {
			return false
		}
	}
	return true
}

// realBlockAuthorized: mydcd's ingressBlockAuthorized for block b.
func (w *world) realBlockAuthorized(actor string, b ingress.Block) error {
	if w.admin(actor) {
		return nil
	}
	if b.Scope == "node" || b.Scope == "tenant" || b.Scope == "gateway" || !w.canManage(actor, b.Tenant) {
		return errForbidden
	}
	if b.Scope == "host" {
		for _, row := range w.realMappings() {
			for _, r := range row.Spec.Routes {
				if r.Host == b.Host && (b.Node == "" || b.Node == row.Node) && row.Tenant != b.Tenant {
					return errForbidden
				}
			}
		}
	}
	return nil
}

// realBlockTarget: mydcd's ingressBlockTarget (a miss is ConditionFailed).
func (w *world) realBlockTarget(b ingress.Block) bool {
	switch b.Scope {
	case "gateway":
		return true
	case "node":
		return w.memberExists(b.Node)
	}
	if _, ok := w.tenants[b.Tenant]; !ok && !(b.Scope == "host" && b.Tenant == "") {
		return false
	}
	switch b.Scope {
	case "tenant":
		return true
	case "source":
		for _, app := range b.Apps {
			if _, ok := w.apps[b.Tenant+"/"+app]; !ok {
				return false
			}
		}
		return true
	}
	for _, row := range w.realMappings() {
		if b.Tenant != "" && row.Tenant != b.Tenant || b.Node != "" && b.Node != row.Node || b.App != "" && b.App != row.App || b.Key != "" && b.Key != row.Key {
			continue
		}
		switch b.Scope {
		case "instance":
			return true
		case "host", "route":
			for _, r := range row.Spec.Routes {
				if b.Scope == "host" && r.Host == b.Host || b.Scope == "route" && r.ID == b.Route && r.Host == b.Host && r.Prefix == b.Prefix {
					return true
				}
			}
		case "backend":
			for _, svc := range row.Spec.Services {
				if svc.ID == b.Service && slices.ContainsFunc(svc.Backends, func(k ingress.BackendSpec) bool { return k.ID == b.Backend }) {
					return true
				}
			}
		}
	}
	return false
}

func (c *fakeConn) applyRealIngress(op UserOperation, actor string) error {
	w := c.f.w
	ch := op.Change
	book := &w.ireal
	if book.revision == math.MaxUint64 {
		return errors.New("revision")
	}
	if len(book.history) >= 4096 {
		return errCAS
	}
	before := slices.Clone(book.blocks)
	var beforePolicy ingress.HostPolicy
	switch ch.Action {
	case ActionSetIngressHostPolicy:
		var q control.IngressHostPolicyChange
		if decodePayload(ch.Payload, &q) != nil || q.Tenant == "" || !validHostPolicy(q.Policy) {
			return errors.New("payload")
		}
		if !w.admin(actor) {
			return errForbidden
		}
		if _, ok := w.tenants[q.Tenant]; !ok {
			return errCAS
		}
		for _, r := range book.policies {
			if r.Tenant == q.Tenant {
				beforePolicy = r.Policy
			}
		}
		i := slices.IndexFunc(book.policies, func(r control.IngressHostPolicyRecord) bool { return r.Tenant == q.Tenant })
		if i < 0 {
			if ch.Expected != 0 {
				return errCAS
			}
			book.policies = append(book.policies, control.IngressHostPolicyRecord{Tenant: q.Tenant, Policy: q.Policy, Revision: 1, Origin: op})
		} else {
			r := &book.policies[i]
			if r.Revision != ch.Expected {
				return errCAS
			}
			r.Policy, r.Origin = q.Policy, op
			r.Revision++
		}
	case ActionIngressBlock:
		var q control.IngressBlockChange
		if decodePayload(ch.Payload, &q) != nil {
			return errors.New("payload")
		}
		b := q.Block
		if b.Actor != "" && b.Actor != op.Session.User || b.CreatedAt != 0 && b.CreatedAt != uint64(op.At) {
			return errors.New("payload")
		}
		b.Actor, b.CreatedAt = op.Session.User, uint64(op.At)
		if !b.Valid() {
			return errors.New("block")
		}
		if err := w.realBlockAuthorized(actor, b); err != nil {
			return err
		}
		if ch.Expected != 0 || len(book.blocks) >= 4096 || slices.ContainsFunc(book.blocks, func(r control.IngressBlockRecord) bool { return r.Block.ID == b.ID }) || !w.realBlockTarget(b) {
			return errCAS
		}
		book.blocks = append(book.blocks, control.IngressBlockRecord{Block: b, Revision: 1, Origin: op, Last: op})
		w.addEvent(realBlockEvent(EventIngressBlocked, b, op.At, b.Reason))
	case ActionIngressUnblock, ActionIngressBlockExtend:
		var q control.IngressBlockSelection
		if decodePayload(ch.Payload, &q) != nil {
			return errors.New("payload")
		}
		i := slices.IndexFunc(book.blocks, func(r control.IngressBlockRecord) bool { return r.Block.ID == q.ID })
		if i < 0 {
			return errors.New("unknown block")
		}
		r := &book.blocks[i]
		if err := w.realBlockAuthorized(actor, r.Block); err != nil {
			return err
		}
		if r.Removed || r.Revision != ch.Expected || r.Revision == math.MaxUint64 {
			return errCAS
		}
		if ch.Action == ActionIngressUnblock {
			if q.ExpiresAt != 0 {
				return errors.New("payload")
			}
			r.Removed = true
			w.addEvent(realBlockEvent(EventIngressUnblocked, r.Block, op.At, "by "+actor))
		} else {
			if r.Block.ExpiresAt == 0 || q.ExpiresAt > math.MaxInt64 || q.ExpiresAt <= uint64(op.At) || q.ExpiresAt <= r.Block.ExpiresAt {
				return errCAS
			}
			r.Block.ExpiresAt = q.ExpiresAt
		}
		r.Revision++
		r.Last = op
	default:
		return errors.New("action")
	}
	book.revision++
	w.realIngressHistory(op, before, beforePolicy)
	return nil
}

// realBlockEvent: ingress-blocked / -unblocked with the block's target
// (Node, Gateway, Tenant, App, RouteID, Host, Prefix). A node or global
// block has no Tenant (system administrator only).
func realBlockEvent(kind string, b ingress.Block, at int64, detail string) FixtureEvent {
	e := FixtureEvent{Time: at, Scope: "cluster", Tenant: b.Tenant, App: b.App, Node: b.Node, Kind: kind, Target: b.Scope + ":" + b.ID, Detail: detail,
		Ingress: &IngressEvent{Gateway: b.Gateway, RouteID: b.Route, Host: b.Host, Prefix: b.Prefix}}
	switch {
	case b.App != "":
		e.Scope = "app"
	case b.Tenant != "":
		e.Scope = "tenant"
	case b.Node != "":
		e.Scope = "node"
	}
	return e
}
