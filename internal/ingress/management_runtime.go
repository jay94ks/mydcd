// SPDX-License-Identifier: Apache-2.0

package ingress

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

type activeFlow struct {
	target RequestTarget
	cancel context.CancelFunc
}
type metricResponse struct {
	http.ResponseWriter
	status int
	sent   uint64
}

func (w *metricResponse) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *metricResponse) WriteHeader(status int) {
	// Informational responses precede the final response and must still reach
	// the client. A 101 switches protocols and is itself the final response.
	if w.status == 0 && (status < 100 || status >= 200 || status == http.StatusSwitchingProtocols) {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w *metricResponse) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	n, e := w.ResponseWriter.Write(p)
	w.sent += uint64(n)
	return n, e
}
func (w *metricResponse) Flush() {
	if w.status == 0 {
		w.WriteHeader(200)
	}
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

type metricBody struct {
	io.ReadCloser
	read uint64
}

func (r *metricBody) Read(p []byte) (int, error) {
	if r.ReadCloser == nil {
		return 0, io.EOF
	}
	n, e := r.ReadCloser.Read(p)
	r.read += uint64(n)
	return n, e
}
func (r *metricBody) Close() error {
	if r.ReadCloser == nil {
		return nil
	}
	return r.ReadCloser.Close()
}

// A reset closes the stream without an HTTP response code. The caller records
// that fact separately from ordinary implicit or explicit HTTP responses.
func blockResponse(w http.ResponseWriter, r *http.Request, b Block) (reset bool) {
	if b.Response == "reset" {
		controller := http.NewResponseController(w)
		conn, _, e := controller.Hijack()
		if e == nil {
			_ = conn.Close()
			return true
		}
		if http.NewResponseController(w).SetWriteDeadline(time.Now()) == nil {
			return true
		}
	}
	status := 503
	if b.Response == "403" {
		status = 403
	}
	if status == http.StatusServiceUnavailable {
		retry := uint64(1)
		now := uint64(time.Now().Unix())
		if b.ExpiresAt > now {
			retry = b.ExpiresAt - now
		}
		w.Header().Set("Retry-After", strconv.FormatUint(retry, 10))
	}
	http.Error(w, http.StatusText(status), status)
	return false
}

func (m *Manager) SetBlocks(revision uint64, node string, blocks []Block, now uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.management == nil {
		m.management = NewManagement()
	}
	if err := m.management.UpdateBlocks(revision, node, blocks, now); err != nil {
		return err
	}
	if m.node == "" {
		m.node = node
	} else if m.node != node {
		return ErrRoute
	}
	for _, block := range blocks {
		applied := false
		code := "TARGET_MISSING"
		if block.Node != "" && block.Node != node {
			m.management.ReportApplication(block.ID, false, now, "NODE_NOT_TARGET")
			continue
		}
		if block.Scope == "node" {
			applied = true
		}
		if block.Scope == "gateway" {
			m.gatewayMu.Lock()
			for _, g := range m.gateways {
				applied = applied || block.Gateway == "both" || block.Gateway == g.kind
			}
			m.gatewayMu.Unlock()
		}
		for _, instance := range m.instances {
			instance.mu.Lock()
			s := instance.record.Spec
			gone := instance.record.Gone
			instance.mu.Unlock()
			if gone {
				continue
			}
			gateways := map[string]bool{}
			for _, listener := range s.Listeners {
				kind := m.listenerGateway(listener.Address)
				if listener.Shared != "" {
					m.gatewayMu.Lock()
					g := m.gateways[listener.Shared]
					if g != nil {
						kind = g.kind
					}
					m.gatewayMu.Unlock()
					if g == nil {
						continue
					}
				}
				if kind == "unclassified" {
					kind = "local"
				}
				gateways[kind] = true
			}
			for _, route := range s.Routes {
				for _, service := range s.Services {
					if service.ID != route.Service {
						continue
					}
					backends := service.Backends
					if len(backends) == 0 {
						backends = []BackendSpec{{}}
					}
					for _, backend := range backends {
						target := RequestTarget{Tenant: s.Tenant, App: s.App, Node: node, Key: instance.key, Route: route, Service: service.ID, Backend: backend.ID}
						if block.Scope == "source" {
							if prefix, err := netip.ParsePrefix(block.Source); err == nil {
								target.Source = prefix.Addr()
							}
						}
						// "both" is a route declaration, never a request gateway.
						// Use the same concrete listener kind as live request matching.
						for kind := range gateways {
							if gatewayIncludes(route.Gateway, kind) {
								target.Gateway = kind
								applied = applied || block.Matches(target, max(now, block.CreatedAt))
							}
						}
					}
				}
			}
		}
		if applied {
			code = ""
		}
		m.management.ReportApplication(block.ID, applied, now, code)
	}
	for _, i := range m.instances {
		i.mu.Lock()
		for _, flow := range i.flows {
			if b, ok := m.management.Match(flow.target, now); ok && b.CutExisting {
				flow.cancel()
			}
		}
		i.mu.Unlock()
	}
	return nil
}
func (m *Manager) Metrics(key string, nowMS uint64) Metrics {
	if m.management == nil {
		return Metrics{WindowSeconds: 60}
	}
	return m.management.Snapshot(key, nowMS)
}
func (m *Manager) BlockApplications() []BlockApplication {
	if m.management == nil {
		return nil
	}
	return m.management.Applications()
}
func (m *Manager) Snapshot(key string, nowMS uint64) (InstanceSnapshot, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	i := m.instances[key]
	if i == nil || m.closed {
		return InstanceSnapshot{}, false
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	r := i.record
	out := InstanceSnapshot{ControlRevision: m.controlRevision, Generation: r.Generation, Revision: r.Revision, ObservedAt: nowMS, Ready: i.started && !i.closing && i.failed == nil && !r.Spec.Lifecycle.Drain, Draining: r.Spec.Lifecycle.Drain, Connections: int(i.connections.Load()), Requests: i.requests()}
	out.Draining = out.Draining || i.controlDraining.Load()
	out.Ready = out.Ready && !out.Draining
	out.DrainRevision, out.DrainStartedAt, out.DrainDeadline = i.controlDrain.Revision, i.controlDrain.StartedAt, i.controlDrain.Deadline
	out.Certificates = m.certificateObservations(r.Spec)
	if i.failed != nil {
		out.Error = "ingress-failed"
	}
	if failure := m.sharedFailure(key, r.Spec); failure != "" {
		out.Error = failure
		out.Ready = false
	}
	for _, l := range r.Spec.Listeners {
		row := ListenerSnapshot{ID: l.ID, Address: i.addresses[l.ID], TLS: l.TLS, HTTP3: l.HTTP3, State: "down", Gateway: m.listenerGateway(l.Address)}
		if l.Shared != "" {
			m.gatewayMu.Lock()
			g := m.gateways[l.Shared]
			if g != nil {
				row.Gateway, row.TLS, row.HTTP3 = g.kind, g.definition.TLS, g.definition.HTTP3
			}
			m.gatewayMu.Unlock()
		}
		if i.started && !i.closing && row.Address != "" {
			row.State = "up"
		}
		out.Listeners = append(out.Listeners, row)
	}
	for _, service := range r.Spec.Services {
		j := r.Balances[service.ID]
		for _, b := range service.Backends {
			row := BackendSnapshot{ID: b.ID, Task: b.Task, Node: b.Node, Network: b.Network, Address: b.Address.String(), Port: b.Port, Weight: b.Weight, Generation: b.Generation, Draining: b.Draining}
			for _, v := range j.Backends {
				if v.Spec.ID == b.ID {
					row.Healthy = v.Spec.Healthy && !v.Spec.Draining && v.Spec.ObservedAt <= nowMS && nowMS-v.Spec.ObservedAt <= j.MaxAge
					row.ObservedAt = v.Spec.ObservedAt
				}
			}
			out.Backends = append(out.Backends, row)
		}
	}
	if m.management != nil {
		out.Metrics = m.management.Snapshot(key, nowMS)
		out.BlockRevision, out.Blocks = m.management.BlockSnapshot()
	}
	return out, true
}

// Event contains only public identities and codes, never request headers,
// bodies, query strings or a transport error's arbitrary text.
type Event struct {
	Kind, Node, Gateway, Tenant, App, RouteID, Host, Prefix string
	Value                                                   uint64
	ObservedAt                                              uint64
}

func (m *Manager) SetEventSink(sink func(Event)) {
	m.eventMu.Lock()
	m.eventSink = sink
	m.eventMu.Unlock()
}
func (m *Manager) emit(event Event) {
	m.eventMu.Lock()
	sink := m.eventSink
	m.eventMu.Unlock()
	if sink != nil {
		event.Node = m.node
		event.ObservedAt = uint64(time.Now().UnixMilli())
		sink(event)
	}
}

type upstreamTargetKey struct{}
type upstreamTarget struct{ key, route, backend string }
type observedBackendConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *observedBackendConn) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }
func (i *instance) dialBackend(s Spec) func(context.Context, string, string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: time.Duration(s.DialTimeoutMS) * time.Millisecond, KeepAlive: -1}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := dialer.DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		target, ok := ctx.Value(upstreamTargetKey{}).(upstreamTarget)
		if !ok || i.manager.management == nil {
			return conn, nil
		}
		release := i.manager.management.ConnectionOpened(target.key, target.route, target.backend)
		return &observedBackendConn{Conn: conn, release: release}, nil
	}
}
