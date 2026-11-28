// SPDX-License-Identifier: Apache-2.0

package ingress

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
	"golang.org/x/net/idna"
)

type completedRequest struct {
	service string
	pin     BackendLease
}
type instance struct {
	controlDraining      atomic.Bool
	controlBalances      map[string]Balance
	controlBackendDrains map[string]ControlDrain
	controlDrain         ControlDrain
	controlTimers        []*time.Timer
	direct               map[string]*ownedHTTPListener
	mu                   sync.Mutex
	manager              *Manager
	key                  string
	record               instanceRecord
	table                Table
	ctx                  context.Context
	cancel               context.CancelFunc
	started, closing     bool
	failed               error
	addresses            map[string]string
	returns              map[string]completedRequest
	servers              []*http.Server
	quicServers          []*http3.Server
	listeners            []io.Closer
	workers, handlers    sync.WaitGroup
	connections          atomic.Int64
	transport            *http.Transport
	buffer               *copyPool
	proxyFailures        uint64
	lastProxyFailure     string
	lastProxyFailureMS   int64
	healthFailures       uint64
	lastHealthFailure    string
	lastHealthFailureMS  int64
	flows                map[uint64]activeFlow
	flowSequence         uint64
	availability         map[string]bool
	certificateFailures  map[string]string
}

func newInstance(m *Manager, key string, r instanceRecord) *instance {
	i := &instance{manager: m, key: key, record: r, addresses: map[string]string{}, returns: map[string]completedRequest{}, direct: map[string]*ownedHTTPListener{}}
	i.applyRuntimeControlsLocked()
	return i
}
func (i *instance) copyRecord() instanceRecord {
	b, _ := json.Marshal(i.record)
	var r instanceRecord
	_ = json.Unmarshal(b, &r)
	return r
}
func (i *instance) save(r instanceRecord) error {
	b, err := json.Marshal(r)
	if err == nil {
		err = i.manager.db.Write(map[string][]byte{"instance/" + i.key: b})
	}
	if err == nil {
		i.record = r
	}
	return err
}
func (i *instance) requests() int {
	n := 0
	for _, j := range i.record.Balances {
		for _, b := range j.Backends {
			n += len(b.Pins.Active)
		}
	}
	return n
}
func (i *instance) retryReturns() error {
	if len(i.returns) == 0 {
		return nil
	}
	r := i.copyRecord()
	for _, v := range i.returns {
		b, err := RestoreBalancer(r.Balances[v.service])
		if err != nil {
			return err
		}
		if err = b.Release(v.pin); err != nil {
			return err
		}
		r.Balances[v.service] = b.Checkpoint()
	}
	if err := i.save(r); err != nil {
		return err
	}
	clear(i.returns)
	return nil
}

type copyPool struct{ buffers sync.Pool }

func (p *copyPool) Get() []byte {
	if v := p.buffers.Get(); v != nil {
		return v.([]byte)
	}
	return make([]byte, 32<<10)
}
func (p *copyPool) Put(b []byte) {
	if cap(b) == 32<<10 {
		p.buffers.Put(b[:32<<10])
	}
}

type limitedListener struct {
	net.Listener
	owner *instance
	limit int64
	owned *ownedHTTPListener
}

func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.owned != nil {
			if g := l.owned.gateway.Load(); g != nil {
				if !g.sourceAllowed(c.RemoteAddr()) {
					g.rejectSource()
					c.Close()
					continue
				}
				if g.connections.Add(1) > 4096 {
					g.connections.Add(-1)
					c.Close()
					continue
				}
				return &gatewayConn{Conn: c, gateway: g}, nil
			}
		}
		if l.owner.controlDraining.Load() {
			_ = c.Close()
			continue
		}
		if l.owner.connections.Add(1) > l.limit {
			l.owner.connections.Add(-1)
			_ = c.Close()
			continue
		}
		return &gatewayConn{Conn: c, owners: map[*instance]bool{l.owner: true}}, nil
	}
}
func (i *instance) start() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.started {
		for _, l := range i.record.Spec.Listeners {
			if l.Shared != "" {
				if err := i.manager.attachShared(i, i.record.Spec, l); err != nil {
					return err
				}
			}
		}
		i.table, _ = routeTable(i.record.Spec.Routes, "local")
		return i.failed
	}
	if i.manager.ctx.Err() != nil || i.record.Gone || i.record.Spec.Lifecycle.Drain {
		return ErrRoute
	}
	s := i.record.Spec
	i.table, _ = routeTable(s.Routes, "local")
	i.ctx, i.cancel = context.WithCancel(i.manager.ctx)
	i.closing = false
	i.failed = nil
	i.transport = &http.Transport{Proxy: nil, DialContext: i.dialBackend(s), DisableKeepAlives: true, DisableCompression: true, ResponseHeaderTimeout: time.Duration(s.ResponseHeaderTimeoutMS) * time.Millisecond, MaxResponseHeaderBytes: int64(s.MaxHeaderBytes), ForceAttemptHTTP2: false}
	i.buffer = &copyPool{}
	fail := func(err error) error {
		i.cancel()
		for _, l := range i.listeners {
			_ = l.Close()
		}
		i.listeners = nil
		i.servers = nil
		i.quicServers = nil
		clear(i.addresses)
		i.failed = err
		i.manager.detachShared(i.key)
		return err
	}
	var direct []Listener
	for _, v := range s.Listeners {
		if v.Shared != "" {
			if err := i.manager.attachShared(i, s, v); err != nil {
				return fail(err)
			}
			continue
		}
		direct = append(direct, v)
		gatewayKind := i.manager.listenerGateway(v.Address)
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), gatewayRequestKey{}, gatewayRequest{Gateway: gatewayKind})
			i.ServeHTTP(w, r.WithContext(ctx))
		})
		owned := &ownedHTTPListener{definition: v, owner: i, kind: gatewayKind, handler: handler}
		i.direct[v.ID] = owned
		var tlsConfig *tls.Config
		if v.TLS {
			tlsConfig = i.manager.dynamicCertificateConfig(owned.admitHost)
		}
		a, _ := netip.ParseAddrPort(v.Address)
		family := "4"
		if a.Addr().Is6() {
			family = "6"
		}
		ln, err := net.Listen("tcp"+family, v.Address)
		if err != nil {
			return fail(err)
		}
		i.listeners = append(i.listeners, ln)
		owned.listener = ln
		srv := &http.Server{Handler: owned, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 64 << 10, TLSConfig: tlsConfig, ErrorLog: log.New(io.Discard, "", 0), BaseContext: func(net.Listener) context.Context { return i.manager.ctx }, ConnContext: ownedConnContext}
		owned.server = srv
		if tlsConfig != nil {
			if err = http2.ConfigureServer(srv, &http2.Server{MaxConcurrentStreams: 1024}); err != nil {
				return fail(err)
			}
		}
		i.servers = append(i.servers, srv)
		i.addresses[v.ID] = ln.Addr().String()
		if v.HTTP3 {
			pc, err := net.ListenPacket("udp"+family, v.Address)
			if err != nil {
				return fail(err)
			}
			i.listeners = append(i.listeners, pc)
			owned.packet = pc
			qs := &http3.Server{TLSConfig: tlsConfig.Clone(), Handler: owned, MaxHeaderBytes: 64 << 10, IdleTimeout: 30 * time.Second, QUICConfig: &quic.Config{MaxIncomingStreams: 1024, MaxIncomingUniStreams: 16, MaxIdleTimeout: 30 * time.Second, InitialStreamReceiveWindow: 64 << 10, MaxStreamReceiveWindow: 128 << 10, InitialConnectionReceiveWindow: 128 << 10, MaxConnectionReceiveWindow: 1 << 20}, ConnContext: func(ctx context.Context, c *quic.Conn) context.Context {
				return owned.quicContext(ctx, c, i, s.MaxConnections)
			}}
			i.quicServers = append(i.quicServers, qs)
			// Keep the owned UDP connection with this server, not a port lookup.
			_ = pc
		}
	}
	if len(i.addresses) == 0 {
		return fail(ErrRoute)
	}
	// Start only after every configured TCP/UDP endpoint has bound. A partial
	// bind never publishes Ready and all process-owned sockets are closed.
	tcp, udp := 0, 0
	for _, v := range direct {
		srv := i.servers[tcp]
		ln := i.listeners[tcp+udp].(net.Listener)
		tcp++
		owned := i.direct[v.ID]
		owned.workers.Add(1)
		go func() {
			defer owned.workers.Done()
			var err error
			limited := &limitedListener{Listener: ln, owner: i, limit: int64(s.MaxConnections), owned: owned}
			if srv.TLSConfig != nil {
				err = srv.ServeTLS(limited, "", "")
			} else {
				err = srv.Serve(limited)
			}
			owned.serveError(i, err)
		}()
		if v.HTTP3 {
			qs := i.quicServers[udp]
			pc := i.listeners[tcp+udp].(net.PacketConn)
			udp++
			owned.workers.Add(1)
			go func() {
				defer owned.workers.Done()
				owned.serveError(i, qs.Serve(&handoffPacketConn{PacketConn: pc, owned: owned}))
			}()
		}
	}
	i.started = true
	i.workers.Add(1)
	go func() { defer i.workers.Done(); i.health() }()
	return nil
}
func (i *instance) serveError(err error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if err != nil && !i.closing && !errors.Is(err, http.ErrServerClosed) {
		i.failed = err
	}
}
func (i *instance) stop() error {
	i.mu.Lock()
	for _, timer := range i.controlTimers {
		timer.Stop()
	}
	i.controlTimers = nil
	if i.cancel == nil {
		i.mu.Unlock()
		return nil
	}
	i.closing = true
	i.started = false
	i.cancel()
	servers := append([]*http.Server(nil), i.servers...)
	quicServers := append([]*http3.Server(nil), i.quicServers...)
	listeners := append([]io.Closer(nil), i.listeners...)
	ownedListeners := []*ownedHTTPListener{}
	for _, owned := range i.direct {
		ownedListeners = append(ownedListeners, owned)
	}
	i.mu.Unlock()
	i.manager.detachShared(i.key)
	for _, s := range servers {
		_ = s.Close()
	}
	for _, s := range quicServers {
		_ = s.Close()
	}
	for _, l := range listeners {
		_ = l.Close()
	}
	for _, owned := range ownedListeners {
		owned.workers.Wait()
	}
	i.workers.Wait()
	i.handlers.Wait()
	i.mu.Lock()
	defer i.mu.Unlock()
	i.listeners = nil
	i.servers = nil
	i.quicServers = nil
	i.cancel = nil
	clear(i.addresses)
	return i.retryReturns()
}

func backendURL(b BackendSpec) *url.URL {
	return &url.URL{Scheme: "http", Host: net.JoinHostPort(b.Address.String(), strconv.Itoa(int(b.Port)))}
}
func (i *instance) health() {
	for {
		if i.ctx.Err() != nil {
			return
		}
		i.manager.expireCertificateCache()
		i.mu.Lock()
		s := i.record.Spec
		i.mu.Unlock()
		for _, route := range s.Routes {
			if i.manager.routeServesTLS(s, route) {
				_, err := i.manager.certificateVersions(i.ctx, route.Host)
				i.certificateEvent(s, route, err)
			}
		}
		for _, svc := range s.Services {
			for _, b := range svc.Backends {
				if i.ctx.Err() != nil {
					return
				}
				ctx, cancel := context.WithTimeout(i.ctx, time.Duration(s.DialTimeoutMS+s.ResponseHeaderTimeoutMS)*time.Millisecond)
				u := backendURL(b)
				u.Path = b.HealthPath
				req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
				started := time.Now()
				res, err := i.transport.RoundTrip(req)
				ok := err == nil && res.StatusCode >= 200 && res.StatusCode < 400
				reason := ""
				if !ok {
					if err != nil {
						reason = proxyFailureKind(ctx, err)
					} else {
						reason = "http-" + strconv.Itoa(res.StatusCode)
					}
				}
				if res != nil {
					_ = res.Body.Close()
				}
				unknown := i.ctx.Err() == nil && (reason == "upstream-timeout" || reason == "upstream-dial-timeout" || reason == "request-deadline")
				cancel()
				i.mu.Lock()
				if !ok {
					if i.healthFailures != ^uint64(0) {
						i.healthFailures++
					}
					i.lastHealthFailure, i.lastHealthFailureMS = reason, time.Since(started).Milliseconds()
				}
				r := i.copyRecord()
				current, exists := backendByID(r.Spec, b.ID, b.Generation)
				if !exists || !sameBackend(current, b) {
					i.mu.Unlock()
					continue // an old in-flight probe cannot update its replacement
				}
				if current.Suspended {
					ok, unknown = false, false
				}
				bal, e := RestoreBalancer(r.Balances[svc.ID])
				if e == nil {
					e = bal.ObserveHealth(Backend{ID: b.ID, Generation: b.Generation, Weight: b.Weight, Capacity: b.Capacity, Healthy: ok, Draining: backendDraining(r, current), ObservedAt: uint64(time.Now().UnixMilli())}, !unknown)
				}
				if e == nil {
					r.Balances[svc.ID] = bal.Checkpoint()
					e = i.save(r)
				}
				if e != nil {
					i.failed = e
				}
				i.mu.Unlock()
			}
		}
		i.availabilityEvents()
		// A slow check must not consume a tick accumulated during its own
		// I/O and immediately start another round. The configured interval
		// begins after the completed round, including failures and timeouts.
		pause := time.NewTimer(time.Duration(s.HealthIntervalMS) * time.Millisecond)
		select {
		case <-i.ctx.Done():
			pause.Stop()
			return
		case <-pause.C:
		}
	}
}

func requestHost(r *http.Request) (string, error) {
	h := r.Host
	if strings.Contains(h, ":") {
		var err error
		h, _, err = net.SplitHostPort(h)
		if err != nil {
			return "", ErrRoute
		}
	}
	h, err := idna.Lookup.ToASCII(h)
	if err != nil {
		return "", err
	}
	h, ok := host(h)
	if !ok {
		return "", ErrRoute
	}
	return h, nil
}
func (i *instance) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	event := RequestEvent{At: uint64(started.UnixMilli()), Method: r.Method, Host: r.Host, Path: r.URL.Path}
	if addr, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		event.Source, _ = netip.ParseAddr(addr)
	}
	observed := &metricResponse{ResponseWriter: w}
	w = observed
	body := &metricBody{ReadCloser: r.Body}
	r.Body = body
	defer func() {
		event.Status = observed.status
		if event.Status == 0 && event.Failure == "" {
			event.Status = 200
		}
		event.DurationMS = uint64(time.Since(started).Milliseconds())
		event.SentBytes = observed.sent
		event.ReceivedBytes = body.read
		if i.manager.management != nil {
			i.manager.management.Record(i.key, event)
		}
	}()
	h, err := requestHost(r)
	escaped := strings.ToLower(r.URL.EscapedPath())
	if err != nil || r.URL.IsAbs() || strings.Contains(escaped, "%2f") || strings.Contains(escaped, "%5c") {
		http.Error(w, "invalid authority or path", http.StatusBadRequest)
		return
	}
	i.mu.Lock()
	s := i.controlledRoutes(i.record.Spec)
	if !i.started || i.closing || i.failed != nil || s.Lifecycle.Drain || i.controlDraining.Load() || i.requests() >= s.MaxRequests {
		i.mu.Unlock()
		http.Error(w, "ingress unavailable", http.StatusServiceUnavailable)
		return
	}
	table := i.table
	if len(i.controlBalances) != 0 {
		table, _ = routeTable(s.Routes, "local")
	}
	gateway := "local"
	if shared, ok := r.Context().Value(gatewayRequestKey{}).(gatewayRequest); ok {
		gateway = shared.Gateway
		kind := gateway
		if kind == "unclassified" {
			kind = "local"
		}
		table, _ = routeTable(s.Routes, kind)
	}
	event.Gateway = gateway
	if acme, ok := i.manager.acmeChallenge(r, h); ok {
		if _, err := table.Host(h); err == nil {
			// No app route is chosen, so only route-free blocks apply
			// (node, gateway, tenant, instance, host, source).
			event.Route = "acme-challenge"
			target := RequestTarget{Tenant: s.Tenant, App: s.App, Key: i.key, Route: Route{Host: h}, Source: event.Source, Node: i.manager.node, Gateway: gateway}
			if i.blocked(w, r, target, &event) {
				return
			}
			if headerBytes(r) > s.MaxHeaderBytes {
				i.mu.Unlock()
				http.Error(w, "request headers too large", http.StatusRequestHeaderFieldsTooLarge)
				return
			}
			i.mu.Unlock()
			acme.serve(w, r)
			return
		}
	}
	if enroll, ok := i.manager.nodeEnroll(r); ok {
		if _, err := table.Host(h); err == nil {
			event.Route = "node-enroll"
			target := RequestTarget{Tenant: s.Tenant, App: s.App, Key: i.key, Route: Route{Host: h}, Source: event.Source, Node: i.manager.node, Gateway: gateway}
			if i.blocked(w, r, target, &event) {
				return
			}
			if headerBytes(r) > s.MaxHeaderBytes {
				i.mu.Unlock()
				http.Error(w, "request headers too large", http.StatusRequestHeaderFieldsTooLarge)
				return
			}
			i.mu.Unlock()
			r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
			enroll(w, r, event.Source)
			return
		}
	}
	route, err := table.Match(h, r.URL.Path)
	if err != nil {
		i.mu.Unlock()
		http.Error(w, "route not found", http.StatusNotFound)
		return
	}
	if shared, ok := r.Context().Value(gatewayRequestKey{}).(gatewayRequest); ok && shared.Route != "" && shared.Route != route.ID {
		i.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	event.Route = route.ID
	target := RequestTarget{Tenant: s.Tenant, App: s.App, Key: i.key, Route: route, Service: route.Service, Source: event.Source, Node: i.manager.node, Gateway: gateway}
	if i.blocked(w, r, target, &event) {
		return
	}
	if headerBytes(r) > s.MaxHeaderBytes {
		i.mu.Unlock()
		http.Error(w, "request headers too large", http.StatusRequestHeaderFieldsTooLarge)
		return
	}
	if r.ContentLength > s.MaxBodyBytes {
		i.mu.Unlock()
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	candidate := i.copyRecord()
	bal, err := RestoreBalancer(candidate.Balances[route.Service])
	policy := Balance{}
	selection := requestSelection(r, s)
	selection.Node = i.manager.node
	selection.Exclude = map[string]bool{}
	for id, b := range selection.Backends {
		if i.backendControl(b.Node).Draining {
			selection.Exclude[id] = true
		}
	}
	i.manager.holdSelection(&selection)
	if i.manager.management != nil {
		for id := range selection.Backends {
			candidate := target
			candidate.Backend = id
			if _, blocked := i.manager.management.Match(candidate, uint64(time.Now().Unix())); blocked {
				selection.Exclude[id] = true
			}
		}
	}
	for _, service := range s.Services {
		if service.ID == route.Service && service.Balance != nil {
			policy = *service.Balance
		}
	}
	if route.Balance != nil {
		policy = *route.Balance
	}
	selection.Group, selection.Condition = policy.Select(selection)
	event.Gateway, event.Condition = gateway, selection.Condition
	var pin BackendLease
	if err == nil {
		pin, err = bal.AcquireWith(uint64(time.Now().UnixMilli()), policy, selection)
	}
	if err == nil {
		candidate.Balances[route.Service] = bal.Checkpoint()
		err = i.save(candidate)
	}
	if err != nil {
		event.Failure = "backends-empty"
		i.mu.Unlock()
		http.Error(w, "backend unavailable", http.StatusServiceUnavailable)
		return
	}
	event.Backend = pin.Backend
	var selected BackendSpec
	for _, svc := range s.Services {
		if svc.ID == route.Service {
			for _, b := range svc.Backends {
				if b.ID == pin.Backend && b.Generation == pin.Lease.Generation {
					selected = b
				}
			}
		}
	}
	i.handlers.Add(1)
	parent := i.ctx
	transport := i.transport
	buffers := i.buffer
	i.mu.Unlock()
	defer i.handlers.Done()
	defer func() {
		i.mu.Lock()
		defer i.mu.Unlock()
		if pin.Backend == "" {
			return
		}
		id := fmt.Sprintf("%s/%s/%d", route.Service, pin.Backend, pin.Lease.Token)
		i.returns[id] = completedRequest{route.Service, pin}
		if e := i.retryReturns(); e != nil {
			i.failed = e
		}
	}()
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(s.RequestTimeoutMS)*time.Millisecond)
	defer cancel()
	i.mu.Lock()
	if i.flows == nil {
		i.flows = map[uint64]activeFlow{}
	}
	i.flowSequence++
	flowID := i.flowSequence
	target.Backend = pin.Backend
	i.flows[flowID] = activeFlow{target: target, cancel: func() { cancel(); _ = http.NewResponseController(w).SetWriteDeadline(time.Now()) }}
	if i.controlDrain.Draining && uint64(time.Now().Unix()) >= i.controlDrain.Deadline || i.backendControlExpired(target.Backend, uint64(time.Now().Unix())) {
		i.flows[flowID].cancel()
	}
	i.mu.Unlock()
	defer func() { i.mu.Lock(); delete(i.flows, flowID); i.mu.Unlock() }()
	stop := context.AfterFunc(parent, cancel)
	defer stop()
	r = r.WithContext(context.WithValue(ctx, upstreamTargetKey{}, upstreamTarget{key: i.key, route: route.ID, backend: pin.Backend}))
	r.Body = http.MaxBytesReader(w, r.Body, s.MaxBodyBytes)
	var proxyTransport http.RoundTripper = transport
	if policy.Retry > 0 && (r.Method == http.MethodGet || r.Method == http.MethodHead) && r.ContentLength == 0 {
		excluded := selection.Exclude
		proxyTransport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
			for attempt := 0; ; attempt++ {
				response, err := transport.RoundTrip(request)
				var operation *net.OpError
				if err == nil || attempt >= policy.Retry || !errors.As(err, &operation) || operation.Op != "dial" || ctx.Err() != nil {
					return response, err
				}
				i.mu.Lock()
				id := fmt.Sprintf("%s/%s/%d", route.Service, pin.Backend, pin.Lease.Token)
				i.returns[id] = completedRequest{route.Service, pin}
				if releaseErr := i.retryReturns(); releaseErr != nil {
					i.failed = releaseErr
					i.mu.Unlock()
					return nil, releaseErr
				}
				excluded[pin.Backend] = true
				pin = BackendLease{}
				candidate := i.copyRecord()
				next, e := RestoreBalancer(candidate.Balances[route.Service])
				selection.Exclude = excluded
				if e == nil {
					pin, e = next.AcquireWith(uint64(time.Now().UnixMilli()), policy, selection)
				}
				if e == nil {
					candidate.Balances[route.Service] = next.Checkpoint()
					e = i.save(candidate)
				}
				if e != nil {
					pin = BackendLease{}
					i.mu.Unlock()
					return nil, e
				}
				selected = selection.Backends[pin.Backend]
				event.Backend = pin.Backend
				if flow, ok := i.flows[flowID]; ok {
					flow.target.Backend = pin.Backend
					i.flows[flowID] = flow
				}
				i.mu.Unlock()
				copy := request.Clone(context.WithValue(request.Context(), upstreamTargetKey{}, upstreamTarget{key: i.key, route: route.ID, backend: pin.Backend}))
				url := *request.URL
				upstream := backendURL(selected)
				url.Scheme, url.Host = upstream.Scheme, upstream.Host
				copy.URL = &url
				request = copy
			}
		})
	}
	proxyStarted := time.Now()
	proxy := &httputil.ReverseProxy{Transport: proxyTransport, BufferPool: buffers, FlushInterval: -1, ErrorLog: log.New(io.Discard, "", 0), Rewrite: func(p *httputil.ProxyRequest) {
		p.SetURL(backendURL(selected))
		p.Out.URL.Path = p.In.URL.Path
		p.Out.URL.RawPath = ""
		p.Out.Host = r.Host
		p.SetXForwarded()
	}, ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
		i.mu.Lock()
		if i.proxyFailures != ^uint64(0) {
			i.proxyFailures++
		}
		i.lastProxyFailure = proxyFailureKind(ctx, err)
		event.Failure = i.lastProxyFailure
		i.lastProxyFailureMS = time.Since(proxyStarted).Milliseconds()
		i.mu.Unlock()
		code := http.StatusBadGateway
		var max *http.MaxBytesError
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			code = http.StatusGatewayTimeout
		} else if errors.As(err, &max) {
			code = http.StatusRequestEntityTooLarge
		}
		http.Error(w, http.StatusText(code), code)
	}}
	proxy.ServeHTTP(w, r)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func requestSelection(r *http.Request, s Spec) Selection {
	q := Selection{Method: r.Method, Headers: map[string]string{}, Cookies: map[string]string{}, Query: map[string]string{}, Backends: map[string]BackendSpec{}}
	if addr, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		q.Source, _ = netip.ParseAddr(addr)
	}
	for key, values := range r.Header {
		if len(values) > 0 {
			q.Headers[http.CanonicalHeaderKey(key)] = values[0]
		}
	}
	for _, cookie := range r.Cookies() {
		if _, exists := q.Cookies[cookie.Name]; !exists {
			q.Cookies[cookie.Name] = cookie.Value
		}
	}
	for key, values := range r.URL.Query() {
		if len(values) > 0 {
			q.Query[key] = values[0]
		}
	}
	for _, service := range s.Services {
		for _, backend := range service.Backends {
			// The newest generation of an ID is the one that can be selected.
			if prior, listed := q.Backends[backend.ID]; !listed || prior.Generation < backend.Generation {
				q.Backends[backend.ID] = backend
			}
		}
	}
	var entropy [8]byte
	if _, err := rand.Read(entropy[:]); err == nil {
		q.Entropy = binary.BigEndian.Uint64(entropy[:])
	}
	return q
}

// Bounded node-local diagnostics; never expose a transport error's URL, body,
// credentials or message. This does not mutate durable readiness or pins.
func proxyFailureKind(ctx context.Context, err error) string {
	var max *http.MaxBytesError
	var timeout net.Error
	var op *net.OpError
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return "request-deadline"
	case errors.Is(ctx.Err(), context.Canceled):
		return "request-canceled"
	case errors.As(err, &max):
		return "request-body-limit"
	case errors.As(err, &timeout) && timeout.Timeout():
		if errors.As(err, &op) && op.Op == "dial" {
			return "upstream-dial-timeout"
		}
		return "upstream-timeout"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "upstream-closed"
	case errors.As(err, &op) && op.Op == "dial":
		return "upstream-dial"
	default:
		return "upstream-transport"
	}
}

// blocked answers a request an emergency block matches; it unlocks i.mu
// when it does.
func (i *instance) blocked(w http.ResponseWriter, r *http.Request, target RequestTarget, event *RequestEvent) bool {
	if i.manager.management == nil {
		return false
	}
	block, blocked := i.manager.management.Match(target, uint64(time.Now().Unix()))
	if !blocked {
		return false
	}
	i.manager.management.CountBlock(block.ID)
	event.Block = block.ID
	i.mu.Unlock()
	if blockResponse(w, r, block) {
		event.Failure = "blocked-reset"
	}
	return true
}

func headerBytes(r *http.Request) int {
	n := len(r.Method) + len(r.RequestURI) + len(r.Proto) + len(r.Host)
	for name, values := range r.Header {
		for _, value := range values {
			n += len(name) + len(value) + 4
		}
	}
	return n
}
