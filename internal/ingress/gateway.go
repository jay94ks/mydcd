// SPDX-License-Identifier: Apache-2.0

package ingress

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

type GatewayConfiguration struct {
	External Gateway `yaml:"external"`
	Local    Gateway `yaml:"local"`
}
type Gateway struct {
	Enabled        bool           `yaml:"enabled"`
	Addresses      []netip.Addr   `yaml:"addresses"`
	Ports          []uint16       `yaml:"ports"`
	AllowedSources []netip.Prefix `yaml:"allowed_sources,omitempty"`
	Listeners      []Listener     `yaml:"listeners"`
}
type HostPolicy struct {
	ExternalAllowed           bool
	ExternalHosts, LocalHosts []string
}
type gatewayBinding struct {
	instance *instance
	spec     Spec
	table    Table
}
type gatewayOwnedRoute struct {
	binding gatewayBinding
	route   Route
}
type gatewaySnapshot struct {
	table  Table
	owners map[string]gatewayOwnedRoute
	// shared holds every owner of a host+prefix that apps of one tenant
	// route together (`app deploy --force`), keyed by the table route that
	// stands for them; requests rotate across them.
	shared map[string][]gatewayOwnedRoute
	next   atomic.Uint64
}
type sharedGateway struct {
	inherited            *ownedHTTPListener
	snapshot             atomic.Pointer[gatewaySnapshot]
	mu                   sync.RWMutex
	manager              *Manager
	kind                 string
	definition           Listener
	allowed              []netip.Prefix
	bindings             map[string]gatewayBinding
	listener             net.Listener
	packet               net.PacketConn
	server               *http.Server
	quic                 *http3.Server
	workers              sync.WaitGroup
	failure              string
	sourceRejected       atomic.Uint64
	unmatched            atomic.Uint64
	connections          atomic.Int64
	rejectionSecond      int64
	rejectionsThisSecond uint64
}

func (c GatewayConfiguration) Validate() error {
	addresses := map[netip.Addr]bool{}
	listeners := map[string]bool{}
	ports := map[string]bool{}
	for _, g := range []Gateway{c.External, c.Local} {
		if len(g.Addresses) > 64 || len(g.Ports) > 64 || len(g.Listeners) > 64 || len(g.AllowedSources) > 256 {
			return ErrRoute
		}
		local := map[netip.Addr]bool{}
		for _, a := range g.Addresses {
			if !a.IsValid() || a.IsUnspecified() || a.IsMulticast() || a.Is4In6() || a.Zone() != "" || addresses[a] {
				return ErrRoute
			}
			addresses[a] = true
			local[a] = true
		}
		allowedPorts := map[uint16]bool{}
		for _, p := range g.Ports {
			if p == 0 || allowedPorts[p] {
				return ErrRoute
			}
			allowedPorts[p] = true
		}
		for _, p := range g.AllowedSources {
			if !p.IsValid() || p != p.Masked() || p.Addr().Is4In6() {
				return ErrRoute
			}
		}
		for _, l := range g.Listeners {
			a, e := netip.ParseAddrPort(l.Address)
			if e != nil || !local[a.Addr()] || !allowedPorts[a.Port()] || l.ID == "" || listeners[l.ID] || l.Shared != "" || l.HTTP3 && !l.TLS || ports[l.Address] {
				return ErrRoute
			}
			listeners[l.ID] = true
			ports[l.Address] = true
		}
		if g.Enabled && (len(g.Addresses) == 0 || len(g.Ports) == 0 || len(g.Listeners) == 0) {
			return ErrRoute
		}
	}
	return nil
}

// ConfigureGateways is installation configuration, not an app-created socket.
// A caller must configure before reconciling apps. Runtime rule changes use the
// same sockets through attachShared and do not restart another tenant's server.
func (m *Manager) ConfigureGateways(c GatewayConfiguration, clusterAddresses []netip.Addr) error {
	if c.Validate() != nil {
		return ErrRoute
	}
	m.gatewayMu.Lock()
	defer m.gatewayMu.Unlock()
	if len(m.gateways) != 0 {
		return ErrRoute
	}
	if m.gateways == nil {
		m.gateways = map[string]*sharedGateway{}
	}
	m.gatewayConfiguration = c
	m.gatewayClusterAddresses = append([]netip.Addr(nil), clusterAddresses...)
	m.gatewayClasses = map[netip.Addr]string{}
	for _, address := range c.External.Addresses {
		m.gatewayClasses[address] = "external"
	}
	for _, address := range c.Local.Addresses {
		m.gatewayClasses[address] = "local"
	}
	for _, pair := range []struct {
		kind    string
		gateway Gateway
	}{{"external", c.External}, {"local", c.Local}} {
		g := pair.gateway
		if !g.Enabled {
			continue
		}
		sources := append([]netip.Prefix(nil), g.AllowedSources...)
		if pair.kind == "local" && len(sources) == 0 {
			for _, p := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"} {
				sources = append(sources, netip.MustParsePrefix(p))
			}
			for _, a := range clusterAddresses {
				if a.IsValid() {
					sources = append(sources, netip.PrefixFrom(a, a.BitLen()))
				}
			}
		}
		for _, l := range g.Listeners {
			m.gateways[l.ID] = &sharedGateway{manager: m, kind: pair.kind, definition: l, allowed: sources, bindings: map[string]gatewayBinding{}}
		}
	}
	return nil
}
func (m *Manager) SetTenantPolicy(tenant string, policy HostPolicy) error {
	if tenant == "" || len(policy.ExternalHosts) > maxPolicyHosts || len(policy.LocalHosts) > maxPolicyHosts {
		return ErrRoute
	}
	for _, pattern := range append(append([]string(nil), policy.ExternalHosts...), policy.LocalHosts...) {
		if pattern != "*" {
			v := strings.TrimPrefix(pattern, "*.")
			if _, ok := host(v); !ok {
				return ErrRoute
			}
		}
	}
	m.gatewayMu.Lock()
	defer m.gatewayMu.Unlock()
	if m.hostPolicies == nil {
		m.hostPolicies = map[string]HostPolicy{}
	}
	m.hostPolicies[tenant] = policy
	for _, g := range m.gateways {
		g.mu.Lock()
		g.rebuildLocked()
		g.mu.Unlock()
	}
	return nil
}

// maxPolicyHosts bounds one tenant's host list: its domains (each as the
// name and "*.name") and its approved hosts.
const maxPolicyHosts = 2048

func hostAllowed(name string, allowed []string) bool {
	for _, pattern := range allowed {
		if pattern == "*" || name == pattern || strings.HasPrefix(pattern, "*.") && strings.HasSuffix(name, pattern[1:]) {
			return true
		}
	}
	return false
}
func gatewayIncludes(rule, kind string) bool {
	return rule == "both" || rule == kind || rule == "" && kind == "local"
}

// Called with the instance lock. A shared snapshot keeps original route IDs
// and delegates to that instance's durable backend lease path.
func (m *Manager) attachShared(i *instance, s Spec, l Listener) error {
	m.gatewayMu.Lock()
	defer m.gatewayMu.Unlock()
	g := m.gateways[l.Shared]
	if g == nil {
		return errors.New("shared ingress listener unavailable")
	}
	policy, ok := m.hostPolicies[s.Tenant]
	if !ok {
		return errors.New("ingress host assignment missing")
	}
	routes := []Route{}
	for _, r := range s.Routes {
		if !gatewayIncludes(r.Gateway, g.kind) {
			continue
		}
		// A route whose host the tenant may not serve here (a host waiting
		// for approval, a domain taken away) stays closed; the app's other
		// routes still open.
		if g.kind == "external" && !policy.ExternalAllowed {
			continue
		}
		allowed := policy.LocalHosts
		if g.kind == "external" {
			allowed = policy.ExternalHosts
		}
		// "*" is a system administrator's route (SystemWildcard), never
		// part of a tenant's host list.
		if r.Host == "*" && !s.SystemWildcard || r.Host != "*" && !hostAllowed(r.Host, allowed) {
			continue
		}
		routes = append(routes, r)
	}
	if len(routes) == 0 {
		return nil
	}
	table, e := NewTable(routes)
	if e != nil {
		return e
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for key, binding := range g.bindings {
		if key == i.key {
			continue
		}
		for _, existing := range binding.table.routes {
			for _, wanted := range table.routes {
				if existing.Host == wanted.Host && existing.Prefix == wanted.Prefix {
					return errors.New("INGRESS_ROUTE_CONFLICT")
				}
			}
		}
	}
	if g.listener == nil {
		if e = g.startLocked(); e != nil {
			g.failure = "listener-bind-failed"
			g.manager.emit(Event{Kind: "ingress-listener-down", Gateway: g.kind})
			return e
		}
		g.manager.emit(Event{Kind: "ingress-listener-up", Gateway: g.kind})
	}
	g.bindings[i.key] = gatewayBinding{instance: i, spec: s, table: table}
	g.rebuildLocked()
	i.addresses[l.ID] = g.definition.Address
	return nil
}
func (m *Manager) detachShared(key string) {
	m.gatewayMu.Lock()
	defer m.gatewayMu.Unlock()
	for _, g := range m.gateways {
		g.mu.Lock()
		delete(g.bindings, key)
		g.rebuildLocked()
		empty := len(g.bindings) == 0
		g.mu.Unlock()
		if empty {
			g.stop()
		}
	}
}

// Called only while manager.gatewayMu and g.mu protect a configuration change.
// Invalid/revoked entries are absent in the newly published immutable view.
func (g *sharedGateway) rebuildLocked() {
	routes := []Route{}
	owners := map[string]gatewayOwnedRoute{}
	shared := map[string][]gatewayOwnedRoute{}
	first := map[string]string{} // host+prefix -> table route ID
	keys := make([]string, 0, len(g.bindings))
	for key := range g.bindings {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		b := g.bindings[key]
		if b.instance != nil && b.instance.controlDraining.Load() {
			continue
		}
		for _, r := range b.table.routes {
			if !g.manager.bindingAllowed(b.spec, r.Route, g.kind) {
				continue
			}
			owned := gatewayOwnedRoute{b, r.Route}
			pattern := r.Host + "\x00" + r.Prefix
			if id, ok := first[pattern]; ok {
				if len(shared[id]) == 0 {
					shared[id] = []gatewayOwnedRoute{owners[id]}
				}
				shared[id] = append(shared[id], owned)
				continue
			}
			route := r.Route
			route.ID = key + "\x00" + r.ID
			first[pattern] = route.ID
			routes = append(routes, route)
			owners[route.ID] = owned
		}
	}
	table, err := NewTable(routes)
	if err != nil {
		g.snapshot.Store(&gatewaySnapshot{owners: map[string]gatewayOwnedRoute{}})
		return
	}
	g.snapshot.Store(&gatewaySnapshot{table: table, owners: owners, shared: shared})
}
func (g *sharedGateway) selected(name, path string) (gatewayBinding, Route, error) {
	snapshot := g.snapshot.Load()
	if snapshot == nil {
		return gatewayBinding{}, Route{}, ErrRoute
	}
	route, err := snapshot.table.Match(name, path)
	if err != nil {
		return gatewayBinding{}, Route{}, err
	}
	if all := snapshot.shared[route.ID]; len(all) > 0 {
		owned := all[(snapshot.next.Add(1)-1)%uint64(len(all))]
		return owned.binding, owned.route, nil
	}
	owned, ok := snapshot.owners[route.ID]
	if !ok {
		return gatewayBinding{}, Route{}, ErrRoute
	}
	return owned.binding, owned.route, nil
}

func (g *sharedGateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Connections accepted before an exact legacy handoff did not pass the
	// new listener gate. Apply that gate to their subsequent requests too.
	if addr, err := netip.ParseAddrPort(r.RemoteAddr); err == nil && !g.sourceAllowed(net.TCPAddrFromAddrPort(addr)) {
		g.rejectSource()
		blockResponse(w, r, Block{Response: "reset"})
		return
	}
	name, e := requestHost(r)
	if e != nil {
		http.Error(w, "invalid authority", 400)
		return
	}
	binding, route, e := g.selected(name, r.URL.Path)
	if e != nil {
		g.unmatched.Add(1)
		http.NotFound(w, r)
		return
	}
	if r.TLS != nil {
		sni, valid := host(r.TLS.ServerName)
		if !valid {
			http.Error(w, "unknown TLS authority", 421)
			return
		}
		if sni != name {
			tlsBinding, _, err := g.selectedHost(sni)
			if err != nil || tlsBinding.spec.Tenant != binding.spec.Tenant {
				http.Error(w, "misdirected request", http.StatusMisdirectedRequest)
				return
			}
		}
	}
	if conn, ok := r.Context().Value(gatewayConnectionKey{}).(*gatewayConn); ok && !conn.assign(binding.instance, binding.spec.MaxConnections) {
		http.Error(w, "ingress connection capacity", 503)
		return
	}
	ctx := context.WithValue(r.Context(), gatewayRequestKey{}, gatewayRequest{Gateway: g.kind, Route: route.ID})
	binding.instance.ServeHTTP(w, r.WithContext(ctx))
}
func (g *sharedGateway) selectedHost(name string) (gatewayBinding, Route, error) {
	snapshot := g.snapshot.Load()
	if snapshot == nil {
		return gatewayBinding{}, Route{}, ErrRoute
	}
	route, err := snapshot.table.Host(name)
	if err != nil {
		return gatewayBinding{}, Route{}, err
	}
	owned, ok := snapshot.owners[route.ID]
	if !ok {
		return gatewayBinding{}, Route{}, ErrRoute
	}
	return owned.binding, owned.route, nil
}

func (m *Manager) bindingAllowed(s Spec, r Route, kind string) bool {
	policy, ok := m.hostPolicies[s.Tenant]
	if !ok {
		return false
	}
	if r.Host == "*" {
		return s.SystemWildcard
	}
	if kind == "external" {
		return policy.ExternalAllowed && hostAllowed(r.Host, policy.ExternalHosts)
	}
	return hostAllowed(r.Host, policy.LocalHosts)
}

type gatewayRequestKey struct{}
type gatewayRequest struct{ Gateway, Route string }

func (g *sharedGateway) startLocked() error {
	a, _ := netip.ParseAddrPort(g.definition.Address)
	family := "4"
	if a.Addr().Is6() {
		family = "6"
	}
	listener, e := net.Listen("tcp"+family, g.definition.Address)
	if e != nil {
		return e
	}
	var config *tls.Config
	if g.definition.TLS {
		config = g.manager.dynamicCertificateConfig(func(name string) error {
			binding, _, e := g.selectedHost(name)
			if e != nil {
				g.unmatched.Add(1)
				return e
			}
			if binding.spec.Tenant == "" {
				return ErrRoute
			}
			return nil
		})
	}
	server := &http.Server{Handler: g, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 64 << 10, TLSConfig: config, ErrorLog: log.New(io.Discard, "", 0), BaseContext: func(net.Listener) context.Context { return g.manager.ctx }, ConnContext: func(ctx context.Context, c net.Conn) context.Context {
		if tlsConn, ok := c.(*tls.Conn); ok {
			c = tlsConn.NetConn()
		}
		if owned, ok := c.(*gatewayConn); ok {
			return context.WithValue(ctx, gatewayConnectionKey{}, owned)
		}
		return ctx
	}}
	if config != nil {
		if e = http2.ConfigureServer(server, &http2.Server{MaxConcurrentStreams: 1024}); e != nil {
			listener.Close()
			return e
		}
	}
	var packet net.PacketConn
	var qs *http3.Server
	if g.definition.HTTP3 {
		packet, e = net.ListenPacket("udp"+family, g.definition.Address)
		if e != nil {
			listener.Close()
			return e
		}
		qs = &http3.Server{TLSConfig: config.Clone(), Handler: g, MaxHeaderBytes: 64 << 10, IdleTimeout: 30 * time.Second, QUICConfig: &quic.Config{MaxIncomingStreams: 1024, MaxIncomingUniStreams: 16}, ConnContext: g.quicContext}
	}
	g.listener, g.server, g.packet, g.quic = listener, server, packet, qs
	g.failure = ""
	g.workers.Add(1)
	go func() {
		defer g.workers.Done()
		limited := &gatewayListener{Listener: listener, gateway: g}
		var err error
		if config != nil {
			err = server.ServeTLS(limited, "", "")
		} else {
			err = server.Serve(limited)
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			g.mu.Lock()
			g.failure = "listener-down"
			g.mu.Unlock()
			g.manager.emit(Event{Kind: "ingress-listener-down", Gateway: g.kind})
		}
	}()
	if qs != nil {
		g.workers.Add(1)
		go func() {
			defer g.workers.Done()
			err := qs.Serve(&gatewayPacketConn{PacketConn: packet, gateway: g})
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				g.mu.Lock()
				g.failure = "listener-down"
				g.mu.Unlock()
				g.manager.emit(Event{Kind: "ingress-listener-down", Gateway: g.kind})
			}
		}()
	}
	return nil
}
func (g *sharedGateway) stop() {
	g.mu.Lock()
	server, qs, listener, packet := g.server, g.quic, g.listener, g.packet
	g.server, g.quic, g.listener, g.packet = nil, nil, nil, nil
	g.mu.Unlock()
	if server != nil {
		_ = server.Close()
	}
	if qs != nil {
		_ = qs.Close()
	}
	if listener != nil {
		_ = listener.Close()
	}
	if packet != nil {
		_ = packet.Close()
	}
	g.workers.Wait()
	if g.inherited != nil {
		g.inherited.workers.Wait()
		g.inherited = nil
	}
	if listener != nil {
		g.manager.emit(Event{Kind: "ingress-listener-down", Gateway: g.kind})
	}
}
func (g *sharedGateway) sourceAllowed(address net.Addr) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.kind != "local" {
		return true
	}
	host, _, e := net.SplitHostPort(address.String())
	if e != nil {
		return false
	}
	ip, e := netip.ParseAddr(host)
	if e != nil {
		return false
	}
	for _, p := range g.allowed {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

type gatewayListener struct {
	net.Listener
	gateway *sharedGateway
}

func (l *gatewayListener) Accept() (net.Conn, error) {
	for {
		c, e := l.Listener.Accept()
		if e != nil {
			return nil, e
		}
		if !l.gateway.sourceAllowed(c.RemoteAddr()) {
			l.gateway.rejectSource()
			c.Close()
			continue
		}
		if l.gateway.connections.Add(1) > 4096 {
			l.gateway.connections.Add(-1)
			c.Close()
			continue
		}
		return &gatewayConn{Conn: c, gateway: l.gateway}, nil
	}
}

type gatewayConnectionKey struct{}
type gatewayConn struct {
	net.Conn
	gateway *sharedGateway
	mu      sync.Mutex
	owners  map[*instance]bool
	once    sync.Once
	closed  bool
}

func (c *gatewayConn) assign(owner *instance, limit int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return false
	}
	if c.owners[owner] {
		return true
	}
	if owner.connections.Add(1) > int64(limit) {
		owner.connections.Add(-1)
		return false
	}
	if c.owners == nil {
		c.owners = map[*instance]bool{}
	}
	c.owners[owner] = true
	return true
}
func (c *gatewayConn) Close() error {
	err := c.Conn.Close()
	c.release()
	return err
}

// release returns every selected instance exactly once. TCP calls it after
// closing its native connection; QUIC calls it from that connection's context,
// never from a request/stream context or a completed response.
func (c *gatewayConn) release() {
	c.once.Do(func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.closed = true
		if c.gateway != nil {
			c.gateway.connections.Add(-1)
		}
		for owner := range c.owners {
			owner.connections.Add(-1)
		}
	})
}

func quicOwnerContext(ctx context.Context, c *quic.Conn, owner *instance, limit int) context.Context {
	// The embedded net.Conn is only the TCP close adapter. QUIC shares the
	// assignment state and uses its own actual connection termination below.
	owned := &gatewayConn{}
	ctx = context.WithValue(ctx, gatewayConnectionKey{}, owned)
	if !owned.assign(owner, limit) {
		owned.release()
		_ = c.CloseWithError(0, "ingress connection capacity")
		return ctx
	}
	context.AfterFunc(c.Context(), owned.release)
	return ctx
}

type gatewayPacketConn struct {
	net.PacketConn
	gateway *sharedGateway
}

func (c *gatewayPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, a, e := c.PacketConn.ReadFrom(p)
		if e != nil {
			return n, a, e
		}
		if !c.gateway.sourceAllowed(a) {
			c.gateway.rejectSource()
			continue
		}
		return n, a, nil
	}
}
func (g *sharedGateway) rejectSource() {
	g.sourceRejected.Add(1)
	now := time.Now().Unix()
	g.mu.Lock()
	if g.rejectionSecond != now {
		g.rejectionSecond = now
		g.rejectionsThisSecond = 0
	}
	g.rejectionsThisSecond++
	spike := g.rejectionsThisSecond == 100
	g.mu.Unlock()
	if spike {
		g.manager.emit(Event{Kind: "ingress-source-rejected-spike", Gateway: g.kind, Value: 100})
	}
}

type SharedGatewayObservation struct {
	ID, Gateway, Address, Error string
	HTTP3                       bool
	Ready                       bool
	SourceRejected              uint64
	Unmatched                   uint64
	Hosts                       []SharedHostObservation
}
type SharedHostObservation struct{ Host, Prefix, Tenant, App string }

func (m *Manager) Gateways() []SharedGatewayObservation {
	m.gatewayMu.Lock()
	defer m.gatewayMu.Unlock()
	out := []SharedGatewayObservation{}
	for _, g := range m.gateways {
		g.mu.RLock()
		row := SharedGatewayObservation{ID: g.definition.ID, Gateway: g.kind, Address: g.definition.Address, HTTP3: g.definition.HTTP3, Error: g.failure, SourceRejected: g.sourceRejected.Load(), Unmatched: g.unmatched.Load(), Ready: g.listener != nil && g.failure == ""}
		for _, b := range g.bindings {
			for _, r := range b.table.routes {
				row.Hosts = append(row.Hosts, SharedHostObservation{Host: r.Host, Prefix: r.Prefix, Tenant: b.spec.Tenant, App: b.spec.App})
			}
		}
		g.mu.RUnlock()
		sort.Slice(row.Hosts, func(i, j int) bool {
			return row.Hosts[i].Host+row.Hosts[i].Prefix < row.Hosts[j].Host+row.Hosts[j].Prefix
		})
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// listenerGateway classifies legacy sockets without assigning them new shared
// ownership or forbidding existing unclassified installation addresses.
func (m *Manager) listenerGateway(address string) string {
	endpoint, err := netip.ParseAddrPort(address)
	if err != nil {
		return "unclassified"
	}
	m.gatewayMu.Lock()
	defer m.gatewayMu.Unlock()
	if kind := m.gatewayClasses[endpoint.Addr()]; kind != "" {
		return kind
	}
	return "unclassified"
}

func (m *Manager) sharedFailure(key string, s Spec) string {
	m.gatewayMu.Lock()
	defer m.gatewayMu.Unlock()
	for _, listener := range s.Listeners {
		if listener.Shared == "" {
			continue
		}
		g := m.gateways[listener.Shared]
		if g == nil {
			return "gateway-unavailable"
		}
		g.mu.RLock()
		_, bound := g.bindings[key]
		failed := bound && (g.listener == nil || g.failure != "")
		g.mu.RUnlock()
		if failed {
			return "gateway-listener-down"
		}
	}
	return ""
}

func (g *sharedGateway) quicContext(ctx context.Context, c *quic.Conn) context.Context {
	if !g.sourceAllowed(c.RemoteAddr()) {
		g.rejectSource()
		c.CloseWithError(0, "source rejected")
		return ctx
	}
	binding, _, err := g.selectedHost(c.ConnectionState().TLS.ServerName)
	if err != nil {
		c.CloseWithError(0, "unknown ingress authority")
		return ctx
	}
	return quicOwnerContext(ctx, c, binding.instance, binding.spec.MaxConnections)
}

type handoffPacketConn struct {
	net.PacketConn
	owned *ownedHTTPListener
}

func (c *handoffPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, a, err := c.PacketConn.ReadFrom(p)
		if err != nil {
			return n, a, err
		}
		g := c.owned.gateway.Load()
		if g == nil || g.sourceAllowed(a) {
			return n, a, nil
		}
		g.rejectSource()
	}
}
