// SPDX-License-Identifier: Apache-2.0

package ingress

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/quic-go/quic-go"
)

// ownedHTTPListener keeps the physical server's lifetime independent of the
// app's health worker. Its delegate is switched only after exact handoff proof.
type ownedHTTPListener struct {
	gateway    atomic.Pointer[sharedGateway]
	owner      *instance
	kind       string // the listener's gateway kind, as ServeHTTP routes it
	handler    http.Handler
	definition Listener
	listener   net.Listener
	packet     net.PacketConn
	server     *http.Server
	workers    sync.WaitGroup
}

func (h *ownedHTTPListener) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if g := h.gateway.Load(); g != nil {
		g.ServeHTTP(w, r)
		return
	}
	h.handler.ServeHTTP(w, r)
}
func (h *ownedHTTPListener) serveError(i *instance, err error) {
	if g := h.gateway.Load(); g != nil {
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			g.mu.Lock()
			g.failure = "listener-down"
			g.mu.Unlock()
			g.manager.emit(Event{Kind: "ingress-listener-down", Gateway: g.kind})
		}
		return
	}
	i.serveError(err)
}

// admitHost refuses a TLS handshake, before any certificate is read, for a
// host the listener does not route: the handed-off gateway's table, or the
// owning app's routes for the listener's gateway kind on a direct listener.
func (h *ownedHTTPListener) admitHost(name string) error {
	if g := h.gateway.Load(); g != nil {
		_, _, err := g.selectedHost(name)
		return err
	}
	if h.owner == nil {
		return ErrRoute
	}
	kind := h.kind
	if kind == "" || kind == "unclassified" {
		kind = "local"
	}
	h.owner.mu.Lock()
	routes := h.owner.controlledRoutes(h.owner.record.Spec).Routes
	h.owner.mu.Unlock()
	table, err := routeTable(routes, kind)
	if err != nil {
		return err
	}
	_, err = table.Host(name)
	return err
}
func ownedConnContext(ctx context.Context, c net.Conn) context.Context {
	if tlsConn, ok := c.(*tls.Conn); ok {
		c = tlsConn.NetConn()
	}
	if conn, ok := c.(*gatewayConn); ok {
		return context.WithValue(ctx, gatewayConnectionKey{}, conn)
	}
	return ctx
}

func (h *ownedHTTPListener) quicContext(ctx context.Context, c *quic.Conn, owner *instance, limit int) context.Context {
	if g := h.gateway.Load(); g != nil {
		return g.quicContext(ctx, c)
	}
	// Keep the direct admission in the same assignment state carried by every
	// stream. If this exact socket is handed off later, selecting its original
	// app is already counted and other apps join this same QUIC lifetime.
	return quicOwnerContext(ctx, c, owner, limit)
}

// sharedHandoffShape is deliberately one-way and one-listener. Runtime config
// and an actual socket must additionally prove endpoint/TLS/HTTP3 equality.
func sharedHandoffShape(before, after Spec) bool {
	if before.Tenant != after.Tenant || before.App != after.App || len(before.Listeners) != 1 || len(after.Listeners) != 1 || before.Listeners[0].Shared != "" || after.Listeners[0].Shared == "" || before.Lifecycle.Drain || after.Lifecycle.Drain {
		return false
	}
	after.Listeners = before.Listeners
	return nativeSpec(before) == nativeSpec(after)
}
func (m *Manager) canHandoffLocked(i *instance, desired Spec) bool {
	if !i.started || i.closing || i.failed != nil || i.record.Native == "" || !sharedHandoffShape(i.record.Spec, desired) {
		return false
	}
	original := i.record.Spec.Listeners[0]
	owned := i.direct[original.ID]
	if owned == nil || owned.listener == nil || owned.server == nil || len(i.servers) != 1 || original.HTTP3 && (owned.packet == nil || len(i.quicServers) != 1) || owned.gateway.Load() != nil {
		return false
	}
	m.gatewayMu.Lock()
	defer m.gatewayMu.Unlock()
	g := m.gateways[desired.Listeners[0].Shared]
	if g == nil {
		return false
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.listener == nil && g.definition.Address == original.Address && g.definition.TLS == original.TLS && g.definition.HTTP3 == original.HTTP3
}

// Called after the new committed source is durable, before it is advertised.
// The physical server keeps running; already entered handlers retain old leases.
func (m *Manager) handoffLocked(i *instance, original Spec) error {
	if !sharedHandoffShape(original, i.record.Spec) {
		return ErrRoute
	}
	old := original.Listeners[0]
	wanted := i.record.Spec.Listeners[0]
	owned := i.direct[old.ID]
	m.gatewayMu.Lock()
	defer m.gatewayMu.Unlock()
	g := m.gateways[wanted.Shared]
	if g == nil || owned == nil || owned.gateway.Load() != nil {
		return ErrRoute
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.listener != nil || old.HTTP3 && (owned.packet == nil || len(i.quicServers) != 1) || g.definition.Address != old.Address || g.definition.TLS != old.TLS || g.definition.HTTP3 != old.HTTP3 {
		return ErrRoute
	}
	routes := []Route{}
	for _, route := range i.record.Spec.Routes {
		if gatewayIncludes(route.Gateway, g.kind) {
			if !m.bindingAllowed(i.record.Spec, route, g.kind) || route.Host == "*" && !i.record.Spec.SystemWildcard {
				return ErrRoute
			}
			routes = append(routes, route)
		}
	}
	table, err := NewTable(routes)
	if err != nil || len(routes) == 0 {
		return ErrRoute
	}
	g.bindings[i.key] = gatewayBinding{instance: i, spec: i.record.Spec, table: table}
	g.rebuildLocked()
	g.listener, g.packet, g.server, g.inherited = owned.listener, owned.packet, owned.server, owned
	if old.HTTP3 {
		g.quic = i.quicServers[0]
	}
	// No new accept or handshake may see a half-built shared routing snapshot.
	owned.gateway.Store(g)
	i.listeners = slices.DeleteFunc(i.listeners, func(c io.Closer) bool { return c == owned.listener || c == owned.packet })
	i.servers = nil
	i.quicServers = nil
	delete(i.direct, old.ID)
	delete(i.addresses, old.ID)
	i.addresses[wanted.ID] = g.definition.Address
	m.emit(Event{Kind: "ingress-listener-up", Gateway: g.kind})
	return nil
}
