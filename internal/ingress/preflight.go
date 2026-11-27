// SPDX-License-Identifier: Apache-2.0

package ingress

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"

	"github.com/jay94ks/seafield/internal/network"
)

// CheckListeners observes this exact current owner, or binds the future TCP/UDP
// endpoints and closes every temporary socket before returning. It never serves
// traffic, changes a native journal, or claims a future resource generation.
// This point-in-time check does not reserve OS ports after the function returns.
func (m *Manager) CheckListeners(ctx context.Context, key string, revision, generation uint64, current *Spec, listeners []Listener) (err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || ctx.Err() != nil || key == "" || len(listeners) == 0 || len(listeners) > 64 {
		return ErrRoute
	}
	var owned []network.Listener
	if i := m.instances[key]; i != nil {
		i.mu.Lock()
		defer i.mu.Unlock()
		if current != nil {
			if revision == 0 || generation == 0 || i.record.Revision != revision || i.record.Generation != generation || marshal(i.record.Spec) != marshal(*current) || !i.started || i.closing || i.failed != nil || i.record.Gone || i.record.Spec.Lifecycle.Drain || len(i.addresses) == 0 {
				return ErrRoute
			}
			for _, l := range i.record.Spec.Listeners {
				if l.Shared != "" {
					continue
				}
				a, e := netip.ParseAddrPort(l.Address)
				if e != nil {
					return e
				}
				owned = append(owned, network.Listener{Address: a.Addr(), Port: a.Port(), Protocol: 6})
				if l.HTTP3 {
					owned = append(owned, network.Listener{Address: a.Addr(), Port: a.Port(), Protocol: 17})
				}
			}
		} else if !i.record.Gone || i.started || len(i.listeners) != 0 {
			return ErrRoute
		}
	} else if current != nil {
		return ErrRoute
	}
	if current == nil && (revision != 0 || generation != 0) {
		return ErrRoute
	}
	var sockets []io.Closer
	defer func() {
		for _, socket := range sockets {
			err = errors.Join(err, socket.Close())
		}
	}()
	var wanted []network.Listener
	for _, l := range listeners {
		if l.Shared != "" {
			m.gatewayMu.Lock()
			g := m.gateways[l.Shared]
			m.gatewayMu.Unlock()
			if g == nil {
				return ErrRoute
			}
			g.mu.RLock()
			open := g.listener != nil
			l = g.definition
			g.mu.RUnlock()
			if open {
				continue
			}
		} else {
			m.gatewayMu.Lock()
			conflict := false
			for _, g := range m.gateways {
				g.mu.RLock()
				active := g.listener != nil
				g.mu.RUnlock()
				if !active {
					continue
				}
				shared, _ := netip.ParseAddrPort(g.definition.Address)
				direct, _ := netip.ParseAddrPort(l.Address)
				conflict = conflict || network.ListenerConflict(network.Listener{Address: shared.Addr(), Port: shared.Port(), Protocol: 6}, network.Listener{Address: direct.Addr(), Port: direct.Port(), Protocol: 6})
			}
			m.gatewayMu.Unlock()
			if conflict {
				return ErrRoute
			}
		}
		a, e := netip.ParseAddrPort(l.Address)
		if e != nil || l.Address != a.String() || a.Port() == 0 || a.Addr().Is4In6() || a.Addr().Zone() != "" || a.Addr().IsMulticast() || l.HTTP3 && !l.TLS {
			return ErrRoute
		}
		family := "4"
		if a.Addr().Is6() {
			family = "6"
		}
		for _, proto := range []uint8{6, 17} {
			if proto == 17 && !l.HTTP3 {
				continue
			}
			endpoint := network.Listener{Address: a.Addr(), Port: a.Port(), Protocol: proto}
			for _, prior := range wanted {
				if network.ListenerConflict(prior, endpoint) {
					return ErrRoute
				}
			}
			wanted = append(wanted, endpoint)
			reuse := false
			for _, prior := range owned {
				reuse = reuse || prior == endpoint
			}
			if reuse {
				continue
			}
			lc := net.ListenConfig{}
			var socket io.Closer
			if proto == 6 {
				socket, e = lc.Listen(ctx, "tcp"+family, l.Address)
			} else {
				socket, e = lc.ListenPacket(ctx, "udp"+family, l.Address)
			}
			if e != nil {
				return e
			}
			sockets = append(sockets, socket)
		}
	}
	return ctx.Err()
}
