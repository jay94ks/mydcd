// SPDX-License-Identifier: Apache-2.0

package services

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/jay94ks/mydcd/internal/network"
)

// A group owns both protocols of one exact Settings preparation. Binding does
// not start admission. Hot views keep these FDs and all original request pins.
type dnsSocketGroup struct {
	owner                   *DNSOwner
	group                   uint64
	tenant, id              string
	binding                 *network.ServiceBinding
	udp                     *net.UDPConn
	tcp                     net.Listener
	mu                      sync.Mutex
	started, closed, joined bool
	connections             map[net.Conn]struct{}
	wg                      sync.WaitGroup
}

func (o *DNSOwner) prepare(ctx context.Context, id uint64, b *network.ServiceBinding, gateway netip.Addr, tenant, service string) error {
	if g := o.sockets[id]; g != nil {
		g.mu.Lock()
		closed, joined := g.closed, g.joined
		g.mu.Unlock()
		if !closed {
			return g.binding.Check(ctx)
		}
		if !joined {
			return ErrLease
		}
		// Recover the SAME original preparation only after positive Stop/Wait.
		delete(o.sockets, id)
	}
	if err := b.Check(ctx); err != nil {
		return err
	}
	config := net.ListenConfig{Control: b.SocketControl(ctx, gateway)}
	family := "4"
	if gateway.Is6() {
		family = "6"
	}
	address := netip.AddrPortFrom(gateway, 53).String()
	packet, err := config.ListenPacket(ctx, "udp"+family, address)
	if err != nil {
		return err
	}
	u, ok := packet.(*net.UDPConn)
	if !ok {
		_ = packet.Close()
		return ErrLease
	}
	t, err := config.Listen(ctx, "tcp"+family, address)
	if err != nil {
		_ = u.Close()
		return err
	}
	if err = b.Check(ctx); err != nil {
		_ = u.Close()
		_ = t.Close()
		return err
	}
	o.sockets[id] = &dnsSocketGroup{owner: o, group: id, tenant: tenant, id: service, binding: b, udp: u, tcp: t, connections: map[net.Conn]struct{}{}}
	return nil
}

func (g *dnsSocketGroup) start() {
	g.mu.Lock()
	if g.started || g.closed {
		g.mu.Unlock()
		return
	}
	g.started = true
	g.wg.Add(2)
	udpReady, tcpReady := make(chan struct{}), make(chan struct{})
	go func() { close(udpReady); g.serveUDP(); g.wg.Done() }()
	go func() { close(tcpReady); g.serveTCP(); g.wg.Done() }()
	g.mu.Unlock()
	<-udpReady
	<-tcpReady
}

func (g *dnsSocketGroup) recordError(err error) {
	if err == nil || errors.Is(err, net.ErrClosed) {
		return
	}
	g.owner.mu.Lock()
	defer g.owner.mu.Unlock()
	if !g.owner.closed {
		g.owner.failed = true
		g.owner.lastErr = err
	}
}
func takeBudget(b chan struct{}) bool {
	select {
	case b <- struct{}{}:
		return true
	default:
		return false
	}
}

func (g *dnsSocketGroup) serveUDP() {
	var buffer [4097]byte
	for {
		n, peer, err := g.udp.ReadFromUDPAddrPort(buffer[:])
		if err != nil {
			g.recordError(err)
			return
		}
		if n > 4096 || n < 12 || !takeBudget(g.owner.requests) {
			continue
		}
		raw := append([]byte(nil), buffer[:n]...)
		g.wg.Add(1)
		go func() {
			defer g.wg.Done()
			defer func() { <-g.owner.requests }()
			wire, finish, err := g.owner.query(g.owner.ctx, g, peer.Addr(), raw, false)
			if finish != nil {
				defer finish()
			}
			if err == nil {
				_, _ = g.udp.WriteToUDPAddrPort(wire, peer)
			}
		}()
	}
}

func (g *dnsSocketGroup) serveTCP() {
	for {
		c, err := g.tcp.Accept()
		if err != nil {
			g.recordError(err)
			return
		}
		policy, err := g.owner.options.Current(g.owner.ctx, g.tenant, g.id)
		if err != nil || policy.MaxConnections < 1 {
			g.owner.queryFailure("tcp-current", errors.Join(err, ErrLease))
			_ = c.Close()
			continue
		}
		g.mu.Lock()
		if g.closed {
			g.mu.Unlock()
			_ = c.Close()
			continue
		}
		if len(g.connections) >= policy.MaxConnections || !takeBudget(g.owner.connections) {
			active := len(g.connections)
			g.mu.Unlock()
			g.owner.queryFailure("tcp-admission", fmt.Errorf("connection capacity: active=%d local-limit=%d", active, policy.MaxConnections))
			_ = c.Close()
			continue
		}
		g.connections[c] = struct{}{}
		g.wg.Add(1)
		g.mu.Unlock()
		go g.serveConnection(c)
	}
}

func (g *dnsSocketGroup) serveConnection(c net.Conn) {
	defer g.wg.Done()
	defer func() { _ = c.Close(); g.mu.Lock(); delete(g.connections, c); g.mu.Unlock(); <-g.owner.connections }()
	peer, err := netip.ParseAddrPort(c.RemoteAddr().String())
	if err != nil {
		return
	}
	var size [2]byte
	for {
		_ = c.SetReadDeadline(time.Now().Add(g.owner.options.IdleTimeout))
		raw, err := ReadDNSTCPFrame(c, 4096)
		if err != nil {
			return
		}
		if !takeBudget(g.owner.requests) {
			return
		}
		wire, finish, e := g.owner.query(g.owner.ctx, g, peer.Addr(), raw, true)
		if e == nil {
			_ = c.SetWriteDeadline(time.Now().Add(g.owner.options.IdleTimeout))
			binary.BigEndian.PutUint16(size[:], uint16(len(wire)))
			packet := append(size[:], wire...)
			for len(packet) > 0 {
				var count int
				count, e = c.Write(packet)
				if e != nil || count == 0 {
					if e == nil {
						e = io.ErrShortWrite
					}
					break
				}
				packet = packet[count:]
			}
		}
		// Actual request work and its write have ended; an error/timeout alone
		// did not release a query while an async I/O worker could still use it.
		if finish != nil {
			finish()
		}
		<-g.owner.requests
		if e != nil {
			return
		}
	}
}

func (g *dnsSocketGroup) close() error {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		g.wg.Wait()
		return nil
	}
	g.closed = true
	err := errors.Join(g.udp.Close(), g.tcp.Close())
	for c := range g.connections {
		_ = c.Close()
	}
	g.mu.Unlock()
	g.wg.Wait()
	g.mu.Lock()
	g.joined = true
	g.mu.Unlock()
	return err
}
