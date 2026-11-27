// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// SFCP is a mesh: whichever node connects first carries traffic both ways.
// A node only dials a peer to which it has no session, so a node behind NAT
// that reaches a public node gives that public node its only path back, and
// an existing member reaches a joining node that cannot reach it (a VPS
// cannot dial a home server's private source endpoint). Failed dials back off.
const (
	meshLinkTick       = time.Second
	meshLinkFirstRetry = time.Second
	meshLinkMaxRetry   = 10 * time.Second
	meshLinkDialLimit  = 5 * time.Second
)

// meshLinks decides when to dial which peer. It holds no connection itself.
type meshLinks struct {
	mu    sync.Mutex
	peers map[sfcp.Identity]*meshLink
}

type meshLink struct {
	next    time.Time
	retry   time.Duration
	dialing bool
}

// due returns the peers to dial now: those without a session, not already
// being dialed and past their backoff. Peers no longer wanted are forgotten.
func (m *meshLinks) due(now time.Time, wanted []sfcp.Peer, connected func(sfcp.Identity) bool) []sfcp.Peer {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.peers == nil {
		m.peers = map[sfcp.Identity]*meshLink{}
	}
	keep := map[sfcp.Identity]bool{}
	var out []sfcp.Peer
	for _, p := range wanted {
		keep[p.Key] = true
		l := m.peers[p.Key]
		if l == nil {
			l = &meshLink{}
			m.peers[p.Key] = l
		}
		if connected(p.Key) {
			l.next, l.retry = time.Time{}, 0
			continue
		}
		if l.dialing || now.Before(l.next) {
			continue
		}
		l.dialing = true
		out = append(out, p)
	}
	for key, l := range m.peers {
		if !keep[key] && !l.dialing {
			delete(m.peers, key)
		}
	}
	return out
}

// done records a dial's outcome.
func (m *meshLinks) done(now time.Time, key sfcp.Identity, ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	l := m.peers[key]
	if l == nil {
		return
	}
	l.dialing = false
	if ok {
		l.next, l.retry = time.Time{}, 0
		return
	}
	if l.retry == 0 {
		l.retry = meshLinkFirstRetry
	} else {
		l.retry = min(2*l.retry, meshLinkMaxRetry)
	}
	l.next = now.Add(l.retry)
}

// meshPeers lists the nodes this node keeps a session with: every member
// and joining node not removed or retired, except itself.
func (r *Runtime) meshPeers(ctx context.Context) []sfcp.Peer {
	engine := r.Engine()
	if engine == nil {
		return nil
	}
	_, d, err := r.members(ctx, false)
	if err != nil {
		return nil
	}
	var out []sfcp.Peer
	for _, entry := range d.Entries {
		full, err := identity.ParseKey(entry.CurrentPeer().Key)
		if err != nil || full == r.Identity.Public || !d.ReplicationKey(full) || entry.Peer.Endpoint == "" || strings.HasPrefix(entry.Peer.Endpoint, "unix:") {
			continue
		}
		peer, ok := r.Mesh.Peer(sfcp.Identity(full))
		if ok && peer.Endpoint == entry.Peer.Endpoint {
			out = append(out, peer)
		}
	}
	return out
}

func (r *Runtime) meshLinkLoop() {
	defer r.wg.Done()
	var links meshLinks
	tick := time.NewTicker(meshLinkTick)
	defer tick.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-tick.C:
		}
		if r.Mesh.InboundOnly() {
			continue
		}
		ctx, cancel := context.WithTimeout(r.ctx, meshLinkTick)
		wanted := r.meshPeers(ctx)
		cancel()
		for _, peer := range links.due(time.Now(), wanted, r.Mesh.Connected) {
			r.wg.Add(1)
			go func() {
				defer r.wg.Done()
				ctx, cancel := context.WithTimeout(r.ctx, meshLinkDialLimit)
				_, err := r.Mesh.Dial(ctx, peer)
				cancel()
				links.done(time.Now(), peer.Key, err == nil)
			}()
		}
	}
}
