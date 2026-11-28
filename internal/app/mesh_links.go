// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"fmt"
	"log"
	"slices"
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
	failure string // the last dial failure logged, "" after a success
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

// logged reports whether a dial outcome differs from the last one logged for
// key, and records it: a dial failing the same way every few seconds is
// logged once, and again when it changes or recovers.
func (m *meshLinks) logged(key sfcp.Identity, err error) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	l := m.peers[key]
	if l == nil {
		return false
	}
	text := ""
	if err != nil {
		text = err.Error()
	}
	if l.failure == text {
		return false
	}
	l.failure = text
	return true
}

// meshPeers lists the nodes this node keeps a session with: every member
// and joining node not removed or retired, except itself.
// skipped names, by member ID, why a member with an endpoint is not dialed.
func (r *Runtime) meshPeers(ctx context.Context) (out []sfcp.Peer, skipped map[string]string) {
	engine := r.Engine()
	if engine == nil {
		return nil, nil
	}
	_, d, err := r.members(ctx, false)
	if err != nil {
		return nil, map[string]string{"*": "membership unreadable: " + err.Error()}
	}
	skipped = map[string]string{}
	for _, entry := range d.Entries {
		full, err := identity.ParseKey(entry.CurrentPeer().Key)
		switch {
		case err != nil:
			skipped[entry.Peer.ID] = "its key does not parse"
			continue
		case full == r.Identity.Public:
			continue
		case !d.ReplicationKey(full):
			skipped[entry.Peer.ID] = "its key is not a current replication key"
			continue
		case entry.Peer.Endpoint == "":
			skipped[entry.Peer.ID] = "it has no endpoint (it connects to this node)"
			continue
		case strings.HasPrefix(entry.Peer.Endpoint, "unix:"):
			continue
		}
		peer, ok := r.Mesh.Peer(sfcp.Identity(full))
		switch {
		case !ok:
			skipped[entry.Peer.ID] = "its key is not a known transport peer"
		case peer.Endpoint != entry.Peer.Endpoint:
			skipped[entry.Peer.ID] = "transport endpoint " + peer.Endpoint + " differs from member endpoint " + entry.Peer.Endpoint
		default:
			out = append(out, peer)
		}
	}
	return out, skipped
}

func (r *Runtime) meshLinkLoop() {
	defer r.wg.Done()
	var links meshLinks
	skippedLogged := map[string]string{}
	wantedLogged, inboundLogged := "", false
	tick := time.NewTicker(meshLinkTick)
	defer tick.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-tick.C:
		}
		if r.Mesh.InboundOnly() {
			if !inboundLogged {
				log.Printf("SFCP mesh: this node is inbound-only and dials no peer")
				inboundLogged = true
			}
			continue
		}
		ctx, cancel := context.WithTimeout(r.ctx, meshLinkTick)
		wanted, skipped := r.meshPeers(ctx)
		cancel()
		for id, reason := range skipped {
			if skippedLogged[id] != reason {
				log.Printf("SFCP mesh does not dial member %s: %s", id, reason)
			}
		}
		if reason, unreadable := skipped["*"]; unreadable {
			skippedLogged["*"] = reason
		} else if skipped != nil {
			skippedLogged = skipped
		}
		// The set this node keeps, and which of it is connected, logged when
		// it changes: a peer it never dials and never logs about is visible.
		var view []string
		for _, p := range wanted {
			view = append(view, fmt.Sprintf("%s=%t", p.ID, r.Mesh.Connected(p.Key)))
		}
		slices.Sort(view)
		if summary := strings.Join(view, " "); summary != wantedLogged && skipped["*"] == "" {
			log.Printf("SFCP mesh peers (connected): %s", summary)
			wantedLogged = summary
		}
		for _, peer := range links.due(time.Now(), wanted, r.Mesh.Connected) {
			r.wg.Add(1)
			go func() {
				defer r.wg.Done()
				ctx, cancel := context.WithTimeout(r.ctx, meshLinkDialLimit)
				_, err := r.Mesh.Dial(ctx, peer)
				cancel()
				if links.logged(peer.Key, err) {
					if err != nil {
						log.Printf("SFCP mesh dial to peer=%s endpoint=%s failed, retrying: %v", peer.ID, peer.Endpoint, err)
					} else {
						log.Printf("SFCP mesh dial to peer=%s endpoint=%s connected", peer.ID, peer.Endpoint)
					}
				}
				links.done(time.Now(), peer.Key, err == nil)
			}()
		}
	}
}
