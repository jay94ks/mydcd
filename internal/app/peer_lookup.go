// SPDX-License-Identifier: Apache-2.0

package app

import (
	"sync"

	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/mydcp"
)

type peerLookupResult struct {
	peer  mydcp.Peer
	known bool
}

// This memoizes a pure derivation, not authority. The caller reads the current
// committed Engine view before every invocation, including every data packet.
type peerLookupCache struct {
	mu                    sync.Mutex
	engine                *cluster.Engine
	index, position, term uint64
	peers                 map[mydcp.Identity]peerLookupResult
}

func (c *peerLookupCache) resolve(engine *cluster.Engine, v cluster.View, readErr error, key mydcp.Identity, derive func() (mydcp.Peer, bool)) (mydcp.Peer, bool) {
	if engine == nil || readErr != nil {
		return derive()
	}
	index := v.State.Index()
	c.mu.Lock()
	current := c.engine == engine && c.index == index && c.position == v.RaftIndex && c.term == v.Term
	if current {
		if got, found := c.peers[key]; found {
			c.mu.Unlock()
			return got.peer, got.known
		}
	}
	c.mu.Unlock()
	peer, known := derive()
	c.mu.Lock()
	defer c.mu.Unlock()
	// A concurrent older derivation cannot replace the newer committed view.
	if c.engine == engine && c.position > v.RaftIndex {
		return peer, known
	}
	if c.engine != engine || c.index != index || c.position != v.RaftIndex || c.term != v.Term {
		c.engine, c.index, c.position, c.term = engine, index, v.RaftIndex, v.Term
		c.peers = make(map[mydcp.Identity]peerLookupResult)
	}
	// User-auth TLS keys can be unregistered. Never grow with arbitrary peers.
	if len(c.peers) >= 64 {
		clear(c.peers)
	}
	c.peers[key] = peerLookupResult{peer, known}
	return peer, known
}
