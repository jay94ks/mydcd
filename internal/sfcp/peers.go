// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"context"
	"time"
)

// peerState is everything a Transport keeps about one peer key. All fields
// are guarded by Transport.mu. A record is dropped once nothing in it is in
// use (forgetPeer); a member's link record keeps it for its outage history.
type peerState struct {
	// channel is the session Dial uses: the preferred live authenticated
	// QUIC session, whichever side opened it (see adoptSession).
	channel *Session
	// sessions holds every live authenticated QUIC session, so another one
	// takes over when channel ends.
	sessions map[*Session]struct{}
	// dial is closed when the dial in progress (QUIC or Unix) ends.
	dial chan struct{}
	// abort stops a QUIC dial still waiting for its handshake once the
	// peer has connected to this node instead.
	abort context.CancelFunc
	// live counts live sessions of any kind; since is when the count last
	// went from zero to one (ConnectedSince).
	live  int
	since time.Time
	// link is the member link record behind LinkObservation.
	link *linkConnection
}

// peerOf returns key's record, or nil. Caller holds t.mu.
func (t *Transport) peerOf(key Identity) *peerState { return t.peers[key] }

// ensurePeer returns key's record, creating it. Caller holds t.mu.
func (t *Transport) ensurePeer(key Identity) *peerState {
	p := t.peers[key]
	if p == nil {
		if t.peers == nil {
			t.peers = map[Identity]*peerState{}
		}
		p = &peerState{}
		t.peers[key] = p
	}
	return p
}

// forgetPeer drops key's record when nothing in it is in use. Caller holds t.mu.
func (t *Transport) forgetPeer(key Identity) {
	p := t.peers[key]
	if p != nil && p.channel == nil && len(p.sessions) == 0 && p.dial == nil && p.abort == nil && p.live <= 0 && p.link == nil {
		delete(t.peers, key)
	}
}

// channelOf is key's current channel, or nil. Caller holds t.mu.
func (t *Transport) channelOf(key Identity) *Session {
	if p := t.peers[key]; p != nil {
		return p.channel
	}
	return nil
}

// dialing reports whether any dial is in progress. Caller holds t.mu.
func (t *Transport) dialing() bool {
	for _, p := range t.peers {
		if p.dial != nil {
			return true
		}
	}
	return false
}
