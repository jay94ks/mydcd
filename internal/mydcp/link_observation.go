// SPDX-License-Identifier: Apache-2.0

package mydcp

import (
	"context"
	"slices"
	"time"

	"github.com/jay94ks/mydcd/internal/observability"
)

type linkConnection struct {
	outages                []observability.Outage
	session                *Session
	connections            map[*Session]struct{}
	handshakeAt, changedAt uint64
	state                  string
}

// Track only authenticated members. User credentials and public/Unix clients
// never grow this map or become graph vertices. It contains no authority.
func (t *Transport) observeMemberSession(s *Session, current Peer) {
	if s == nil || s.local != nil || !current.Member || !current.Report || current.Key != s.peer.Key || s.conn.Context().Err() != nil {
		return
	}
	now := uint64(time.Now().UnixMilli())
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	if t.linkConnections == nil {
		t.linkConnections = map[Identity]linkConnection{}
	}
	c := t.linkConnections[s.peer.Key]
	if c.connections == nil {
		c.connections = map[*Session]struct{}{}
	}
	if _, tracked := c.connections[s]; tracked {
		t.mu.Unlock()
		return
	}
	c.connections[s] = struct{}{}
	c.handshakeAt = max(c.handshakeAt, s.authenticatedAt)
	if c.session == nil || c.session.conn.Context().Err() != nil {
		c.session = s
	}
	if c.state == "" || c.state == "down" {
		c.state, c.changedAt = "up", now
		if n := len(c.outages); n > 0 && c.outages[n-1].EndedAt == 0 {
			c.outages[n-1].EndedAt = now
		}
	}
	t.linkConnections[s.peer.Key] = c
	t.mu.Unlock()
	context.AfterFunc(s.conn.Context(), func() {
		t.mu.Lock()
		defer t.mu.Unlock()
		c := t.linkConnections[s.peer.Key]
		delete(c.connections, s)
		c.refresh(uint64(time.Now().UnixMilli()))
		t.linkConnections[s.peer.Key] = c
	})

}

// LinkObservation reads actual quic-go counters. Unknown means no authenticated
// connection has been observed; the caller must not turn it into an Up edge.
func (t *Transport) LinkObservation(local string, peer Peer) (observability.Link, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	c, ok := t.linkConnections[peer.Key]
	if !ok {
		return observability.Link{}, false
	}
	c.refresh(uint64(time.Now().UnixMilli()))
	t.linkConnections[peer.Key] = c
	state := c.state
	stats := c.session.conn.ConnectionStats()
	if state != "down" {
		quality := "up"
		if stats.PacketsSent > 0 && stats.PacketsLost > 0 {
			quality = "degraded"
		}
		if quality != c.state {
			c.state, c.changedAt = quality, uint64(time.Now().UnixMilli())
			t.linkConnections[peer.Key] = c
		}
		state = quality
	}
	l := observability.Link{ID: observability.PairID(local, peer.ID), Peer: peer.ID, State: state, Measurement: "quic-connection-cumulative", Outages: slices.Clone(c.outages), LastHandshakeAt: c.handshakeAt, LastChangeAt: c.changedAt, Samples: stats.PacketsSent}
	if stats.SmoothedRTT > 0 {
		n := float64(stats.SmoothedRTT) / float64(time.Millisecond)
		l.RTTMillis = &n
	}
	if stats.PacketsSent > 0 && stats.PacketsLost <= stats.PacketsSent {
		n := float64(stats.PacketsLost) / float64(stats.PacketsSent) * 100
		l.LossPct = &n
		if n > 0 && state == "up" {
			l.State = "degraded"
		}
	}
	return l, true
}

// Concurrent inbound/outbound connections form one member edge. Losing one
// connection is not a link outage while another authenticated path is alive.
func (c *linkConnection) refresh(now uint64) {
	if c.session != nil && c.session.conn.Context().Err() == nil {
		return
	}
	for session := range c.connections {
		if session.conn.Context().Err() == nil {
			c.session = session
			return
		}
		delete(c.connections, session)
	}
	if c.state != "down" {
		c.state, c.changedAt = "down", now
		c.outages = append(slices.Clone(c.outages), observability.Outage{StartedAt: now})
		if len(c.outages) > 8 {
			c.outages = c.outages[len(c.outages)-8:]
		}
	}
}
