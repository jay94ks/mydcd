// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"context"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/eventbus"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
)

// ChangeBatch is one change watch frame: every change up to Index was
// delivered. Refs name the records that changed (never their content);
// Resync means changes before Index are no longer known: read again.
//
// Events are report notices (a node report changed what sfcd stores),
// not numbered or resumed; EventsLost means some were dropped, so screens
// built from reports read again.
type ChangeBatch struct {
	Index      uint64
	Resync     bool
	Refs       []control.WatchRef
	Events     []userauth.ChangeEvent
	EventsLost bool
}

// WatchChanges opens the watch on its own transport with a copy of the
// session key, as OpenStream does, so it neither blocks nor is cut by the
// Conn's other exchanges.
func (c *realConn) WatchChanges(ctx context.Context, from uint64, each func(ChangeBatch) error) (uint64, error) {
	const m = "change-watch"
	s, done, err := c.open(ctx, m, true)
	if err != nil {
		return from, err
	}
	self, err := identity.FromSeed(c.c.Self.Private.Seed())
	done()
	if err != nil {
		return from, fail(m, CodeTransport, err.Error())
	}
	defer clear(self.Private)
	peer := c.peer
	mesh, err := sfcp.NewTransport(self, c.c.Cluster, func(key sfcp.Identity) (sfcp.Peer, bool) { return peer, key == peer.Key })
	if err != nil {
		return from, fail(m, CodeTransport, err.Error())
	}
	defer mesh.Close()
	client := userauth.Client{Cluster: c.c.Cluster, Self: self, Mesh: mesh, Peers: []sfcp.Peer{peer}}
	last, err := client.WatchChanges(ctx, peer, s, from, []string{eventbus.TopicReport}, func(r userauth.ChangeWatchReply) error {
		return each(ChangeBatch{Index: r.Index, Resync: r.Resync, Refs: r.Refs, Events: r.Events, EventsLost: r.EventsLost})
	})
	if err != nil && ctx.Err() == nil {
		return last, realError(m, err)
	}
	return last, err
}
