// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/eventlog"
	"github.com/jay94ks/seafield/internal/loginlog"
)

// R09 4b over the fixture's real loopback SFCP and SDK Raft: login-records,
// own-sessions and events carry Params and return Data; the session's own
// user is the only one read, and an expired event cursor keeps its code.
func TestActivityMethodsActualWire(t *testing.T) {
	f := newVolumeFileWireFixture(t)
	f.session.Scopes = fullUserScopes()
	f.session.Signature = ed25519.Sign(f.nodes[0].Private, access.SessionBytes(f.session))
	var asked loginlog.Query
	f.service.LoginRecords = func(_ context.Context, _ cluster.View, _ access.Session, q loginlog.Query) (loginlog.Page, error) {
		asked = q
		return loginlog.Page{Items: []loginlog.Record{}}, nil
	}
	f.service.EventReader = func(_ context.Context, _ cluster.View, _ access.Session, q eventlog.Query) (eventlog.Page, error) {
		if q.After == "expired" {
			return eventlog.Page{}, eventlog.ErrCursorExpired
		}
		return eventlog.Page{Schema: 1, Items: []eventlog.Item{}, Cursor: "c1"}, nil
	}
	if err := f.service.Serve(); err != nil {
		t.Fatal(err)
	}
	for !f.engines[0].IsLeader() {
		_ = f.engines[1].TransferLeadership(f.ctx, f.peers[0].ID, f.peers[0].Endpoint)
		if f.ctx.Err() != nil {
			t.Fatal(f.ctx.Err())
		}
		time.Sleep(50 * time.Millisecond)
	}
	peer, session := f.peers[0], f.session
	if _, _, err := f.client.LoginRecords(f.ctx, peer, session, "", 10); err != nil || asked.User != session.User || asked.Limit != 10 {
		t.Fatal("login-records", asked, err)
	}
	if p, err := f.client.OwnSessions(f.ctx, peer, session); err != nil || len(p.Items) != 0 {
		t.Fatal("own-sessions", err)
	}
	if p, err := f.client.EventsPage(f.ctx, peer, session, eventlog.Query{Limit: 10}); err != nil || p.Cursor != "c1" {
		t.Fatal("events", err)
	}
	var refused *Error
	if _, err := f.client.EventsPage(f.ctx, peer, session, eventlog.Query{After: "expired"}); !errors.As(err, &refused) || refused.Code != "CURSOR_EXPIRED" {
		t.Fatal("expired event cursor", err)
	}
	if _, _, err := f.client.LoginRecords(f.ctx, peer, session, "", 0); err == nil {
		t.Fatal("login-records without a limit sent")
	}
}
