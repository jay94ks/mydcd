// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/eventlog"
)

func TestEventQueryIsOnlyItsParams(t *testing.T) {
	q, _ := json.Marshal(eventlog.Query{Tenant: "team", App: "shop", Kind: "task-exited", Limit: 1})
	base := Request{Schema: 1, Method: "events", Params: q}
	if _, typed, ok := base.typedMethod(); !typed || !ok {
		t.Fatal("typed event query rejected")
	}
	for _, edit := range []func(*Request){
		func(r *Request) { r.Tenant = "team" },
		func(r *Request) { r.After = "outer-cursor" },
		func(r *Request) { r.Node = "node-a" },
		func(r *Request) { r.Params = json.RawMessage(`{"Limit":101}`) },
		func(r *Request) { r.Params = json.RawMessage(`{"App":"shop"}`) },
		func(r *Request) { r.Secret = []byte("private") },
	} {
		bad := base
		edit(&bad)
		if _, _, ok := bad.typedMethod(); ok {
			t.Fatal("mixed event query accepted")
		}
	}
}

func TestEventCursorExpiryIsDistinctFromDeniedAndUnavailable(t *testing.T) {
	for _, pair := range []struct {
		err  error
		code string
	}{{eventlog.ErrCursorExpired, "CURSOR_EXPIRED"}, {eventlog.ErrInvalid, "denied"}, {access.ErrDenied, "denied"}, {eventlog.ErrUnavailable, "unavailable"}} {
		s := Service{EventReader: func(context.Context, cluster.View, access.Session, eventlog.Query) (eventlog.Page, error) {
			return eventlog.Page{}, pair.err
		}}
		p, code := s.eventQuery(context.Background(), cluster.View{}, access.Session{}, eventlog.Query{})
		if code != pair.code || p.Items != nil {
			t.Fatal("event failure mislabeled as an empty healthy page", code)
		}
	}
}
