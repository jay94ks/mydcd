// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/eventlog"
)

func TestEventSelectorsDoNotBorrowAnotherQueryOrOuterCursor(t *testing.T) {
	q := eventlog.Query{Tenant: "team", App: "shop", Kind: "task-exited", Limit: 1}
	base := Request{Method: "events", Tenant: "team", Events: &q}
	if !base.validQuerySelectors() || !base.validMethodFields() {
		t.Fatal("typed event selectors rejected")
	}
	for _, edit := range []func(*Request){
		func(r *Request) { r.Tenant = "other" },
		func(r *Request) { r.After = "outer-cursor" },
		func(r *Request) { r.Node = "node-a" },
		func(r *Request) { r.App = "shop" },
		func(r *Request) { r.Method = "whoami" },
		func(r *Request) { r.Events = nil },
		func(r *Request) { r.Secret = []byte("private") },
	} {
		bad := base
		edit(&bad)
		if bad.validQuerySelectors() {
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
		r := s.eventQuery(context.Background(), cluster.View{}, access.Session{}, eventlog.Query{})
		if r.Code != pair.code || r.Events != nil {
			t.Fatal("event failure mislabeled as an empty healthy page", r.Code)
		}
	}
}
