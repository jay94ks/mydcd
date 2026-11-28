// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"errors"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/eventlog"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// EventsMethod reads one page of the event log. A tenant's events need
// Read in it; the cluster-wide log (no tenant) needs ManageCluster.
var EventsMethod = define(Method[eventlog.Query, eventlog.Page]{Name: "events"}, true, func(ctx context.Context, s Service, view cluster.View, session access.Session, q eventlog.Query) (eventlog.Page, string) {
	c, issuer, ok := s.accountCatalog(view, session)
	action := access.Read
	if q.Tenant == "" {
		action = access.ManageCluster
	}
	if !ok || c.AuthorizeSession(session, s.Policy.Cluster, issuer, time.Now().Unix(), q.Tenant, action, "") != nil {
		return eventlog.Page{}, "denied"
	}
	return s.eventQuery(ctx, view, session, q)
})

func (s Service) eventQuery(ctx context.Context, view cluster.View, session access.Session, q eventlog.Query) (eventlog.Page, string) {
	if s.EventReader == nil {
		return eventlog.Page{}, "unavailable"
	}
	page, err := s.EventReader(ctx, view, session, q)
	if err == nil {
		return page, "ok"
	}
	code := "unavailable"
	if errors.Is(err, eventlog.ErrCursorExpired) {
		code = "CURSOR_EXPIRED"
	} else if errors.Is(err, access.ErrDenied) || errors.Is(err, access.ErrInvalid) || errors.Is(err, eventlog.ErrInvalid) {
		code = "denied"
	}
	return eventlog.Page{}, code
}

func (c Client) EventsPage(ctx context.Context, peer sfcp.Peer, session access.Session, q eventlog.Query) (eventlog.Page, error) {
	p, err := call(ctx, c, peer, session, EventsMethod, q)
	if err != nil {
		return eventlog.Page{}, err
	}
	if p.Schema != 1 || p.Cursor == "" || len(p.Cursor) > 1536 || len(p.Items) > 100 {
		return eventlog.Page{}, sfcp.ErrFrame
	}
	for _, item := range p.Items {
		if !item.Event.Valid() || item.ID == "" || item.Cursor == "" || q.Tenant != "" && item.Target.Tenant != q.Tenant || q.App != "" && item.Target.App != q.App {
			return eventlog.Page{}, sfcp.ErrFrame
		}
	}
	return p, nil
}
