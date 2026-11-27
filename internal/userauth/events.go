// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"errors"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/eventlog"
	"github.com/jay94ks/seafield/internal/sfcp"
)

func (s Service) eventQuery(ctx context.Context, view cluster.View, session access.Session, q eventlog.Query) Reply {
	if s.EventReader == nil {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	page, err := s.EventReader(ctx, view, session, q)
	if err == nil {
		return Reply{Schema: 1, Code: "ok", Events: &page}
	}
	code := "unavailable"
	if errors.Is(err, eventlog.ErrCursorExpired) {
		code = "CURSOR_EXPIRED"
	} else if errors.Is(err, access.ErrDenied) || errors.Is(err, access.ErrInvalid) || errors.Is(err, eventlog.ErrInvalid) {
		code = "denied"
	}
	return Reply{Schema: 1, Code: code}
}
func (c Client) EventsPage(ctx context.Context, peer sfcp.Peer, session access.Session, q eventlog.Query) (eventlog.Page, error) {
	if !q.Valid() {
		return eventlog.Page{}, sfcp.ErrAdmission
	}
	reply, err := c.query(ctx, peer, session, Request{Method: "events", Tenant: q.Tenant, Events: &q})
	if err != nil {
		return eventlog.Page{}, err
	}
	if reply.Events == nil || reply.Events.Schema != 1 || reply.Events.Cursor == "" || len(reply.Events.Cursor) > 1536 || len(reply.Events.Items) > 100 {
		return eventlog.Page{}, sfcp.ErrFrame
	}
	for _, item := range reply.Events.Items {
		if !item.Event.Valid() || item.ID == "" || item.Cursor == "" || q.Tenant != "" && item.Target.Tenant != q.Tenant || q.App != "" && item.Target.App != q.App {
			return eventlog.Page{}, sfcp.ErrFrame
		}
	}
	return *reply.Events, nil
}
