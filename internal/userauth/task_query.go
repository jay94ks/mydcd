// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"errors"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/observability"
)

func (c Client) TasksPage(ctx context.Context, peer mydcp.Peer, session access.Session, q control.TaskSelection, after string) (Reply, error) {
	if !q.Valid() {
		return Reply{}, access.ErrInvalid
	}
	return c.query(ctx, peer, session, Request{Method: "tasks", Node: q.Node, Tenant: q.Tenant, App: q.App, After: after})
}

func (s Service) taskQueryReply(ctx context.Context, view cluster.View, session access.Session, request Request) Reply {
	var reports []observability.Report
	if s.NodeObservations != nil {
		var err error
		reports, err = s.NodeObservations(ctx, view)
		if err != nil {
			return Reply{Schema: 1, Code: "unavailable"}
		}
	}
	page, err := s.Policy.TaskPage(view.State, session, time.Now().Unix(), control.TaskSelection{Node: request.Node, Tenant: request.Tenant, App: request.App}, request.After, reports)
	if err != nil {
		code := "unavailable"
		if errors.Is(err, access.ErrConflict) {
			code = "conflict"
		} else if errors.Is(err, access.ErrDenied) || errors.Is(err, access.ErrInvalid) {
			code = "denied"
		}
		return Reply{Schema: 1, Code: code}
	}
	return Reply{Schema: 1, Code: "ok", Tasks: page.Tasks, TasksNext: page.Next, TasksRootRevision: page.RootRevision}
}
