// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"errors"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/observability"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// TaskQuery selects one page of tasks.
type TaskQuery struct {
	control.TaskSelection
	After string `json:",omitempty"`
}

func (q TaskQuery) Valid() bool { return q.TaskSelection.Valid() && len(q.After) <= 512 }

func (c Client) TasksPage(ctx context.Context, peer sfcp.Peer, session access.Session, q control.TaskSelection, after string) (control.TasksPage, error) {
	query := TaskQuery{TaskSelection: q, After: after}
	if !query.Valid() {
		return control.TasksPage{}, access.ErrInvalid
	}
	return call(ctx, c, peer, session, TasksMethod, query)
}

// TasksMethod pages accepted tasks and their signed observations; the policy
// reader authorizes Read on each tenant and server it shows.
var TasksMethod = define(Method[TaskQuery, control.TasksPage]{Name: "tasks"}, true, func(ctx context.Context, s Service, view cluster.View, session access.Session, q TaskQuery) (control.TasksPage, string) {
	var reports []observability.Report
	if s.NodeObservations != nil {
		var err error
		reports, err = s.NodeObservations(ctx, view)
		if err != nil {
			return control.TasksPage{}, "unavailable"
		}
	}
	page, err := s.Policy.TaskPage(view.State, session, time.Now().Unix(), q.TaskSelection, q.After, reports)
	switch {
	case err == nil:
		return page, "ok"
	case errors.Is(err, access.ErrConflict):
		return control.TasksPage{}, "conflict"
	case errors.Is(err, access.ErrDenied) || errors.Is(err, access.ErrInvalid):
		return control.TasksPage{}, "denied"
	}
	return control.TasksPage{}, "unavailable"
})
