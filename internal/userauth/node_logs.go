// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// NodeLogs reads one page of a container's stored log on one server
// (control.NodeLogsQuery). It needs ManageCluster, as the server's
// diagnostics do.
func (c Client) NodeLogs(ctx context.Context, peer sfcp.Peer, session access.Session, q control.NodeLogsQuery) (control.NodeLogsPage, error) {
	if !q.Valid() {
		return control.NodeLogsPage{}, access.ErrInvalid
	}
	page, err := call(ctx, c, peer, session, NodeLogsMethod, q)
	if err != nil {
		return control.NodeLogsPage{}, err
	}
	if !page.Valid(q) {
		return control.NodeLogsPage{}, sfcp.ErrAdmission
	}
	return page, nil
}

var NodeLogsMethod = define(Method[control.NodeLogsQuery, control.NodeLogsPage]{Name: "node-logs"}, true, func(ctx context.Context, s Service, view cluster.View, session access.Session, q control.NodeLogsQuery) (control.NodeLogsPage, string) {
	if !s.manageCluster(view, session) {
		return control.NodeLogsPage{}, "denied"
	}
	read, err := s.Policy.ReadNodeDiagnostics(view.State, session, time.Now().Unix(), q.Node)
	if err != nil {
		return control.NodeLogsPage{}, "denied"
	}
	if s.NodeLogs == nil {
		return control.NodeLogsPage{}, "unavailable"
	}
	page, err := s.NodeLogs(ctx, control.NodeLogsRead{Read: read, Query: q})
	if err != nil || !page.Valid(q) {
		return control.NodeLogsPage{}, "unavailable"
	}
	return page, "ok"
})
