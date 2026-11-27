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

// LogsClearMethod clears stored container logs for an app or standalone
// selection on every server that keeps them, without touching the
// containers. The server it reaches passes it to each member server, which
// checks Deploy on its own state and clears its own log store; there is no
// Raft command (devel/proposals/seafield-log-clear.md).
var LogsClearMethod = define(Method[control.LogsClear, control.LogsClearReply]{Name: "logs-clear"}, true, func(ctx context.Context, s Service, view cluster.View, session access.Session, q control.LogsClear) (control.LogsClearReply, string) {
	if _, err := s.Policy.LogsScope(view.State, session, time.Now().Unix(), q, access.Read, ""); err != nil {
		return control.LogsClearReply{}, "denied"
	}
	if s.LogsClearer == nil {
		return control.LogsClearReply{}, "unavailable"
	}
	nodes, err := s.LogsClearer(ctx, session, q)
	if err != nil {
		return control.LogsClearReply{}, "unavailable"
	}
	return control.LogsClearReply{Nodes: nodes}, "ok"
})

// ClearLogs sends a log clear through target and returns each server's
// answer. A server that answers "unreachable" kept its logs; sending the
// same clear again later clears them too.
func (c Client) ClearLogs(ctx context.Context, target sfcp.Peer, session access.Session, q control.LogsClear) (control.LogsClearReply, error) {
	return call(ctx, c, target, session, LogsClearMethod, q)
}

// StoredLogsMethod lists what the servers' log stores keep for an
// app or standalone selection, including logs of containers that are gone.
// A server that is down cannot be read; there are no copies elsewhere.
var StoredLogsMethod = define(Method[control.StoredLogsQuery, control.StoredLogsReply]{Name: "stored-logs"}, true, func(ctx context.Context, s Service, view cluster.View, session access.Session, q control.StoredLogsQuery) (control.StoredLogsReply, string) {
	if _, err := s.Policy.LogsScope(view.State, session, time.Now().Unix(), q.LogsClear, access.Read, ""); err != nil {
		return control.StoredLogsReply{}, "denied"
	}
	if s.StoredLogsReader == nil {
		return control.StoredLogsReply{}, "unavailable"
	}
	nodes, err := s.StoredLogsReader(ctx, session, q)
	if err != nil {
		return control.StoredLogsReply{}, "unavailable"
	}
	return control.StoredLogsReply{Nodes: nodes}, "ok"
})

// StoredLogs sends a stored-log list through target.
func (c Client) StoredLogs(ctx context.Context, target sfcp.Peer, session access.Session, q control.StoredLogsQuery) (control.StoredLogsReply, error) {
	return call(ctx, c, target, session, StoredLogsMethod, q)
}
