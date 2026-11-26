// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"reflect"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/mydcp"
)

func nodeShellQuery(method string) bool {
	return method == "node-shell-policy" || method == "node-shell-sessions"
}
func (r Request) validNodeShellQuery() bool {
	want := Request{Schema: r.Schema, Method: r.Method, Nonce: r.Nonce}
	if r.Method == "node-shell-sessions" {
		want.After = r.After
		want.State, want.Node = r.State, r.Node
	}
	return nodeShellQuery(r.Method) && len(r.After) <= 256 && (control.NodeShellSessionsQuery{State: r.State, Node: r.Node}).Valid() && reflect.DeepEqual(r, want)
}
func (c Client) NodeShellPolicy(ctx context.Context, peer mydcp.Peer, session access.Session) (Reply, error) {
	reply, err := c.query(ctx, peer, session, Request{Method: "node-shell-policy"})
	if err == nil && (reply.NodeShellPolicy == nil || reply.NodeShellPolicy.Account != access.NodeShellAccount || reply.NodeShellPolicy.MaxSessions < 1 || reply.NodeShellPolicy.MaxSessions > 16 || reply.NodeShellPolicy.IdleSeconds < 60 || reply.NodeShellPolicy.IdleSeconds > 86400 || reply.NodeShellPolicy.RootRevision != reply.NodeShellRootRevision) {
		return Reply{}, mydcp.ErrFrame
	}
	return reply, err
}
func (c Client) NodeShellSessions(ctx context.Context, peer mydcp.Peer, session access.Session, after string, filters ...control.NodeShellSessionsQuery) (Reply, error) {
	var q control.NodeShellSessionsQuery
	if len(filters) > 1 {
		return Reply{}, access.ErrInvalid
	}
	if len(filters) == 1 {
		q = filters[0]
	}
	if !q.Valid() {
		return Reply{}, access.ErrInvalid
	}
	reply, err := c.query(ctx, peer, session, Request{Method: "node-shell-sessions", After: after, State: q.State, Node: q.Node})
	if err == nil && (reply.NodeShellSessions == nil || !validNodeShellSessionsPage(*reply.NodeShellSessions, q, after) || reply.NodeShellSessions.RootRevision != reply.NodeShellRootRevision) {
		return Reply{}, mydcp.ErrFrame
	}
	return reply, err
}

func validNodeShellSessionsPage(page control.NodeShellSessionsPage, q control.NodeShellSessionsQuery, after string) bool {
	if page.Schema != 1 || len(page.Sessions) > 8 || page.Total < len(page.Sessions) {
		return false
	}
	previous := after
	for _, row := range page.Sessions {
		if !lifecycle.ValidID(row.SessionID) || row.SessionID <= previous || q.Node != "" && row.Node != q.Node {
			return false
		}
		if row.State != "queued" && row.State != "opened" && row.State != "closing" && row.State != "closed" || q.State == "open" && row.State == "closed" || q.State == "closed" && row.State != "closed" {
			return false
		}
		previous = row.SessionID
	}
	return page.Next == "" || len(page.Sessions) == 8 && page.Total > 8 && page.Next == previous
}
func (s Service) nodeShellQueryReply(view cluster.View, session access.Session, r Request) Reply {
	reply := Reply{Schema: 1, Code: "ok", ModuleEpoch: view.State.ModuleEpoch(), NodeShellRootRevision: view.State.Object(control.NodeShellKey).Revision}
	now := time.Now().Unix()
	if r.Method == "node-shell-policy" {
		value, err := s.Policy.NodeShellPolicy(view.State, session, now)
		if err != nil {
			return Reply{Schema: 1, Code: "denied"}
		}
		reply.NodeShellPolicy = &value
	} else {
		value, err := s.Policy.NodeShellSessions(view.State, session, now, r.After, control.NodeShellSessionsQuery{State: r.State, Node: r.Node})
		if err != nil {
			return Reply{Schema: 1, Code: "denied"}
		}
		reply.NodeShellSessions = &value
	}
	return reply
}
