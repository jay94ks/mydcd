// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// NodeShellSessionsQuery selects one page of server shell sessions: those
// after the session ID After, narrowed by State ("open" or "closed") and Node.
type NodeShellSessionsQuery struct {
	After string `json:",omitempty"`
	State string `json:",omitempty"`
	Node  string `json:",omitempty"`
}

func (q NodeShellSessionsQuery) Valid() bool {
	return len(q.After) <= 256 && (control.NodeShellSessionsQuery{State: q.State, Node: q.Node}).Valid()
}

func (c Client) NodeShellPolicy(ctx context.Context, peer sfcp.Peer, session access.Session) (control.NodeShellPolicyView, error) {
	p, err := call(ctx, c, peer, session, NodeShellPolicyMethod, NoParams{})
	if err == nil && (p.Account != access.NodeShellAccount || p.MaxSessions < 1 || p.MaxSessions > 16 || p.IdleSeconds < 60 || p.IdleSeconds > 86400) {
		return control.NodeShellPolicyView{}, sfcp.ErrFrame
	}
	return p, err
}

func (c Client) NodeShellSessions(ctx context.Context, peer sfcp.Peer, session access.Session, after string, filters ...control.NodeShellSessionsQuery) (control.NodeShellSessionsPage, error) {
	var q control.NodeShellSessionsQuery
	if len(filters) > 1 {
		return control.NodeShellSessionsPage{}, access.ErrInvalid
	}
	if len(filters) == 1 {
		q = filters[0]
	}
	query := NodeShellSessionsQuery{After: after, State: q.State, Node: q.Node}
	if !query.Valid() {
		return control.NodeShellSessionsPage{}, access.ErrInvalid
	}
	page, err := call(ctx, c, peer, session, NodeShellSessionsMethod, query)
	if err == nil && !validNodeShellSessionsPage(page, q, after) {
		return control.NodeShellSessionsPage{}, sfcp.ErrFrame
	}
	return page, err
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

// Both are authorized by their control.Policy reader. Each carries its book's
// RootRevision, the CAS root a node-shell change starts from.
var (
	NodeShellPolicyMethod = define(Method[NoParams, control.NodeShellPolicyView]{Name: "node-shell-policy"}, true, func(_ context.Context, s Service, view cluster.View, session access.Session, _ NoParams) (control.NodeShellPolicyView, string) {
		p, err := s.Policy.NodeShellPolicy(view.State, session, time.Now().Unix())
		if err != nil {
			return control.NodeShellPolicyView{}, "denied"
		}
		return p, "ok"
	})
	NodeShellSessionsMethod = define(Method[NodeShellSessionsQuery, control.NodeShellSessionsPage]{Name: "node-shell-sessions"}, true, func(_ context.Context, s Service, view cluster.View, session access.Session, q NodeShellSessionsQuery) (control.NodeShellSessionsPage, string) {
		page, err := s.Policy.NodeShellSessions(view.State, session, time.Now().Unix(), q.After, control.NodeShellSessionsQuery{State: q.State, Node: q.Node})
		if err != nil {
			return control.NodeShellSessionsPage{}, "denied"
		}
		return page, "ok"
	})
)
