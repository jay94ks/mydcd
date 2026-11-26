// SPDX-License-Identifier: Apache-2.0

package control

import (
	"slices"
	"strings"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/credentials"
)

type NodeShellNodeView struct {
	Node, Shell          string
	Sudo, Enabled, Ready bool
	NotReady             string `json:",omitempty"`
}
type NodeShellPolicyView struct {
	Enabled                       bool
	MaxSessions, IdleSeconds      int
	Account                       string
	Nodes                         []NodeShellNodeView
	Grants                        []access.NodeShellGrant
	Revision, Index, RootRevision uint64
}

func nodeShellReadScope(c access.Catalog, session access.Session, cluster [32]byte, issuer access.Issuer, at int64) bool {
	if c.VerifySession(session, cluster, issuer, at) != nil {
		return false
	}
	for _, scope := range session.Scopes {
		if scope.Tenant == "*" && slices.Contains(scope.Actions, access.NodeShell) {
			return true
		}
	}
	return false
}
func (p Policy) NodeShellPolicy(s state.State, session access.Session, at int64) (NodeShellPolicyView, error) {
	current, err := p.Current(s)
	if err != nil {
		return NodeShellPolicyView{}, err
	}
	p = current
	b, err := p.NodeShells(s)
	if err != nil {
		return NodeShellPolicyView{}, err
	}
	c, err := p.Catalog(s)
	if err != nil {
		return NodeShellPolicyView{}, err
	}
	admin := c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, "", access.ManageCluster, "") == nil
	if !admin && !nodeShellReadScope(c, session, p.Cluster, p.Issuer(session.Issuer), at) {
		return NodeShellPolicyView{}, access.ErrDenied
	}
	policy := b.Policy.Clone()
	view := NodeShellPolicyView{Enabled: policy.Enabled, MaxSessions: policy.MaxSessions, IdleSeconds: policy.IdleSeconds, Account: policy.Account, Revision: policy.Revision, Index: s.Index(), RootRevision: s.Object(NodeShellKey).Revision, Nodes: []NodeShellNodeView{}, Grants: []access.NodeShellGrant{}}
	nodes := map[string]bool{}
	if admin {
		directory, err := p.Members(s)
		if err != nil {
			return view, err
		}
		for _, e := range directory.Entries {
			nodes[e.Peer.ID] = true
		}
		for _, n := range policy.Nodes {
			nodes[n.Node] = true
		}
		view.Grants = policy.Grants
	} else {
		for _, grant := range policy.Grants {
			if grant.User == session.User {
				view.Grants = append(view.Grants, grant)
				for _, node := range grant.Nodes {
					nodes[node] = true
				}
			}
		}
		if c.SystemAllowed(session.User) {
			directory, err := p.Members(s)
			if err != nil {
				return view, err
			}
			for _, e := range directory.Entries {
				nodes[e.Peer.ID] = true
			}
		}
	}
	for node := range nodes {
		setting, enabled := policy.Node(node)
		ready, reason := p.nodeShellReady(s, b, node, at)
		v := NodeShellNodeView{Node: node, Shell: setting.Shell, Sudo: setting.Sudo, Enabled: enabled, Ready: reason == nil}
		if reason != nil {
			v.NotReady = ready.NotReady
			if v.NotReady == "" {
				v.NotReady = NodeShellErrorCode(reason)
			}
		}
		view.Nodes = append(view.Nodes, v)
	}
	slices.SortFunc(view.Nodes, func(a, b NodeShellNodeView) int { return strings.Compare(a.Node, b.Node) })
	return view, nil
}

type NodeShellSessionsPage struct {
	Schema              uint8
	Index, RootRevision uint64
	Sessions            []NodeShellSession
	Next                string
	Total               int
}

// Closed retention limits the public list only. Original signed operations,
// effect receipts and event history remain under their existing lifetimes.
const NodeShellClosedListLimit = 200

type NodeShellSessionsQuery struct{ State, Node string }

func (q NodeShellSessionsQuery) Valid() bool {
	return (q.State == "" || q.State == "open" || q.State == "closed") && (q.Node == "" || lifecycle.ValidID(q.Node))
}

func (p Policy) NodeShellSessions(s state.State, session access.Session, at int64, after string, filters ...NodeShellSessionsQuery) (NodeShellSessionsPage, error) {
	var q NodeShellSessionsQuery
	if len(filters) > 1 {
		return NodeShellSessionsPage{}, access.ErrInvalid
	}
	if len(filters) == 1 {
		q = filters[0]
	}
	if !q.Valid() || len(after) > 256 {
		return NodeShellSessionsPage{}, access.ErrInvalid
	}
	current, err := p.Current(s)
	if err != nil {
		return NodeShellSessionsPage{}, err
	}
	p = current
	page := NodeShellSessionsPage{Schema: 1, Index: s.Index(), RootRevision: s.Object(NodeShellKey).Revision, Sessions: []NodeShellSession{}}
	c, err := p.Catalog(s)
	if err != nil {
		return page, err
	}
	admin := c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, "", access.ManageCluster, "") == nil
	if !admin && !nodeShellReadScope(c, session, p.Cluster, p.Issuer(session.Issuer), at) {
		return page, access.ErrDenied
	}
	b, err := p.NodeShells(s)
	if err != nil {
		return page, err
	}
	return nodeShellSessionsPage(b, page, session.User, admin, after, q), nil
}

// This pure projection is shared by every authenticated query. It never
// mutates the book or removes the original authority needed to settle effects.
func nodeShellSessionsPage(b NodeShellBook, page NodeShellSessionsPage, user string, admin bool, after string, q NodeShellSessionsQuery) NodeShellSessionsPage {
	var closed, rows []NodeShellSession
	for _, r := range b.Records {
		if q.Node != "" && r.Session.Node != q.Node {
			continue
		}
		if r.Session.State == "closed" {
			closed = append(closed, r.Session)
		} else if q.State != "closed" && (admin || r.Session.User == user) {
			rows = append(rows, r.Session)
		}
	}
	// The per-node public retention window is independent of the caller.
	// Apply visibility before Total/paging, never expose other users' counts.
	if q.State != "open" {
		slices.SortFunc(closed, func(a, b NodeShellSession) int {
			if a.ClosedAt > b.ClosedAt {
				return -1
			}
			if a.ClosedAt < b.ClosedAt {
				return 1
			}
			return strings.Compare(a.SessionID, b.SessionID)
		})
		counts := map[string]int{}
		for _, row := range closed {
			counts[row.Node]++
			if counts[row.Node] <= NodeShellClosedListLimit && (admin || row.User == user) {
				rows = append(rows, row)
			}
		}
	}
	slices.SortFunc(rows, func(a, b NodeShellSession) int { return strings.Compare(a.SessionID, b.SessionID) })
	page.Total = len(rows)
	for _, row := range rows {
		if row.SessionID <= after {
			continue
		}
		if len(page.Sessions) == 8 {
			page.Next = page.Sessions[len(page.Sessions)-1].SessionID
			break
		}
		page.Sessions = append(page.Sessions, cloneNodeShell(row))
	}
	return page
}

// Catalog revocation uses the original signed account/session change as the
// close actor. Comparing before/after authority isolates this mutation from an
// unrelated expiry; it neither creates a new down command nor invents OS exit.
func (p Policy) nodeShellCatalogRevocations(s state.State, before, after access.Catalog, op UserOperation) (map[string][]byte, state.Code) {
	b, err := p.NodeShells(s)
	if err != nil {
		return nil, state.Invalid
	}
	changed := false
	actor, ok := before.User(op.Session.User)
	if !ok {
		return nil, state.Forbidden
	}
	for i := range b.Records {
		r := &b.Records[i]
		if r.Session.State == "closed" || r.Session.State == "closing" {
			continue
		}
		old := before.AuthorizeNodeShell(r.Origin.Session, p.Cluster, p.Issuer(r.Origin.Session.Issuer), op.At, r.Session.Node, b.Policy)
		next := after.AuthorizeNodeShell(r.Origin.Session, p.Cluster, p.Issuer(r.Origin.Session.Issuer), op.At, r.Session.Node, b.Policy)
		oldOperation := before.OperationAllowed(r.Origin.Session, "open-node-shell")
		nextOperation := after.OperationAllowed(r.Origin.Session, "open-node-shell")
		if old == nil && oldOperation == nil && (next != nil || nextOperation != nil) {
			requestNodeShellClose(r, op, actor, "policy")
			changed = true
		}
	}
	if !changed {
		return nil, state.Applied
	}
	return p.nodeShellCheckpoint(s, b)
}

func (p Policy) authorizeNodeShell(s state.State, c access.Catalog, op UserOperation) error {
	current, err := p.Current(s)
	if err != nil {
		return err
	}
	p = current
	if c.OperationAllowed(op.Session, op.Change.Action) != nil {
		return access.ErrDenied
	}
	if op.Change.Action == "open-node-shell" {
		var q NodeShellOpen
		b, err := p.NodeShells(s)
		if err != nil || canonical(op.Change.Payload, &q) != nil || !q.Valid() || op.Change.Expected != 0 {
			return access.ErrDenied
		}
		return c.AuthorizeNodeShell(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, q.Node, b.Policy)
	}
	return c.AuthorizeSession(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, "", access.ManageCluster, "")
}
func (p Policy) reduceCatalogNodeShellPatch(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	return p.Reduce(s, cmd)
}

func nodeShellCloseOriginMatches(op UserOperation, row NodeShellSession, original access.Session) bool {
	switch op.Change.Action {
	case "set-node-shell-policy":
		var q NodeShellPolicyChange
		return canonical(op.Change.Payload, &q) == nil
	case "set-node-shell-node":
		var q NodeShellNodeChange
		return canonical(op.Change.Payload, &q) == nil && q.Node == row.Node
	case "set-node-shell-grant":
		var q NodeShellGrantChange
		return canonical(op.Change.Payload, &q) == nil && q.User == row.User
	case "put-user":
		var q access.User
		return canonical(op.Change.Payload, &q) == nil && q.ID == row.User
	case "set-account-scope":
		var q access.AccountScope
		return canonical(op.Change.Payload, &q) == nil && q.User == row.User
	case "add-credential":
		var q access.CredentialAddition
		return canonical(op.Change.Payload, &q) == nil && q.User == row.User
	case "disable-credential":
		var q access.CredentialDisable
		return canonical(op.Change.Payload, &q) == nil && q.User == row.User
	case "issue-initial-credential":
		var q credentials.InitialFact
		return canonical(op.Change.Payload, &q) == nil && q.Verify() && q.Request.User == row.User
	case "revoke-session":
		var q SessionRevocation
		return canonical(op.Change.Payload, &q) == nil && q.User == row.User && q.Session == original.ID
	}
	return false
}

func (p Policy) nodeShellRawCatalogRevokes(s state.State, before, after access.Catalog) bool {
	b, err := p.NodeShells(s)
	if err != nil {
		return true
	}
	for _, r := range b.Records {
		if r.Session.State == "closed" || r.Session.State == "closing" {
			continue
		}
		at := r.Origin.At
		issuer := p.Issuer(r.Origin.Session.Issuer)
		was := before.AuthorizeNodeShell(r.Origin.Session, p.Cluster, issuer, at, r.Session.Node, b.Policy) == nil && before.OperationAllowed(r.Origin.Session, "open-node-shell") == nil
		now := after.AuthorizeNodeShell(r.Origin.Session, p.Cluster, issuer, at, r.Session.Node, b.Policy) == nil && after.OperationAllowed(r.Origin.Session, "open-node-shell") == nil
		if was && !now {
			return true
		}
	}
	return false
}
