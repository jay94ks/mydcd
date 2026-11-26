// SPDX-License-Identifier: Apache-2.0

package access

import (
	"slices"
	"strings"
)

const NodeShell Action = "node-shell"
const NodeShellAccount = "mydc-shell"

type NodeShellNode struct {
	Node, Shell string
	Sudo        bool
}
type NodeShellGrant struct {
	User  string
	Nodes []string
}
type NodeShellPolicy struct {
	Revision                 uint64
	Enabled                  bool
	MaxSessions, IdleSeconds int
	Account                  string
	Nodes                    []NodeShellNode
	Grants                   []NodeShellGrant
}

func DefaultNodeShellPolicy() NodeShellPolicy {
	return NodeShellPolicy{MaxSessions: 4, IdleSeconds: 1800, Account: NodeShellAccount}
}
func (p NodeShellPolicy) Clone() NodeShellPolicy {
	p.Nodes = slices.Clone(p.Nodes)
	p.Grants = slices.Clone(p.Grants)
	for i := range p.Grants {
		p.Grants[i].Nodes = slices.Clone(p.Grants[i].Nodes)
	}
	return p
}
func (p NodeShellPolicy) Valid() bool {
	if p.Account != NodeShellAccount || p.MaxSessions < 1 || p.MaxSessions > 16 || p.IdleSeconds < 60 || p.IdleSeconds > 86400 || len(p.Nodes) > maxRecords || len(p.Grants) > maxRecords {
		return false
	}
	previous := ""
	for _, n := range p.Nodes {
		if !identifier(n.Node) || n.Node <= previous || (n.Shell != "inherit" && n.Shell != "on" && n.Shell != "off") {
			return false
		}
		previous = n.Node
	}
	previous = ""
	for _, g := range p.Grants {
		if !identifier(g.User) || g.User <= previous || len(g.Nodes) == 0 || len(g.Nodes) > 256 {
			return false
		}
		previous = g.User
		last := ""
		for _, node := range g.Nodes {
			if !identifier(node) || node <= last {
				return false
			}
			last = node
		}
	}
	return true
}
func (p NodeShellPolicy) Node(node string) (NodeShellNode, bool) {
	n := NodeShellNode{Node: node, Shell: "inherit"}
	for _, row := range p.Nodes {
		if row.Node == node {
			n = row
			break
		}
	}
	enabled := p.Enabled
	if n.Shell != "inherit" {
		enabled = n.Shell == "on"
	}
	return n, enabled
}
func (p NodeShellPolicy) Allows(c Catalog, user, node string) bool {
	if c.SystemAllowed(user) {
		return true
	}
	u, ok := c.User(user)
	if !ok || !u.Enabled {
		return false
	}
	for _, g := range p.Grants {
		if g.User == user {
			return slices.Contains(g.Nodes, node)
		}
	}
	return false
}

// Set methods validate immutable configuration only. The committed control
// boundary requires a current system administrator and the signed policy CAS.
func (p NodeShellPolicy) SetGlobal(expected uint64, enabled bool, maxSessions, idleSeconds int) (NodeShellPolicy, error) {
	if expected != p.Revision {
		return p, ErrConflict
	}
	n := p.Clone()
	if n.Revision == ^uint64(0) {
		return p, ErrInvalid
	}
	n.Revision++
	n.Enabled = enabled
	n.MaxSessions = maxSessions
	n.IdleSeconds = idleSeconds
	if !n.Valid() {
		return p, ErrInvalid
	}
	return n, nil
}
func (p NodeShellPolicy) SetNode(expected uint64, row NodeShellNode) (NodeShellPolicy, error) {
	if expected != p.Revision {
		return p, ErrConflict
	}
	n := p.Clone()
	if n.Revision == ^uint64(0) {
		return p, ErrInvalid
	}
	n.Revision++
	found := false
	for i := range n.Nodes {
		if n.Nodes[i].Node == row.Node {
			n.Nodes[i] = row
			found = true
			break
		}
	}
	if !found {
		n.Nodes = append(n.Nodes, row)
	}
	slices.SortFunc(n.Nodes, func(a, b NodeShellNode) int { return strings.Compare(a.Node, b.Node) })
	if !n.Valid() {
		return p, ErrInvalid
	}
	return n, nil
}
func (p NodeShellPolicy) SetGrant(expected uint64, row NodeShellGrant) (NodeShellPolicy, error) {
	if expected != p.Revision {
		return p, ErrConflict
	}
	if !identifier(row.User) {
		return p, ErrInvalid
	}
	n := p.Clone()
	if n.Revision == ^uint64(0) {
		return p, ErrInvalid
	}
	n.Revision++
	nodes := slices.Clone(row.Nodes)
	slices.Sort(nodes)
	n.Grants = slices.DeleteFunc(n.Grants, func(g NodeShellGrant) bool { return g.User == row.User })
	if len(nodes) > 0 {
		n.Grants = append(n.Grants, NodeShellGrant{User: row.User, Nodes: nodes})
	}
	slices.SortFunc(n.Grants, func(a, b NodeShellGrant) int { return strings.Compare(a.User, b.User) })
	if !n.Valid() {
		return p, ErrInvalid
	}
	return n, nil
}
func (c Catalog) AuthorizeNodeShell(s Session, cluster [32]byte, issuer Issuer, at int64, node string, p NodeShellPolicy) error {
	if !p.Valid() || !identifier(node) || c.VerifySession(s, cluster, issuer, at) != nil || !p.Allows(c, s.User, node) {
		return ErrDenied
	}
	for _, scope := range s.Scopes {
		if scope.Tenant == "*" && slices.Contains(scope.Actions, NodeShell) {
			return nil
		}
	}
	return ErrDenied
}
