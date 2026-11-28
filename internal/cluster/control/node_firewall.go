// SPDX-License-Identifier: Apache-2.0

package control

import (
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/firewall"
)

// NodeFirewallOp is a system administrator's read or change of one server's
// firewall (devel/proposals/node-firewall.md). It never goes through Raft:
// the server checks the session at a quorum read, applies the change to its
// own SFC-INPUT chain at once and records it in its signed event log.
//
// Action show reads the firewall; change applies Delta when the firewall is
// still at Revision (Operation names the change, so a retry with the same ID
// returns the first outcome); log reads earlier changes, newest first,
// before revision After (0: from the newest).
type NodeFirewallOp struct {
	Operation    string `json:",omitempty"`
	Node, Action string
	Revision     uint64          `json:",omitempty"`
	Delta        *firewall.Delta `json:",omitempty"`
	After        uint64          `json:",omitempty"`
}

func (o NodeFirewallOp) Valid() bool {
	if !lifecycle.ValidID(o.Node) {
		return false
	}
	switch o.Action {
	case "show":
		return o == NodeFirewallOp{Node: o.Node, Action: o.Action}
	case "log":
		return o == NodeFirewallOp{Node: o.Node, Action: o.Action, After: o.After}
	case "change":
		return lifecycle.ValidID(o.Operation) && o.Delta != nil && !o.Delta.Empty() && len(o.Delta.Add)+len(o.Delta.Update)+len(o.Delta.Delete) <= firewall.MaxRules && o.After == 0
	}
	return false
}

// NodeFirewallRead is the server's authority for one firewall request: the
// session checked at a quorum read and the owner key of that server.
type NodeFirewallRead struct {
	Session                   access.Session
	Op                        NodeFirewallOp
	Owner                     [32]byte
	At                        int64
	Index, MembersRoot, Epoch uint64
}

// ReadNodeFirewall authorizes a system administrator's firewall request on
// one installed server.
func (p Policy) ReadNodeFirewall(s state.State, session access.Session, at int64, op NodeFirewallOp) (NodeFirewallRead, error) {
	current, err := p.Current(s)
	if err != nil {
		return NodeFirewallRead{}, err
	}
	c, err := current.Catalog(s)
	if err != nil {
		return NodeFirewallRead{}, err
	}
	if !op.Valid() || c.AuthorizeSession(session, p.Cluster, current.Issuer(session.Issuer), at, "", access.ManageCluster, "") != nil || !c.SystemAllowed(session.User) {
		return NodeFirewallRead{}, access.ErrDenied
	}
	owner, err := current.nodeOwner(s, op.Node)
	if err != nil {
		return NodeFirewallRead{}, err
	}
	return NodeFirewallRead{Session: session, Op: op, Owner: owner, At: at, Index: s.Index(), MembersRoot: s.Object(MembersKey).Revision, Epoch: s.ModuleEpoch()}, nil
}

// NodeFirewallView is one server's firewall now. Managed false means
// node.yaml does not let sfcd control it: every other field is empty and a
// change is refused with not-managed.
//
// Operator is the server's other input rules, read from the kernel as nft
// expressions (OperatorFormat "nft"): every input-hook chain of the ip, ip6
// and inet tables and the chains they jump to, without SFC-INPUT and its
// jump. They are shown only. Applied says SFC-INPUT holds the current rules in every
// family; ApplyError is why it does not.
type NodeFirewallView struct {
	Schema   uint8
	Node     string
	Managed  bool
	Revision uint64          `json:",omitempty"`
	Policy   string          `json:",omitempty"`
	Rules    []firewall.Rule `json:",omitempty"`
	MaxRules int             `json:",omitempty"`
	// Cluster is the cluster firewall this server applies under its own
	// (the copy it last read from Raft); Effective is the policy in force.
	Cluster   *firewall.State `json:",omitempty"`
	Effective string          `json:",omitempty"`
	// Shadowed are server rules a required cluster rule partly overrides.
	Shadowed          []string          `json:",omitempty"`
	Locked            []firewall.Locked `json:",omitempty"`
	Operator          []string          `json:",omitempty"`
	OperatorFormat    string            `json:",omitempty"`
	OperatorTruncated bool              `json:",omitempty"`
	Applied           bool              `json:",omitempty"`
	ApplyError        string            `json:",omitempty"`
}

// NodeFirewallChange is one applied change, kept on the server (the newest
// NodeFirewallLogKeep) and in the signed event log of the cluster.
type NodeFirewallChange struct {
	Operation, User string
	At              int64
	From, To        uint64
	Delta           firewall.Delta
	Added           []string `json:",omitempty"`
}

// NodeFirewallLogKeep is how many changes one server keeps.
const NodeFirewallLogKeep = 500

// NodeFirewallResult answers a NodeFirewallOp. Code is empty on success or
// one of NodeFirewallCodes; a refused change still carries View, so a
// revision conflict shows the current revision.
type NodeFirewallResult struct {
	Schema uint8
	Node   string
	Action string
	Code   string               `json:",omitempty"`
	Error  string               `json:",omitempty"`
	View   *NodeFirewallView    `json:",omitempty"`
	Change *NodeFirewallChange  `json:",omitempty"`
	Log    []NodeFirewallChange `json:",omitempty"`
	More   bool                 `json:",omitempty"`
}

// NodeFirewallCodes are the fixed refusal and failure reasons.
var NodeFirewallCodes = []string{
	"not-managed",        // node.yaml firewall.managed is off on that server
	"revision",           // the firewall changed since it was read
	"invalid",            // a rule or the policy is not valid
	"duplicate",          // the same rule exists twice
	"too-many",           // more than firewall.MaxRules rules
	"missing",            // update or delete of a rule that is not there
	"apply-failed",       // netfilter write failed; the previous rules stay
	"operation-conflict", // the ID is in use for another change
}

func (r NodeFirewallResult) Valid() bool {
	codeOK := r.Code == ""
	for _, c := range NodeFirewallCodes {
		codeOK = codeOK || r.Code == c
	}
	return r.Schema == 1 && lifecycle.ValidID(r.Node) && (r.Action == "show" || r.Action == "change" || r.Action == "log") && codeOK && len(r.Error) <= 512 && len(r.Log) <= 100 && (r.View == nil || r.View.Node == r.Node)
}
