// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/state"
)

const NodeShellKey = "control/node-shell"
const NodeShellReportMaxAge int64 = 30
const maxNodeShellRecords = 4096

var (
	ErrNodeShellDisabled    = errors.New("node-shell-disabled")
	ErrNodeShellNotReady    = errors.New("node-shell-not-ready")
	ErrNodeShellLimit       = errors.New("limit")
	ErrNodeShellUnreachable = errors.New("node-unreachable")
)

func NodeShellErrorCode(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrNodeShellDisabled):
		return "node-shell-disabled"
	case errors.Is(err, ErrNodeShellNotReady):
		return "node-shell-not-ready"
	case errors.Is(err, ErrNodeShellLimit):
		return "limit"
	case errors.Is(err, ErrNodeShellUnreachable):
		return "node-unreachable"
	}
	return "forbidden"
}

type NodeShellPolicyChange struct {
	Enabled                  bool
	MaxSessions, IdleSeconds int
}
type NodeShellNodeChange = access.NodeShellNode
type NodeShellGrantChange = access.NodeShellGrant
type NodeShellOpen struct {
	Node       string
	Cols, Rows uint16
}
type NodeShellClose struct{ SessionID string }
type NodeShellUser struct{ User, Username string }
type NodeShellEnd struct {
	Code     int
	Reason   string
	ClosedBy *NodeShellUser `json:",omitempty"`
}
type NodeShellSession struct {
	SessionID, User, Username, Node, Account    string
	Sudo                                        bool
	CreatedAt, OpenedAt, LastActivity, ClosedAt int64
	BytesIn, BytesOut                           uint64
	State                                       string
	End                                         *NodeShellEnd `json:",omitempty"`
}
type NodeShellRecord struct {
	Session     NodeShellSession
	Origin      UserOperation
	Owner       [32]byte
	Ready       NodeShellReport
	Cols, Rows  uint16
	CloseOrigin *UserOperation   `json:",omitempty"`
	Opened      *NodeShellReport `json:",omitempty"`
	Report      *NodeShellReport `json:",omitempty"`
}
type NodeShellBook struct {
	Schema    uint8
	Cluster   [32]byte
	Revision  uint64
	Policy    access.NodeShellPolicy
	Changes   []UserOperation   `json:",omitempty"`
	Readiness []NodeShellReport `json:",omitempty"`
	Records   []NodeShellRecord `json:",omitempty"`
}

func cloneNodeShell[T any](value T) T {
	raw, _ := json.Marshal(value)
	var copy T
	_ = json.Unmarshal(raw, &copy)
	return copy
}
func (b NodeShellBook) Record(id string) (NodeShellRecord, bool) {
	for _, r := range b.Records {
		if r.Session.SessionID == id {
			return cloneNodeShell(r), true
		}
	}
	return NodeShellRecord{}, false
}
func (b NodeShellBook) Quiescent() bool {
	for _, r := range b.Records {
		if r.Session.State != "closed" {
			return false
		}
	}
	return true
}
func nodeShellAction(action string) bool {
	return slices.Contains([]string{"set-node-shell-policy", "set-node-shell-node", "set-node-shell-grant", "open-node-shell", "close-node-shell"}, action)
}
func nodeShellPolicyChange(policy access.NodeShellPolicy, change Change) (access.NodeShellPolicy, error) {
	switch change.Action {
	case "set-node-shell-policy":
		var q NodeShellPolicyChange
		if canonical(change.Payload, &q) != nil {
			return policy, access.ErrInvalid
		}
		return policy.SetGlobal(change.Expected, q.Enabled, q.MaxSessions, q.IdleSeconds)
	case "set-node-shell-node":
		var q NodeShellNodeChange
		if canonical(change.Payload, &q) != nil {
			return policy, access.ErrInvalid
		}
		return policy.SetNode(change.Expected, q)
	case "set-node-shell-grant":
		var q NodeShellGrantChange
		if canonical(change.Payload, &q) != nil {
			return policy, access.ErrInvalid
		}
		return policy.SetGrant(change.Expected, q)
	}
	return policy, access.ErrInvalid
}
func (p Policy) NodeShells(s state.State) (NodeShellBook, error) {
	b := NodeShellBook{Schema: 1, Cluster: p.Cluster, Policy: access.DefaultNodeShellPolicy()}

	raw, revision, err := readCheckpoint(s, NodeShellKey, p.Cluster, p.TrustRoot)
	if err != nil || raw == nil {
		return b, err
	}
	if canonical(raw, &b) != nil || b.Schema != 1 || b.Cluster != p.Cluster || b.Revision != revision || revision == 0 || len(b.Changes) > maxNodeShellRecords || len(b.Records) > maxNodeShellRecords || len(b.Readiness) > maxNodeShellRecords {
		return b, ErrCatalog
	}
	policy := access.DefaultNodeShellPolicy()
	for _, op := range b.Changes {
		if op.VerifyOriginal(p.Cluster) != nil {
			return b, ErrCatalog
		}
		policy, err = nodeShellPolicyChange(policy, op.Change)
		if err != nil {
			return b, ErrCatalog
		}
	}
	a, _ := json.Marshal(policy)
	z, _ := json.Marshal(b.Policy)
	if string(a) != string(z) || !b.Policy.Valid() {
		return b, ErrCatalog
	}
	previous := ""
	for _, report := range b.Readiness {
		if report.Kind != "ready" || report.Node <= previous || !report.validProof(p.Cluster) || report.PolicyRevision > b.Policy.Revision {
			return b, ErrCatalog
		}
		previous = report.Node
	}
	seen := map[string]bool{}
	for _, r := range b.Records {
		row := r.Session
		var q NodeShellOpen
		if r.Origin.VerifyOriginal(p.Cluster) != nil || r.Origin.Change.Action != "open-node-shell" || canonical(r.Origin.Change.Payload, &q) != nil || !q.Valid() || row.SessionID != r.Origin.RequestID || seen[row.SessionID] || row.User != r.Origin.Session.User || row.Node != q.Node || r.Cols != q.Cols || r.Rows != q.Rows || row.Account != access.NodeShellAccount || !validNodeShellUsername(row.Username) || r.Origin.Change.Expected != 0 || row.CreatedAt != r.Origin.At || r.Owner == ([32]byte{}) || row.OpenedAt < 0 || row.LastActivity < 0 || row.ClosedAt < 0 {
			return b, ErrCatalog
		}
		if !r.Ready.validProof(p.Cluster) || r.Ready.Kind != "ready" || !r.Ready.Ready || r.Ready.Reporter != r.Owner || r.Ready.Node != row.Node || r.Ready.Sudo != row.Sudo || r.Ready.PolicyRevision > b.Policy.Revision || r.Ready.At > row.CreatedAt || row.CreatedAt-r.Ready.At > NodeShellReportMaxAge {
			return b, ErrCatalog
		}
		seen[row.SessionID] = true
		if row.End != nil {
			if row.End.Code < 0 || row.End.Code > 255 {
				return b, ErrCatalog
			}
			if row.End.Reason != "exit" && row.End.Reason != "idle" && row.End.Reason != "closed" && row.End.Reason != "policy" {
				return b, ErrCatalog
			}
			if row.End.Reason == "closed" || row.End.Reason == "policy" {
				if r.CloseOrigin == nil || r.CloseOrigin.VerifyOriginal(p.Cluster) != nil || row.End.ClosedBy == nil || row.End.ClosedBy.User != r.CloseOrigin.Session.User || !validNodeShellUsername(row.End.ClosedBy.Username) {
					return b, ErrCatalog
				}
				if row.End.Reason == "policy" && !nodeShellCloseOriginMatches(*r.CloseOrigin, row, r.Origin.Session) {
					return b, ErrCatalog
				}
				if row.End.Reason == "closed" {
					var close NodeShellClose
					if r.CloseOrigin.Change.Action != "close-node-shell" || canonical(r.CloseOrigin.Change.Payload, &close) != nil || close.SessionID != row.SessionID {
						return b, ErrCatalog
					}
				}
			} else if row.End.ClosedBy != nil || r.CloseOrigin != nil {
				return b, ErrCatalog
			}
		}
		switch row.State {
		case "queued":
			if row.OpenedAt != 0 || row.LastActivity != 0 || row.ClosedAt != 0 || row.BytesIn != 0 || row.BytesOut != 0 || row.End != nil || r.Report != nil {
				return b, ErrCatalog
			}
		case "opened":
			if row.OpenedAt < row.CreatedAt || row.LastActivity < row.OpenedAt || row.ClosedAt != 0 || row.End != nil {
				return b, ErrCatalog
			}
		case "closing":
			if row.End == nil || r.CloseOrigin == nil || row.ClosedAt != 0 {
				return b, ErrCatalog
			}
		case "closed":
			if row.End == nil || row.ClosedAt < row.CreatedAt {
				return b, ErrCatalog
			}
		default:
			return b, ErrCatalog
		}
		if r.Opened != nil {
			report := r.Opened
			if !report.validProof(p.Cluster) || report.Kind != "opened" || report.Node != row.Node || report.SessionID != row.SessionID || report.Reporter != r.Owner || report.At != row.OpenedAt || report.LastActivity != row.OpenedAt {
				return b, ErrCatalog
			}
		} else if row.OpenedAt != 0 {
			return b, ErrCatalog
		}
		if r.Report != nil {
			report := r.Report
			if !report.validProof(p.Cluster) || report.SessionID != row.SessionID || report.Node != row.Node || !p.nodeShellRetainedReporter(s, row.Node, r.Owner, *report) || report.BytesIn != row.BytesIn || report.BytesOut != row.BytesOut || report.LastActivity != row.LastActivity || report.Kind == "ready" {
				return b, ErrCatalog
			}
			if row.State == "closed" && (report.Kind != "closed" || report.At != row.ClosedAt || row.End == nil || report.Reason != row.End.Reason || report.Code != row.End.Code) || row.State == "opened" && (report.Kind != "opened" && report.Kind != "activity") {
				return b, ErrCatalog
			}
		} else if row.State == "opened" || row.State == "closed" {
			return b, ErrCatalog
		}
	}
	return b, nil
}

// Only a completed cleanup receipt may come from a successor of the frozen
// owner. Snapshot validation accepts its retained lineage; fresh report admission
// still requires the exact current installed node key in nodeShellReport.
func (p Policy) nodeShellRetainedReporter(s state.State, node string, owner [32]byte, report NodeShellReport) bool {
	if report.Reporter == owner {
		return true
	}
	if report.Kind != "closed" {
		return false
	}
	members, err := p.Members(s)
	return err == nil && members.ResourceKeyForNode(node, owner) && members.ResourceKeyForNode(node, report.Reporter)
}
func validNodeShellUsername(name string) bool {
	return name != "" && len(name) <= 256 && utf8.ValidString(name) && !strings.ContainsFunc(name, unicode.IsControl)
}

// NodeShellOwner exposes the committed work view only to this node's current
// installed identity. Policy must be read again before local account changes;
// the immutable record owner is not an authentication fallback.
func (p Policy) NodeShellOwner(s state.State, caller [32]byte, node string) (NodeShellBook, error) {
	owner, err := p.nodeOwner(s, node)
	if err != nil || owner != caller {
		return NodeShellBook{}, access.ErrDenied
	}
	return p.NodeShells(s)
}

func (q NodeShellOpen) Valid() bool {
	return lifecycle.ValidID(q.Node) && q.Cols >= 1 && q.Cols <= 1000 && q.Rows >= 1 && q.Rows <= 1000
}
func (p Policy) nodeShellCheckpoint(s state.State, b NodeShellBook) (map[string][]byte, state.Code) {
	if b.Revision == ^uint64(0) {
		return nil, state.Invalid
	}
	b.Revision++
	raw, err := json.Marshal(b)
	if err != nil {
		return nil, state.Invalid
	}
	return writeCheckpoint(s, NodeShellKey, p.Cluster, p.TrustRoot, b.Revision, raw)
}

type NodeShellReport struct {
	Schema                              uint8
	Cluster, Reporter                   [32]byte
	Node                                string
	PolicyRevision, Epoch, RootRevision uint64
	RequestID                           string
	At, LastActivity                    int64
	Kind, SessionID                     string
	Ready                               bool
	NotReady                            string
	Sudo                                bool
	BytesIn, BytesOut, Sequence         uint64
	Code                                int
	Reason                              string
	Signature                           []byte
}

func NodeShellReportBytes(r NodeShellReport) []byte {
	r.Signature = nil
	raw, _ := json.Marshal(r)
	return append([]byte("sfc-node-shell-report-1\x00"), raw...)
}
func (r NodeShellReport) validProof(cluster [32]byte) bool {
	if r.Schema != 1 || r.Cluster != cluster || r.Reporter == ([32]byte{}) || !lifecycle.ValidID(r.Node) || r.At <= 0 || r.Epoch == 0 || r.RequestID == "" || r.Sequence == 0 || r.LastActivity < 0 || r.LastActivity > r.At || !ed25519.Verify(r.Reporter[:], NodeShellReportBytes(r), r.Signature) {
		return false
	}
	if r.Kind == "ready" {
		return r.SessionID == "" && r.LastActivity == 0 && r.BytesIn == 0 && r.BytesOut == 0 && r.Code == 0 && r.Reason == "" && (r.Ready && r.NotReady == "" || !r.Ready && validNodeShellReason(r.NotReady))
	}
	if r.SessionID == "" || r.Ready || r.NotReady != "" || r.Sudo {
		return false
	}
	switch r.Kind {
	case "opened":
		return r.Code == 0 && r.Reason == "" && r.LastActivity == r.At
	case "activity":
		return r.Code == 0 && r.Reason == ""
	case "closed":
		return r.Code >= 0 && r.Code <= 255 && slices.Contains([]string{"exit", "idle", "closed", "policy"}, r.Reason)
	}
	return false
}
func (r NodeShellReport) Command() (state.Command, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return state.Command{}, err
	}
	c := state.Command{Kind: state.ModuleReport, Actor: "node/" + hex.EncodeToString(r.Reporter[:]), Epoch: r.Epoch, Key: NodeShellKey, Expected: r.RootRevision, Value: string(raw)}
	c.RequestID = state.ReportRequestID(c)
	_, err = state.EncodeCommand(c)
	return c, err
}
func (p Policy) nodeShellReport(s state.State, c state.Command) (NodeShellReport, error) {
	var r NodeShellReport
	if c.Kind != state.ModuleReport || c.Key != NodeShellKey || canonical([]byte(c.Value), &r) != nil || !r.validProof(p.Cluster) || r.Epoch != s.ModuleEpoch() {
		return r, access.ErrDenied
	}
	want, err := r.Command()
	if err != nil || want != c {
		return r, access.ErrDenied
	}
	owner, err := p.nodeOwner(s, r.Node)
	if err != nil || owner != r.Reporter {
		return r, access.ErrDenied
	}
	return r, nil
}
func (p Policy) ResolveNodeShellReport(s state.State, caller [32]byte, raw []byte) (state.Command, error) {
	var r NodeShellReport
	if canonical(raw, &r) != nil || r.Reporter != caller {
		return state.Command{}, access.ErrDenied
	}
	cmd, err := r.Command()
	if err != nil {
		return cmd, err
	}
	if _, ok := s.LookupResult(cmd); ok {
		if !r.validProof(p.Cluster) {
			return cmd, access.ErrDenied
		}
		return cmd, nil
	}
	_, err = p.nodeShellReport(s, cmd)
	return cmd, err
}

func validNodeShellReason(reason string) bool {
	return slices.Contains([]string{"account-not-prepared", "account-unavailable", "account-invalid", "ssh-unavailable", "key-unavailable", "sudo-unavailable", "policy-changed", "stale-report", "node-unreachable"}, reason)
}
func (p Policy) nodeShellReady(s state.State, b NodeShellBook, node string, at int64) (NodeShellReport, error) {
	owner, err := p.nodeOwner(s, node)
	if err != nil {
		return NodeShellReport{}, ErrNodeShellUnreachable
	}
	n, enabled := b.Policy.Node(node)
	if !enabled {
		return NodeShellReport{}, ErrNodeShellDisabled
	}
	for _, ready := range b.Readiness {
		if ready.Node == node {
			if ready.Reporter != owner || ready.PolicyRevision != b.Policy.Revision || ready.Sudo != n.Sudo || ready.At > at || at-ready.At > NodeShellReportMaxAge || !ready.Ready {
				return ready, ErrNodeShellNotReady
			}
			return ready, nil
		}
	}
	return NodeShellReport{}, ErrNodeShellNotReady
}
func (p Policy) CheckNodeShellOpen(s state.State, op UserOperation, at int64) error {
	current, err := p.Current(s)
	if err != nil {
		return err
	}
	p = current
	b, err := p.NodeShells(s)
	if err != nil {
		return err
	}
	c, err := p.Catalog(s)
	var q NodeShellOpen
	if err != nil || op.Change.Action != "open-node-shell" || op.Change.Expected != 0 || canonical(op.Change.Payload, &q) != nil || !q.Valid() || c.OperationAllowed(op.Session, op.Change.Action) != nil || c.AuthorizeNodeShell(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), at, q.Node, b.Policy) != nil {
		return access.ErrDenied
	}
	if _, err = p.nodeShellReady(s, b, q.Node, at); err != nil {
		return err
	}
	active := 0
	for _, r := range b.Records {
		if r.Session.User == op.Session.User && r.Session.Node == q.Node && r.Session.State != "closed" {
			active++
		}
	}
	if active >= b.Policy.MaxSessions || len(b.Records) >= maxNodeShellRecords {
		return ErrNodeShellLimit
	}
	return nil
}

type NodeShellPermit struct {
	Record         NodeShellRecord
	IdleSeconds    int
	PolicyRevision uint64
}

func (p Policy) NodeShellPermit(s state.State, caller [32]byte, id string, at int64) (NodeShellPermit, error) {
	current, err := p.Current(s)
	if err != nil {
		return NodeShellPermit{}, err
	}
	p = current
	b, err := p.NodeShells(s)
	if err != nil {
		return NodeShellPermit{}, err
	}
	r, found := b.Record(id)
	if !found || r.Session.State != "queued" && r.Session.State != "opened" {
		return NodeShellPermit{}, access.ErrDenied
	}
	owner, err := p.nodeOwner(s, r.Session.Node)
	if err != nil || owner != caller || caller != r.Owner {
		return NodeShellPermit{}, access.ErrDenied
	}
	c, err := p.Catalog(s)
	if err != nil || c.OperationAllowed(r.Origin.Session, "open-node-shell") != nil || c.AuthorizeNodeShell(r.Origin.Session, p.Cluster, p.Issuer(r.Origin.Session.Issuer), at, r.Session.Node, b.Policy) != nil {
		return NodeShellPermit{}, access.ErrDenied
	}
	ready, err := p.nodeShellReady(s, b, r.Session.Node, at)
	if err != nil || ready.Sudo != r.Session.Sudo {
		return NodeShellPermit{}, ErrNodeShellNotReady
	}
	return NodeShellPermit{Record: r, IdleSeconds: b.Policy.IdleSeconds, PolicyRevision: b.Policy.Revision}, nil
}
func (p Policy) reduceNodeShell(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	current, err := p.Current(s)
	if err != nil {
		return nil, state.Invalid
	}
	p = current
	b, err := p.NodeShells(s)
	if err != nil {
		return nil, state.Invalid
	}
	if cmd.Kind == state.ModuleReport {
		return p.reduceNodeShellReport(s, b, cmd)
	}
	c, err := p.Catalog(s)
	if err != nil {
		return nil, state.Invalid
	}
	op, err := p.Operation(c, cmd, false)
	if err != nil || !nodeShellAction(op.Change.Action) || c.OperationAllowed(op.Session, op.Change.Action) != nil {
		return nil, state.Forbidden
	}
	if op.Change.Action == "open-node-shell" {
		if err = p.CheckNodeShellOpen(s, op, op.At); err != nil {
			switch {
			case errors.Is(err, access.ErrDenied):
				return nil, state.Forbidden
			case errors.Is(err, ErrNodeShellDisabled):
				return nil, state.NodeShellDisabled
			case errors.Is(err, ErrNodeShellNotReady):
				return nil, state.NodeShellNotReady
			case errors.Is(err, ErrNodeShellLimit):
				return nil, state.NodeShellLimit
			case errors.Is(err, ErrNodeShellUnreachable):
				return nil, state.NodeShellUnreachable
			}
			return nil, state.ConditionFailed
		}
		var q NodeShellOpen
		_ = canonical(op.Change.Payload, &q)
		user, _ := c.User(op.Session.User)
		ready, _ := p.nodeShellReady(s, b, q.Node, op.At)
		b.Records = append(b.Records, NodeShellRecord{Session: NodeShellSession{SessionID: op.RequestID, User: user.ID, Username: user.Username, Node: q.Node, Account: access.NodeShellAccount, Sudo: ready.Sudo, CreatedAt: op.At, State: "queued"}, Origin: op, Owner: ready.Reporter, Ready: ready, Cols: q.Cols, Rows: q.Rows})
	} else {
		if c.AuthorizeSession(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, "", access.ManageCluster, "") != nil {
			return nil, state.Forbidden
		}
		actor, _ := c.User(op.Session.User)
		if op.Change.Action == "close-node-shell" {
			var q NodeShellClose
			if op.Change.Expected != 0 || canonical(op.Change.Payload, &q) != nil || q.SessionID == "" {
				return nil, state.Invalid
			}
			found := false
			for i := range b.Records {
				if b.Records[i].Session.SessionID == q.SessionID {
					found = true
					if b.Records[i].Session.State != "closed" && b.Records[i].Session.State != "closing" {
						requestNodeShellClose(&b.Records[i], op, actor, "closed")
					}
				}
			}
			if !found {
				return nil, state.ConditionFailed
			}
		} else {
			if len(b.Changes) >= maxNodeShellRecords {
				return nil, state.ConditionFailed
			}
			switch op.Change.Action {
			case "set-node-shell-node":
				var q NodeShellNodeChange
				if canonical(op.Change.Payload, &q) != nil {
					return nil, state.Invalid
				}
				if _, err = p.nodeOwner(s, q.Node); err != nil {
					return nil, state.Forbidden
				}
			case "set-node-shell-grant":
				var q NodeShellGrantChange
				if canonical(op.Change.Payload, &q) != nil {
					return nil, state.Invalid
				}
				if _, ok := c.User(q.User); !ok {
					return nil, state.Invalid
				}
				for _, node := range q.Nodes {
					if _, err = p.nodeOwner(s, node); err != nil {
						return nil, state.Forbidden
					}
				}
			}
			prior := b.Policy
			b.Policy, err = nodeShellPolicyChange(b.Policy, op.Change)
			if err != nil {
				if errors.Is(err, access.ErrConflict) {
					return nil, state.ConditionFailed
				}
				return nil, state.Invalid
			}
			b.Changes = append(b.Changes, op)
			for i := range b.Records {
				r := &b.Records[i]
				if r.Session.State == "closed" || r.Session.State == "closing" {
					continue
				}
				old, _ := prior.Node(r.Session.Node)
				next, enabled := b.Policy.Node(r.Session.Node)
				if !enabled || !b.Policy.Allows(c, r.Session.User, r.Session.Node) || old.Sudo != next.Sudo {
					requestNodeShellClose(r, op, actor, "policy")
				}
			}
		}
	}
	return p.nodeShellCheckpoint(s, b)
}
func requestNodeShellClose(r *NodeShellRecord, op UserOperation, actor access.User, reason string) {
	r.Session.State = "closing"
	r.Session.End = &NodeShellEnd{Reason: reason, ClosedBy: &NodeShellUser{User: actor.ID, Username: actor.Username}}
	copy := cloneNodeShell(op)
	r.CloseOrigin = &copy
}
func (p Policy) reduceNodeShellReport(s state.State, b NodeShellBook, cmd state.Command) (map[string][]byte, state.Code) {
	r, err := p.nodeShellReport(s, cmd)
	if err != nil {
		return nil, state.Forbidden
	}
	if r.Kind == "ready" {
		n, enabled := b.Policy.Node(r.Node)
		if r.PolicyRevision != b.Policy.Revision || !enabled || r.Sudo != n.Sudo || r.SessionID != "" || r.LastActivity != 0 || r.BytesIn != 0 || r.BytesOut != 0 || r.Code != 0 || r.Reason != "" || r.Ready && r.NotReady != "" || !r.Ready && !validNodeShellReason(r.NotReady) {
			return nil, state.Invalid
		}
		found := false
		for i, old := range b.Readiness {
			if old.Node == r.Node {
				if r.Sequence <= old.Sequence || r.At < old.At {
					return nil, state.ConditionFailed
				}
				b.Readiness[i] = r
				found = true
			}
		}
		if !found {
			b.Readiness = append(b.Readiness, r)
			slices.SortFunc(b.Readiness, func(a, b NodeShellReport) int { return strings.Compare(a.Node, b.Node) })
		}
		return p.nodeShellCheckpoint(s, b)
	}
	for i := range b.Records {
		record := &b.Records[i]
		row := &record.Session
		if row.SessionID != r.SessionID {
			continue
		}
		if (record.Owner != r.Reporter && (r.Kind != "closed" || !p.ownsResource(s, r.Reporter, record.Owner))) || row.Node != r.Node || row.State == "closed" || r.Ready || r.NotReady != "" || r.Sudo || r.At < row.CreatedAt || r.LastActivity < row.LastActivity || r.LastActivity > r.At || r.BytesIn < row.BytesIn || r.BytesOut < row.BytesOut || record.Report != nil && (r.Sequence <= record.Report.Sequence || r.At < record.Report.At) {
			return nil, state.ConditionFailed
		}
		switch r.Kind {
		case "opened":
			if row.State != "queued" || r.LastActivity != r.At || r.Code != 0 || r.Reason != "" {
				return nil, state.ConditionFailed
			}
			if _, err = p.NodeShellPermit(s, r.Reporter, r.SessionID, r.At); err != nil {
				return nil, state.Forbidden
			}
			row.State = "opened"
			row.OpenedAt = r.At
			row.LastActivity = r.At
			record.Opened = &r
		case "activity":
			if row.State != "opened" || r.Code != 0 || r.Reason != "" {
				return nil, state.ConditionFailed
			}
			if r.BytesIn == row.BytesIn && r.BytesOut == row.BytesOut && r.LastActivity != row.LastActivity {
				return nil, state.Invalid
			}
		case "closed":
			if r.Code < 0 || r.Code > 255 {
				return nil, state.Invalid
			}
			if row.State == "closing" {
				if r.Reason != row.End.Reason {
					return nil, state.Invalid
				}
				row.End.Code = r.Code
			} else {
				if r.Reason != "exit" && r.Reason != "idle" {
					return nil, state.Invalid
				}
				if r.Reason == "idle" && (row.State != "opened" || r.At-r.LastActivity < int64(b.Policy.IdleSeconds)) {
					return nil, state.ConditionFailed
				}
				row.End = &NodeShellEnd{Code: r.Code, Reason: r.Reason}
			}
			row.State = "closed"
			row.ClosedAt = r.At
		default:
			return nil, state.Invalid
		}
		row.LastActivity = r.LastActivity
		row.BytesIn, row.BytesOut = r.BytesIn, r.BytesOut
		record.Report = &r
		return p.nodeShellCheckpoint(s, b)
	}
	return nil, state.ConditionFailed
}

// nodeShellBook is the NodeShellKey Raft book (see book.go).
var nodeShellBook = Book{
	Key:     NodeShellKey,
	Actions: []string{"set-node-shell-policy", "set-node-shell-node", "set-node-shell-grant", "open-node-shell", "close-node-shell"},
	Reduce:  Policy.reduceNodeShell,
	Authorize: func(p Policy, s state.State, c access.Catalog, op UserOperation) error {
		return p.authorizeNodeShell(s, c, op)
	},
	OwnScope: true,
	AdmitReport: func(p Policy, s state.State, cmd state.Command) error {
		_, err := p.nodeShellReport(s, cmd)
		return err
	},
	ReportOnly: true,
}
