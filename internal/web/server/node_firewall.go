// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http"
	"strconv"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/firewall"
	"github.com/jay94ks/seafield/internal/web/sfc"
)

// Node firewall ("방화벽 설정" tab, UI-1G): node-firewall, system admin.
// No Raft: the server applies a change at once. The reply is always 200
// with code empty on success or one of control.NodeFirewallCodes; a server
// that cannot be reached is the usual unavailable error.

type firewallRuleView struct {
	ID      string   `json:"id,omitempty"`
	Action  string   `json:"action"`
	Proto   string   `json:"proto"`
	Ports   string   `json:"ports,omitempty"`
	From    []string `json:"from"`
	Comment string   `json:"comment,omitempty"`
	// Required: a cluster rule no server can override (cluster rules only).
	Required bool `json:"required,omitempty"`
}

type firewallLockedView struct {
	Name   string   `json:"name"`
	Proto  string   `json:"proto,omitempty"`
	Port   uint16   `json:"port,omitempty"`
	From   []string `json:"from,omitempty"`
	Reason string   `json:"reason"`
}

type firewallView struct {
	Node     string             `json:"node"`
	Managed  bool               `json:"managed"`
	Revision uint64             `json:"revision"`
	Policy   string             `json:"policy,omitempty"`
	Rules    []firewallRuleView `json:"rules"`
	MaxRules int                `json:"maxRules,omitempty"`
	// Cluster is the cluster firewall this server applies under its own;
	// effective is the policy in force (policy inherit follows the
	// cluster); shadowed are rule IDs a required cluster rule partly
	// overrides ("일부 가려짐").
	Cluster   *clusterFirewallView `json:"cluster,omitempty"`
	Effective string               `json:"effective,omitempty"`
	Shadowed  []string             `json:"shadowed"`
	Locked    []firewallLockedView `json:"locked"`
	// Operator: the server's other input rules as nft expressions
	// (operatorFormat "nft"), read only.
	Operator          []string `json:"operator"`
	OperatorFormat    string   `json:"operatorFormat,omitempty"`
	OperatorTruncated bool     `json:"operatorTruncated,omitempty"`
	Applied           bool     `json:"applied"`
	ApplyError        string   `json:"applyError,omitempty"`
}

type firewallDeltaView struct {
	Add    []firewallRuleView `json:"add,omitempty"`
	Update []firewallRuleView `json:"update,omitempty"`
	Delete []string           `json:"delete,omitempty"`
	Policy string             `json:"policy,omitempty"`
}

type firewallChangeView struct {
	Operation string            `json:"operation"`
	User      string            `json:"user"`
	At        int64             `json:"at"`
	From      uint64            `json:"from"`
	To        uint64            `json:"to"`
	Delta     firewallDeltaView `json:"delta"`
	Added     []string          `json:"added,omitempty"`
}

type firewallResultView struct {
	Code     string               `json:"code,omitempty"`
	Error    string               `json:"error,omitempty"`
	Firewall *firewallView        `json:"firewall,omitempty"`
	Change   *firewallChangeView  `json:"change,omitempty"`
	Log      []firewallChangeView `json:"log,omitempty"`
	More     bool                 `json:"more,omitempty"`
}

func newFirewallRuleView(r firewall.Rule) firewallRuleView {
	from := r.From
	if from == nil {
		from = []string{}
	}
	return firewallRuleView{ID: r.ID, Action: r.Action, Proto: r.Proto, Ports: r.Ports, From: from, Comment: r.Comment, Required: r.Required}
}

func firewallRuleViews(rules []firewall.Rule) []firewallRuleView {
	out := []firewallRuleView{}
	for _, r := range rules {
		out = append(out, newFirewallRuleView(r))
	}
	return out
}

func (v firewallRuleView) rule() firewall.Rule {
	r := firewall.Rule{ID: v.ID, Action: v.Action, Proto: v.Proto, Ports: v.Ports, Comment: v.Comment, Required: v.Required}
	if len(v.From) > 0 {
		r.From = v.From
	}
	return r
}

func newFirewallChangeView(c control.NodeFirewallChange) firewallChangeView {
	d := firewallDeltaView{Delete: c.Delta.Delete, Policy: c.Delta.Policy}
	if len(c.Delta.Add) > 0 {
		d.Add = firewallRuleViews(c.Delta.Add)
	}
	if len(c.Delta.Update) > 0 {
		d.Update = firewallRuleViews(c.Delta.Update)
	}
	return firewallChangeView{Operation: c.Operation, User: c.User, At: c.At, From: c.From, To: c.To, Delta: d, Added: c.Added}
}

func newFirewallResultView(r control.NodeFirewallResult) firewallResultView {
	out := firewallResultView{Code: r.Code, Error: r.Error, More: r.More}
	if v := r.View; v != nil {
		fv := &firewallView{Node: v.Node, Managed: v.Managed, Revision: v.Revision, Policy: v.Policy, Rules: firewallRuleViews(v.Rules), MaxRules: v.MaxRules, Locked: []firewallLockedView{}, Operator: append([]string{}, v.Operator...), OperatorFormat: v.OperatorFormat, OperatorTruncated: v.OperatorTruncated, Applied: v.Applied, ApplyError: v.ApplyError, Effective: v.Effective, Shadowed: append([]string{}, v.Shadowed...)}
		if v.Cluster != nil {
			c := newClusterFirewallView(*v.Cluster)
			fv.Cluster = &c
		}
		for _, l := range v.Locked {
			fv.Locked = append(fv.Locked, firewallLockedView{Name: l.Name, Proto: l.Proto, Port: l.Port, From: l.From, Reason: l.Reason})
		}
		out.Firewall = fv
	}
	if r.Change != nil {
		c := newFirewallChangeView(*r.Change)
		out.Change = &c
	}
	for _, c := range r.Log {
		out.Log = append(out.Log, newFirewallChangeView(c))
	}
	return out
}

func (s *Server) firewallCall(w http.ResponseWriter, r *http.Request, ws *webSession, op control.NodeFirewallOp) {
	if !op.Valid() {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "opId, revision and at least one of add, update, delete, policy")
		return
	}
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (firewallResultView, error) {
		res, err := c.NodeFirewall(ctx, op)
		if err != nil {
			return firewallResultView{}, err
		}
		return newFirewallResultView(res), nil
	})
}

// GET /nodes/{node}/firewall → node-firewall show.
func (s *Server) handleNodeFirewall(w http.ResponseWriter, r *http.Request, ws *webSession) {
	s.firewallCall(w, r, ws, control.NodeFirewallOp{Node: r.PathValue("node"), Action: "show"})
}

// POST /nodes/{node}/firewall {opId, revision, add?, update?, delete?,
// policy?} → node-firewall change. policy: inherit, return or drop. add has no id; update carries every
// field of the rule after the change. Reusing an opId returns the first
// result.
func (s *Server) handleNodeFirewallChange(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID     string             `json:"opId"`
		Revision uint64             `json:"revision"`
		Add      []firewallRuleView `json:"add,omitempty"`
		Update   []firewallRuleView `json:"update,omitempty"`
		Delete   []string           `json:"delete,omitempty"`
		Policy   string             `json:"policy,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	d := firewall.Delta{Delete: req.Delete, Policy: req.Policy}
	for _, a := range req.Add {
		d.Add = append(d.Add, a.rule())
	}
	for _, u := range req.Update {
		d.Update = append(d.Update, u.rule())
	}
	s.firewallCall(w, r, ws, control.NodeFirewallOp{Operation: req.OpID, Node: r.PathValue("node"), Action: "change", Revision: req.Revision, Delta: &d})
}

// GET /nodes/{node}/firewall/log?before=REVISION → node-firewall log, 50
// changes newest first; more says there are older ones.
func (s *Server) handleNodeFirewallLog(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var before uint64
	if v := r.URL.Query().Get("before"); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			writeError(w, http.StatusUnprocessableEntity, "invalid", "before must be a revision")
			return
		}
		before = n
	}
	s.firewallCall(w, r, ws, control.NodeFirewallOp{Node: r.PathValue("node"), Action: "log", After: before})
}
