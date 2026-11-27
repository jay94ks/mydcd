// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http"

	"github.com/jay94ks/seafield/internal/firewall"
	"github.com/jay94ks/seafield/internal/web/sfc"
)

// Cluster firewall ("클러스터 방화벽"): the default policy and the shared
// rules every managed server applies under its own. Unlike a server's own
// firewall it is in Raft: a change is the signed set-cluster-firewall
// (revision + delta), system admin.

type clusterFirewallView struct {
	Revision uint64             `json:"revision"`
	Policy   string             `json:"policy"`
	Rules    []firewallRuleView `json:"rules"`
	MaxRules int                `json:"maxRules,omitempty"`
}

func newClusterFirewallView(s firewall.State) clusterFirewallView {
	return clusterFirewallView{Revision: s.Revision, Policy: s.Policy, Rules: firewallRuleViews(s.Rules)}
}

// GET /firewall → cluster-firewall.
func (s *Server) handleClusterFirewall(w http.ResponseWriter, r *http.Request, ws *webSession) {
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (clusterFirewallView, error) {
		v, err := c.ClusterFirewall(ctx)
		if err != nil {
			return clusterFirewallView{}, err
		}
		out := newClusterFirewallView(v.Firewall)
		out.MaxRules = v.MaxRules
		return out, nil
	})
}

// POST /firewall {opId, revision, add?, update?, delete?, policy?} →
// set-cluster-firewall, Expected = revision. add has no id; update carries
// every field of the rule after the change; required marks a rule no server
// can override; policy is return or drop.
func (s *Server) handleClusterFirewallChange(w http.ResponseWriter, r *http.Request, ws *webSession) {
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
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		d := firewall.Delta{Delete: req.Delete, Policy: req.Policy}
		for _, a := range req.Add {
			d.Add = append(d.Add, a.rule())
		}
		for _, u := range req.Update {
			d.Update = append(d.Update, u.rule())
		}
		if d.Empty() || len(d.Add)+len(d.Update)+len(d.Delete) > firewall.MaxRules {
			return "", nil, 0, "", invalid("at least one of add, update, delete, policy")
		}
		// Check the change against the current value first, so a mistake is
		// a clear 422 instead of a rejected signed change.
		v, err := c.ClusterFirewall(ctx)
		if err != nil {
			return "", nil, 0, "", err
		}
		if _, _, err := v.Firewall.Change(v.Firewall.Revision, d); err != nil {
			return "", nil, 0, "", invalid(err.Error())
		}
		return sfc.ActionSetClusterFirewall, d, req.Revision, "cluster-firewall", nil
	})
}
