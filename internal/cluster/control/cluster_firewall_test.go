// SPDX-License-Identifier: Apache-2.0

package control

import (
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/eventlog"
	"github.com/jay94ks/seafield/internal/firewall"
)

func TestClusterFirewallBook(t *testing.T) {
	f := newBackupCore(t)
	if v, err := f.p.ClusterFirewall(f.s); err != nil || v.Revision != 0 || v.Policy != firewall.PolicyReturn || v.Scope != firewall.ScopeCluster {
		t.Fatal(v, err)
	}
	ssh := firewall.Rule{Action: "allow", Proto: "tcp", Ports: "22", From: []string{"192.168.1.0/24"}, Required: true}
	f.apply("fw-1", ClusterFirewallAction, 0, firewall.Delta{Add: []firewall.Rule{ssh}, Policy: firewall.PolicyDrop}, state.Applied)
	before := f.s
	v, err := f.p.ClusterFirewall(f.s)
	if err != nil || v.Revision != 1 || v.Policy != firewall.PolicyDrop || len(v.Rules) != 1 || v.Rules[0].ID != "c1" || !v.Rules[0].Required {
		t.Fatal(v, err)
	}
	// A stale revision, a server-only policy and a duplicate are refused.
	f.apply("fw-2", ClusterFirewallAction, 0, firewall.Delta{Delete: []string{"c1"}}, state.ConditionFailed)
	f.apply("fw-3", ClusterFirewallAction, 1, firewall.Delta{Policy: firewall.PolicyInherit}, state.ConditionFailed)
	f.apply("fw-4", ClusterFirewallAction, 1, firewall.Delta{Add: []firewall.Rule{ssh}}, state.ConditionFailed)
	f.apply("fw-5", ClusterFirewallAction, 1, firewall.Delta{}, state.Invalid)
	f.apply("fw-6", ClusterFirewallAction, 1, firewall.Delta{Delete: []string{"c1"}, Policy: firewall.PolicyReturn}, state.Applied)
	if v, err := f.p.ClusterFirewall(f.s); err != nil || v.Revision != 2 || len(v.Rules) != 0 || v.NextID != 2 {
		t.Fatal(v, err)
	}
	var kinds []string
	var detail eventlog.Detail
	if err := clusterFirewallEvents(f.p, before, f.s, func(kind, _ string, _ eventlog.Target, d eventlog.Detail) { kinds, detail = append(kinds, kind), d }); err != nil {
		t.Fatal(err)
	}
	if len(kinds) != 1 || kinds[0] != "cluster-firewall-changed" || detail.FromVersion != 1 || detail.ToVersion != 2 || detail.Reason != "delete c1; policy return" || detail.Actor != "admin" {
		t.Fatal(kinds, detail)
	}
	view, err := f.p.ReadClusterFirewall(f.s, f.session, 2)
	if err != nil || !view.Valid() || view.Firewall.Revision != 2 {
		t.Fatal(view, err)
	}
}
