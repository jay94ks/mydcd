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

// ClusterFirewallMethod reads the committed cluster firewall: the default
// policy and the shared rules every managed server applies under its own.
// A system administrator only. Changes are the management change
// set-cluster-firewall.
var ClusterFirewallMethod = define(Method[control.ClusterFirewallQuery, control.ClusterFirewallView]{Name: "cluster-firewall"}, true, func(_ context.Context, s Service, view cluster.View, session access.Session, _ control.ClusterFirewallQuery) (control.ClusterFirewallView, string) {
	v, err := s.Policy.ReadClusterFirewall(view.State, session, time.Now().Unix())
	if err != nil {
		return control.ClusterFirewallView{}, "denied"
	}
	return v, "ok"
})

// ClusterFirewall reads the cluster firewall through target.
func (c Client) ClusterFirewall(ctx context.Context, target sfcp.Peer, session access.Session) (control.ClusterFirewallView, error) {
	r, err := call(ctx, c, target, session, ClusterFirewallMethod, control.ClusterFirewallQuery{})
	if err == nil && !r.Valid() {
		return control.ClusterFirewallView{}, sfcp.ErrFrame
	}
	return r, err
}
