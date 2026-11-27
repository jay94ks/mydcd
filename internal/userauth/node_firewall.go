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

// NodeFirewallMethod reads or changes one server's own firewall chain. A
// system administrator only; it never goes through Raft
// (devel/proposals/node-firewall.md).
var NodeFirewallMethod = define(Method[control.NodeFirewallOp, control.NodeFirewallResult]{Name: "node-firewall"}, true, func(ctx context.Context, s Service, view cluster.View, session access.Session, op control.NodeFirewallOp) (control.NodeFirewallResult, string) {
	read, err := s.Policy.ReadNodeFirewall(view.State, session, time.Now().Unix(), op)
	if err != nil {
		return control.NodeFirewallResult{}, "denied"
	}
	if s.NodeFirewall == nil {
		return control.NodeFirewallResult{}, "unavailable"
	}
	result, err := s.NodeFirewall(ctx, read)
	if err != nil || !result.Valid() || result.Node != op.Node || result.Action != op.Action {
		return control.NodeFirewallResult{}, "unavailable"
	}
	return result, "ok"
})

// NodeFirewall sends one firewall request through target.
func (c Client) NodeFirewall(ctx context.Context, target sfcp.Peer, session access.Session, op control.NodeFirewallOp) (control.NodeFirewallResult, error) {
	r, err := call(ctx, c, target, session, NodeFirewallMethod, op)
	if err == nil && (!r.Valid() || r.Node != op.Node || r.Action != op.Action) {
		return control.NodeFirewallResult{}, sfcp.ErrFrame
	}
	return r, err
}
