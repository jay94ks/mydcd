// SPDX-License-Identifier: Apache-2.0

package control

import (
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"time"
)

// PublicNodeView projects scheduling actor/time from the verified original
// command. It never returns the signed session, capability or original bytes.
func (p Policy) PublicNodeView(s state.State, node string) (membership.NodeView, bool) {
	d, err := p.Members(s)
	if err != nil {
		return membership.NodeView{}, false
	}
	c, err := p.Catalog(s)
	if err != nil {
		return membership.NodeView{}, false
	}
	return p.publicNodeView(d, c, node)
}
func (p Policy) publicNodeView(d membership.Directory, c access.Catalog, node string) (membership.NodeView, bool) {
	view, ok := d.NodeView(node)
	if !ok {
		return view, ok
	}
	if r := view.Identity; r != nil {
		for _, row := range d.Rotations {
			if row.Node != node || row.Operation != r.Operation {
				continue
			}
			var op UserOperation
			if canonical(row.Origin, &op) != nil || op.VerifyOriginal(p.Cluster) != nil || op.Change.Action != "rotate-node-identity" || op.At <= 0 {
				return membership.NodeView{}, false
			}
			r.RequestedAt = time.Unix(op.At, 0).UTC().Format(time.RFC3339)
		}
	}
	if !view.Scheduling.Enabled {
		return view, true
	}
	for _, row := range d.Cordons {
		if row.Node != node || !row.Enabled {
			continue
		}
		var op UserOperation
		// A drain cordons the server too; its original is drain-node.
		if canonical(row.Origin, &op) != nil || op.VerifyOriginal(p.Cluster) != nil || op.Change.Action != "cordon-node" && op.Change.Action != "drain-node" || op.At <= 0 {
			return membership.NodeView{}, false
		}
		if op.Change.Action == "cordon-node" {
			target, err := cordonTarget(op.Change.Action, op.Change.Payload)
			if err != nil {
				return membership.NodeView{}, false
			}
			view.Scheduling.Reason = target.Reason
		}
		user, found := c.User(op.Session.User)
		view.Scheduling.CordonedBy = op.Session.User
		if found {
			view.Scheduling.CordonedBy = user.Username
		}
		view.Scheduling.CordonedAt = time.Unix(op.At, 0).UTC().Format(time.RFC3339)
	}
	return view, true
}
