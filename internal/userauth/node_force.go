// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/mydcp"
)

func (c Client) NodeForceRemovePlan(ctx context.Context, peer mydcp.Peer, session access.Session, q control.NodeForceQuery) (control.NodeForcePlan, error) {
	if !q.Valid() {
		return control.NodeForcePlan{}, access.ErrInvalid
	}
	reply, err := c.query(ctx, peer, session, Request{Method: "node-force-remove-plan", NodeForce: &q})
	if err != nil {
		return control.NodeForcePlan{}, err
	}
	if reply.Code != "ok" || reply.NodeForcePlan == nil || reply.NodeForcePlan.Node != q.Node || reply.NodeForcePlan.Operation != q.Operation || reply.NodeForcePlan.Schema != 1 {
		return control.NodeForcePlan{}, mydcp.ErrAdmission
	}
	return *reply.NodeForcePlan, nil
}
func (s Service) nodeForcePlanReply(ctx context.Context, view cluster.View, session access.Session, q control.NodeForceQuery) Reply {
	plan, err := s.Policy.PlanNodeForceRemoval(view.State, session, time.Now().Unix(), q)
	if err != nil {
		return Reply{Schema: 1, Code: "denied"}
	}
	if len(plan.Blockers) > 0 {
		return Reply{Schema: 1, Code: "ok", NodeForcePlan: &plan}
	}
	if s.NodeForceProbe == nil {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	probe, err := s.NodeForceProbe(ctx, view, plan)
	if err != nil {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	change := control.NodeForceChange{ID: q.Node, Operation: q.Operation, Epoch: plan.Epoch, Probe: probe}
	code := s.Policy.CheckNodeForceProbe(view.State, change, plan.Expected, probe.FinishedAt)
	if code != state.Applied {
		reason := state.RejectionReason(code)
		if reason == "" {
			return Reply{Schema: 1, Code: "conflict"}
		}
		plan.Blockers = append(plan.Blockers, control.NodeBlocker{Code: reason})
	}
	plan.Probe = &probe
	plan.Forceable = len(plan.Blockers) == 0
	return Reply{Schema: 1, Code: "ok", NodeForcePlan: &plan}
}
