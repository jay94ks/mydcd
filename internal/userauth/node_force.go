// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/sfcp"
)

func (c Client) NodeForceRemovePlan(ctx context.Context, peer sfcp.Peer, session access.Session, q control.NodeForceQuery) (control.NodeForcePlan, error) {
	if !q.Valid() {
		return control.NodeForcePlan{}, access.ErrInvalid
	}
	plan, err := call(ctx, c, peer, session, NodeForceRemovePlanMethod, q)
	if err != nil {
		return control.NodeForcePlan{}, err
	}
	if plan.Node != q.Node || plan.Operation != q.Operation || plan.Schema != 1 {
		return control.NodeForcePlan{}, sfcp.ErrAdmission
	}
	return plan, nil
}

var NodeForceRemovePlanMethod = define(Method[control.NodeForceQuery, control.NodeForcePlan]{Name: "node-force-remove-plan"}, true, func(ctx context.Context, s Service, view cluster.View, session access.Session, q control.NodeForceQuery) (control.NodeForcePlan, string) {
	if !s.manageCluster(view, session) {
		return control.NodeForcePlan{}, "denied"
	}
	plan, err := s.Policy.PlanNodeForceRemoval(view.State, session, time.Now().Unix(), q)
	if err != nil {
		return control.NodeForcePlan{}, "denied"
	}
	if len(plan.Blockers) > 0 {
		return plan, "ok"
	}
	if s.NodeForceProbe == nil {
		return control.NodeForcePlan{}, "unavailable"
	}
	probe, err := s.NodeForceProbe(ctx, view, plan)
	if err != nil {
		return control.NodeForcePlan{}, "unavailable"
	}
	change := control.NodeForceChange{ID: q.Node, Operation: q.Operation, Epoch: plan.Epoch, Probe: probe}
	code := s.Policy.CheckNodeForceProbe(view.State, change, plan.Expected, probe.FinishedAt)
	if code != state.Applied {
		reason := state.RejectionReason(code)
		if reason == "" {
			return control.NodeForcePlan{}, "conflict"
		}
		plan.Blockers = append(plan.Blockers, control.NodeBlocker{Code: reason})
	}
	plan.Probe = &probe
	plan.Forceable = len(plan.Blockers) == 0
	return plan, "ok"
})
