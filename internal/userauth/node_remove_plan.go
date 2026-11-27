// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"errors"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// NodeRemovePlan reads the same reducer-owned blockers used by remove-node.
// Reading it neither reserves removal nor turns the result into a permission:
// the original signed change still checks exact Expected and Epoch at commit.
func (c Client) NodeRemovePlan(ctx context.Context, peer sfcp.Peer, session access.Session, node string) (control.NodeRemovePlan, error) {
	if !lifecycle.ValidID(node) {
		return control.NodeRemovePlan{}, access.ErrInvalid
	}
	plan, err := call(ctx, c, peer, session, NodeRemovePlanMethod, NodeQuery{Node: node})
	if err != nil {
		return control.NodeRemovePlan{}, err
	}
	if plan.Node != node || plan.Schema != 1 {
		return control.NodeRemovePlan{}, sfcp.ErrAdmission
	}
	return plan, nil
}

func (c Client) NodeDemotePlan(ctx context.Context, peer sfcp.Peer, session access.Session, node string) (control.NodeVotingPlan, error) {
	if !lifecycle.ValidID(node) {
		return control.NodeVotingPlan{}, access.ErrInvalid
	}
	plan, err := call(ctx, c, peer, session, NodeDemotePlanMethod, NodeQuery{Node: node})
	if err != nil {
		return control.NodeVotingPlan{}, err
	}
	if plan.Node != node || plan.Schema != 1 {
		return control.NodeVotingPlan{}, sfcp.ErrAdmission
	}
	return plan, nil
}

var (
	NodeRemovePlanMethod = define(Method[NodeQuery, control.NodeRemovePlan]{Name: "node-remove-plan"}, true, func(_ context.Context, s Service, view cluster.View, session access.Session, q NodeQuery) (control.NodeRemovePlan, string) {
		if !s.manageCluster(view, session) {
			return control.NodeRemovePlan{}, "denied"
		}
		plan, err := s.Policy.PlanNodeRemoval(view.State, session, time.Now().Unix(), q.Node)
		return plan, planCode(err)
	})
	NodeDemotePlanMethod = define(Method[NodeQuery, control.NodeVotingPlan]{Name: "node-demote-plan"}, true, func(_ context.Context, s Service, view cluster.View, session access.Session, q NodeQuery) (control.NodeVotingPlan, string) {
		if !s.manageCluster(view, session) {
			return control.NodeVotingPlan{}, "denied"
		}
		plan, err := s.Policy.PlanNodeDemotion(view.State, session, time.Now().Unix(), q.Node)
		return plan, planCode(err)
	})
)

func planCode(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, access.ErrDenied) || errors.Is(err, access.ErrInvalid):
		return "denied"
	}
	return "unavailable"
}
