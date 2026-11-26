// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"errors"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/mydcp"
)

// NodeRemovePlan reads the same reducer-owned blockers used by remove-node.
// Reading it neither reserves removal nor turns the result into a permission:
// the original signed change still checks exact Expected and Epoch at commit.
func (c Client) NodeRemovePlan(ctx context.Context, peer mydcp.Peer, session access.Session, node string) (control.NodeRemovePlan, error) {
	if !lifecycle.ValidID(node) {
		return control.NodeRemovePlan{}, access.ErrInvalid
	}
	reply, err := c.query(ctx, peer, session, Request{Method: "node-remove-plan", Node: node})
	if err != nil {
		return control.NodeRemovePlan{}, err
	}
	if reply.Code != "ok" || reply.NodeRemovePlan == nil || reply.NodeRemovePlan.Node != node || reply.NodeRemovePlan.Schema != 1 {
		return control.NodeRemovePlan{}, mydcp.ErrAdmission
	}
	return *reply.NodeRemovePlan, nil
}
func (s Service) nodeRemovePlanReply(view cluster.View, session access.Session, request Request) Reply {
	if request.Method == "node-demote-plan" {
		plan, err := s.Policy.PlanNodeDemotion(view.State, session, time.Now().Unix(), request.Node)
		if err != nil {
			code := "unavailable"
			if errors.Is(err, access.ErrDenied) || errors.Is(err, access.ErrInvalid) {
				code = "denied"
			}
			return Reply{Schema: 1, Code: code}
		}
		return Reply{Schema: 1, Code: "ok", NodeVotingPlan: &plan}
	}
	plan, err := s.Policy.PlanNodeRemoval(view.State, session, time.Now().Unix(), request.Node)
	if err != nil {
		code := "unavailable"
		if errors.Is(err, access.ErrDenied) || errors.Is(err, access.ErrInvalid) {
			code = "denied"
		}
		return Reply{Schema: 1, Code: code}
	}
	return Reply{Schema: 1, Code: "ok", NodeRemovePlan: &plan}
}

func (c Client) NodeDemotePlan(ctx context.Context, peer mydcp.Peer, session access.Session, node string) (control.NodeVotingPlan, error) {
	if !lifecycle.ValidID(node) {
		return control.NodeVotingPlan{}, access.ErrInvalid
	}
	reply, err := c.query(ctx, peer, session, Request{Method: "node-demote-plan", Node: node})
	if err != nil {
		return control.NodeVotingPlan{}, err
	}
	if reply.Code != "ok" || reply.NodeVotingPlan == nil || reply.NodeVotingPlan.Node != node || reply.NodeVotingPlan.Schema != 1 {
		return control.NodeVotingPlan{}, mydcp.ErrAdmission
	}
	return *reply.NodeVotingPlan, nil
}
