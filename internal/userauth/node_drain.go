// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"time"
)

func (c Client) NodeDrainPlan(ctx context.Context, peer mydcp.Peer, session access.Session, q control.NodeDrainQuery) (control.NodeDrainPlan, error) {
	if !q.Valid() {
		return control.NodeDrainPlan{}, access.ErrInvalid
	}
	reply, err := c.query(ctx, peer, session, Request{Method: "node-drain-plan", NodeDrain: &q})
	if err != nil {
		return control.NodeDrainPlan{}, err
	}
	if reply.NodeDrainPlan == nil || reply.NodeDrainPlan.Node != q.Node || reply.NodeDrainPlan.Operation != q.Operation {
		return control.NodeDrainPlan{}, mydcp.ErrAdmission
	}
	return *reply.NodeDrainPlan, nil
}
func (c Client) NodeDrainStatus(ctx context.Context, peer mydcp.Peer, session access.Session, q control.NodeDrainQuery) (control.NodeDrainStatus, error) {
	if !q.ValidStatus() {
		return control.NodeDrainStatus{}, access.ErrInvalid
	}
	reply, err := c.query(ctx, peer, session, Request{Method: "node-drain-status", NodeDrain: &q})
	if err != nil {
		return control.NodeDrainStatus{}, err
	}
	if reply.NodeDrainStatus == nil || reply.NodeDrainStatus.Node != q.Node || !(control.NodeDrainQuery{Node: reply.NodeDrainStatus.Node, Operation: reply.NodeDrainStatus.Operation}).Valid() || q.Operation != "" && reply.NodeDrainStatus.Operation != q.Operation {
		return control.NodeDrainStatus{}, mydcp.ErrAdmission
	}
	return *reply.NodeDrainStatus, nil
}
func (s Service) nodeDrainReply(ctx context.Context, view cluster.View, session access.Session, request Request) Reply {
	if request.NodeDrain == nil {
		return Reply{Schema: 1, Code: "denied"}
	}
	if request.Method == "node-drain-status" {
		status, err := s.Policy.NodeDrainStatus(view.State, session, time.Now().Unix(), *request.NodeDrain)
		if err != nil {
			return Reply{Schema: 1, Code: "denied"}
		}
		return Reply{Schema: 1, Code: "ok", NodeDrainStatus: &status}
	}
	var plan control.NodeDrainPlan
	var err error
	if s.NodeDrainPlanner != nil {
		plan, err = s.NodeDrainPlanner(ctx, view, session, time.Now().Unix(), *request.NodeDrain)
	} else {
		plan, err = s.Policy.PlanNodeDrain(view.State, session, time.Now().Unix(), *request.NodeDrain)
	}
	if err != nil {
		return Reply{Schema: 1, Code: "denied"}
	}
	return Reply{Schema: 1, Code: "ok", NodeDrainPlan: &plan}
}
