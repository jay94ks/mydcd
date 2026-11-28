// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"errors"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/sfcp"
	"time"
)

// NodeDrainStatusQuery selects a drain's status; Operation may be empty for
// the node's latest original drain.
type NodeDrainStatusQuery control.NodeDrainQuery

func (q NodeDrainStatusQuery) Valid() bool { return control.NodeDrainQuery(q).ValidStatus() }

func (c Client) NodeDrainPlan(ctx context.Context, peer sfcp.Peer, session access.Session, q control.NodeDrainQuery) (control.NodeDrainPlan, error) {
	if !q.Valid() {
		return control.NodeDrainPlan{}, access.ErrInvalid
	}
	plan, err := call(ctx, c, peer, session, NodeDrainPlanMethod, q)
	if err != nil {
		return control.NodeDrainPlan{}, err
	}
	if plan.Node != q.Node || plan.Operation != q.Operation {
		return control.NodeDrainPlan{}, sfcp.ErrAdmission
	}
	return plan, nil
}

func (c Client) NodeDrainStatus(ctx context.Context, peer sfcp.Peer, session access.Session, q control.NodeDrainQuery) (control.NodeDrainStatus, error) {
	if !q.ValidStatus() {
		return control.NodeDrainStatus{}, access.ErrInvalid
	}
	status, err := call(ctx, c, peer, session, NodeDrainStatusMethod, NodeDrainStatusQuery(q))
	if err != nil {
		return control.NodeDrainStatus{}, err
	}
	if status.Node != q.Node || !(control.NodeDrainQuery{Node: status.Node, Operation: status.Operation}).Valid() || q.Operation != "" && status.Operation != q.Operation {
		return control.NodeDrainStatus{}, sfcp.ErrAdmission
	}
	return status, nil
}

var (
	NodeDrainPlanMethod = define(Method[control.NodeDrainQuery, control.NodeDrainPlan]{Name: "node-drain-plan"}, true, func(ctx context.Context, s Service, view cluster.View, session access.Session, q control.NodeDrainQuery) (control.NodeDrainPlan, string) {
		if !s.manageCluster(view, session) {
			return control.NodeDrainPlan{}, "denied"
		}
		var plan control.NodeDrainPlan
		var err error
		if s.NodeDrainPlanner != nil {
			plan, err = s.NodeDrainPlanner(ctx, view, session, time.Now().Unix(), q)
		} else {
			plan, err = s.Policy.PlanNodeDrain(view.State, session, time.Now().Unix(), q)
		}
		if err != nil {
			return control.NodeDrainPlan{}, "denied"
		}
		return plan, "ok"
	})
	NodeDrainStatusMethod = define(Method[NodeDrainStatusQuery, control.NodeDrainStatus]{Name: "node-drain-status"}, true, func(_ context.Context, s Service, view cluster.View, session access.Session, q NodeDrainStatusQuery) (control.NodeDrainStatus, string) {
		if !s.manageCluster(view, session) {
			return control.NodeDrainStatus{}, "denied"
		}
		status, err := s.Policy.NodeDrainStatus(view.State, session, time.Now().Unix(), control.NodeDrainQuery(q))
		if errors.Is(err, control.ErrNoNodeDrain) {
			return control.NodeDrainStatus{}, "missing"
		}
		if err != nil {
			return control.NodeDrainStatus{}, "denied"
		}
		return status, "ok"
	})
)

// manageCluster says whether the verified session may manage the cluster now.
func (s Service) manageCluster(view cluster.View, session access.Session) bool {
	c, err := s.Policy.Catalog(view.State)
	return err == nil && c.AuthorizeSession(session, s.Policy.Cluster, s.Policy.Issuer(session.Issuer), time.Now().Unix(), "", access.ManageCluster, "") == nil
}
