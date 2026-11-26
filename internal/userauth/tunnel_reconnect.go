// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"errors"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/mydcp"
)

func (s Service) tunnelQuery(ctx context.Context, view cluster.View, request Request, session access.Session) Reply {
	var err error
	out := Reply{Schema: 1, Code: "unavailable"}
	if request.Method == "tunnel-reconnect-plan" {
		if s.NodeObservations == nil {
			return out
		}
		reports, e := s.NodeObservations(ctx, view)
		if e != nil {
			return out
		}
		plan, e := s.Policy.PlanTunnelReconnect(view.State, session, time.Now().Unix(), *request.Tunnel, reports)
		err = e
		if err == nil {
			out.Code, out.TunnelPlan = "ok", &plan
		}
	} else {
		status, e := s.Policy.TunnelStatus(view.State, session, time.Now().Unix(), *request.Tunnel)
		err = e
		if err == nil {
			out.Code, out.TunnelStatus = "ok", &status
		}
	}
	if errors.Is(err, access.ErrDenied) || errors.Is(err, access.ErrInvalid) {
		out.Code = "denied"
	}
	if errors.Is(err, access.ErrConflict) {
		out.Code = "conflict"
	}
	return out
}
func (c Client) QueryTunnelReconnect(ctx context.Context, peer mydcp.Peer, session access.Session, plan bool, q control.TunnelQuery) (Reply, error) {
	if !q.Valid(plan) {
		return Reply{}, mydcp.ErrAdmission
	}
	method := "tunnel-reconnect-status"
	if plan {
		method = "tunnel-reconnect-plan"
	}
	reply, err := c.query(ctx, peer, session, Request{Method: method, Tunnel: &q})
	if err != nil {
		return reply, err
	}
	if plan {
		p := reply.TunnelPlan
		if p == nil || !p.Valid() || p.Cluster != c.Cluster || p.Node != q.Node || p.Peer != q.Peer {
			return Reply{}, mydcp.ErrFrame
		}
	} else {
		r := reply.TunnelStatus
		if r == nil || r.Schema != 1 || r.Operation != q.Operation || !r.Plan.Valid() || r.Plan.Cluster != c.Cluster || r.Revision == 0 || r.User == "" {
			return Reply{}, mydcp.ErrFrame
		}
		if r.State != "queued" && r.State != "running" && r.State != "done" && r.State != "failed" || (r.State == "done" || r.State == "failed") != (r.Result != nil) || r.Result != nil && (!r.Result.Valid(r.Plan) || (r.State == "failed") != (r.Result.State == "failed")) {
			return Reply{}, mydcp.ErrFrame
		}
	}
	return reply, nil
}
