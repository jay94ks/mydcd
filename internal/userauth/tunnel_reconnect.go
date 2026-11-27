// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"errors"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// TunnelPlanQuery names one down server-to-server link to reconnect.
type TunnelPlanQuery struct{ Node, Peer string }

func (q TunnelPlanQuery) Valid() bool {
	return control.TunnelQuery{Node: q.Node, Peer: q.Peer}.Valid(true)
}

// TunnelStatusQuery names one recorded reconnect operation.
type TunnelStatusQuery struct{ Operation string }

func (q TunnelStatusQuery) Valid() bool {
	return control.TunnelQuery{Operation: q.Operation}.Valid(false)
}

func tunnelRefusal(err error) string {
	switch {
	case errors.Is(err, access.ErrDenied) || errors.Is(err, access.ErrInvalid):
		return "denied"
	case errors.Is(err, access.ErrConflict):
		return "conflict"
	}
	return "unavailable"
}

var (
	// TunnelReconnectPlanMethod plans the reconnect of a link the servers'
	// signed observations report down (system administrator).
	TunnelReconnectPlanMethod = define(Method[TunnelPlanQuery, control.TunnelPlan]{Name: "tunnel-reconnect-plan"}, false, func(ctx context.Context, s Service, view cluster.View, session access.Session, q TunnelPlanQuery) (control.TunnelPlan, string) {
		if s.NodeObservations == nil {
			return control.TunnelPlan{}, "unavailable"
		}
		reports, err := s.NodeObservations(ctx, view)
		if err != nil {
			return control.TunnelPlan{}, "unavailable"
		}
		plan, err := s.Policy.PlanTunnelReconnect(view.State, session, time.Now().Unix(), control.TunnelQuery{Node: q.Node, Peer: q.Peer}, reports)
		if err != nil {
			return control.TunnelPlan{}, tunnelRefusal(err)
		}
		return plan, "ok"
	})
	// TunnelReconnectStatusMethod reads one reconnect operation.
	TunnelReconnectStatusMethod = define(Method[TunnelStatusQuery, control.TunnelStatus]{Name: "tunnel-reconnect-status"}, false, func(_ context.Context, s Service, view cluster.View, session access.Session, q TunnelStatusQuery) (control.TunnelStatus, string) {
		status, err := s.Policy.TunnelStatus(view.State, session, time.Now().Unix(), control.TunnelQuery{Operation: q.Operation})
		if err != nil {
			return control.TunnelStatus{}, tunnelRefusal(err)
		}
		return status, "ok"
	})
)

func (c Client) TunnelReconnectPlan(ctx context.Context, peer sfcp.Peer, session access.Session, node, link string) (control.TunnelPlan, error) {
	p, err := call(ctx, c, peer, session, TunnelReconnectPlanMethod, TunnelPlanQuery{Node: node, Peer: link})
	if err != nil {
		return control.TunnelPlan{}, err
	}
	if !p.Valid() || p.Cluster != c.Cluster || p.Node != node || p.Peer != link {
		return control.TunnelPlan{}, sfcp.ErrFrame
	}
	return p, nil
}

func (c Client) TunnelReconnectStatus(ctx context.Context, peer sfcp.Peer, session access.Session, operation string) (control.TunnelStatus, error) {
	r, err := call(ctx, c, peer, session, TunnelReconnectStatusMethod, TunnelStatusQuery{Operation: operation})
	if err != nil {
		return control.TunnelStatus{}, err
	}
	if r.Schema != 1 || r.Operation != operation || !r.Plan.Valid() || r.Plan.Cluster != c.Cluster || r.Revision == 0 || r.User == "" {
		return control.TunnelStatus{}, sfcp.ErrFrame
	}
	if r.State != "queued" && r.State != "running" && r.State != "done" && r.State != "failed" || (r.State == "done" || r.State == "failed") != (r.Result != nil) || r.Result != nil && (!r.Result.Valid(r.Plan) || (r.State == "failed") != (r.Result.State == "failed")) {
		return control.TunnelStatus{}, sfcp.ErrFrame
	}
	return r, nil
}
