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

func (s Service) cdTogglePlan(view cluster.View, request Request, session access.Session) Reply {
	plan, err := s.Policy.PlanCDToggle(view.State, session, time.Now().Unix(), request.Tenant, *request.CDToggle)
	if err == nil {
		return Reply{Schema: 1, Code: "ok", CDTogglePlan: &plan}
	}
	if errors.Is(err, access.ErrDenied) {
		return Reply{Schema: 1, Code: "denied"}
	}
	if errors.Is(err, access.ErrConflict) {
		return Reply{Schema: 1, Code: "conflict"}
	}
	return Reply{Schema: 1, Code: "unavailable"}
}
func (c Client) PlanCDToggle(ctx context.Context, peer mydcp.Peer, session access.Session, tenant string, q control.CDToggleQuery) (control.CDTogglePlan, error) {
	var out control.CDTogglePlan
	if tenant == "" || !q.Valid() {
		return out, mydcp.ErrAdmission
	}
	reply, err := c.query(ctx, peer, session, Request{Method: "app-cd-toggle-plan", Tenant: tenant, CDToggle: &q})
	if err != nil {
		return out, err
	}
	p := reply.CDTogglePlan
	if p == nil || p.Schema != 1 || p.Tenant != tenant || p.App != q.App || p.Action != q.Action || p.Expected == 0 || p.Epoch == 0 || p.WouldPause != (q.Action == "pause-app-cd") || !p.PreservesOriginal {
		return out, mydcp.ErrFrame
	}
	return *p, nil
}
