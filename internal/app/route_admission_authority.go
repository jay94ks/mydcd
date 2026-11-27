// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// Private to ONE source packet admission. Only a successful source-local
// native observation sets work/minimum, after that call's own latest quorum.
// No durable/global permission cache or cross-request reuse exists.
type routeAdmissionAuthority struct {
	work    control.RouteWork
	minimum uint64
	until   time.Time
}

func (a routeAdmissionAuthority) allows(ctx context.Context, owner [32]byte, index uint64, current control.RouteWork, now time.Time) bool {
	return ctx.Err() == nil && a.minimum > 0 && index >= a.minimum && now.Before(a.until) &&
		a.work.Schema == 1 && a.work.Epoch > 0 && a.work.PrepareAllowed &&
		a.work.Reference.Local.Owner == owner && sameRouteWorkPermission(a.work, current)
}

// Caller holds routeMu. A current committed readback may only narrow/reject
// the SAME request's fresh authority; it cannot renew its floor or deadline.
func (r *Runtime) readRouteAdmissionAuthority(ctx context.Context, admission routeAdmissionAuthority, caller [32]byte) (cluster.View, control.ResourceProjection, control.RouteWork, error) {
	var projection control.ResourceProjection
	var work control.RouteWork
	view, err := r.Engine().Read(ctx, false)
	if err != nil {
		return view, projection, work, err
	}
	projection, work, err = r.controlPolicy.ProjectRouteWork(view.State, r.commandIdentity().Public, control.RouteWorkRequest{Reference: admission.work.Reference.ID, At: time.Now().Unix()})
	if err != nil {
		return view, projection, work, err
	}
	if err := r.validateRouteFlowCaller(view, work, caller); err != nil {
		return view, projection, work, err
	}
	if err := r.tenantIsolationReady(view, projection); err != nil {
		return view, projection, work, err
	}
	if !admission.allows(ctx, r.Identity.Public, view.State.Index(), work, time.Now()) {
		return view, projection, work, sfcp.ErrAdmission
	}
	return view, projection, work, nil
}
