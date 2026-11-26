// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/schema"
)

// Bind the quorum response to the SAME local committed policy, rather than
// consuming an old reconcile projection with a newer grant/report epoch.
func (r *Runtime) readRouteWork(ctx context.Context, request control.RouteWorkRequest) (cluster.View, control.ResourceProjection, control.RouteWork, error) {
	var view cluster.View
	var projection control.ResourceProjection
	var work control.RouteWork
	raw, err := json.Marshal(request)
	if err != nil {
		return view, projection, work, err
	}
	reply, err := r.appCall(ctx, "route-work", raw)
	if err != nil {
		return view, projection, work, err
	}
	work, err = schema.Decode[control.RouteWork](reply.Data)
	if err != nil || work.Schema != 1 || work.Reference.ID != request.Reference || work.Reference.Local.Owner != r.Identity.Public {
		return view, projection, work, errors.New("route work differs from original local owner")
	}
	view, err = r.Engine().ReadAtLeast(ctx, reply.CommandIndex)
	if err != nil {
		return view, projection, work, err
	}
	if view.State.ModuleEpoch() != work.Epoch || view.State.Object(control.ResourcesKey).Revision < work.ResourcesRevision || view.State.Object(control.AppsKey).Revision < work.AppsRevision {
		return view, projection, work, errors.New("route work epoch changed or roots precede quorum response")
	}
	projection, current, err := r.controlPolicy.ProjectRouteWork(view.State, r.commandIdentity().Public, request)
	if err != nil {
		return view, projection, work, err
	}
	if !sameRouteWorkPermission(work, current) {
		return view, projection, work, errors.New("route work permission or original reference changed before local readback")
	}
	return view, projection, current, nil
}

// Recompute all permissions on the committed readback before comparing. Only
// unrelated root advancement may differ; callers consume that CURRENT work
// together with its projection, never an old permission with newer roots.
func sameRouteWorkPermission(original, current control.RouteWork) bool {
	if current.ResourcesRevision < original.ResourcesRevision || current.AppsRevision < original.AppsRevision {
		return false
	}
	original.ResourcesRevision, original.AppsRevision = current.ResourcesRevision, current.AppsRevision
	a, err := json.Marshal(original)
	if err != nil {
		return false
	}
	b, err := json.Marshal(current)
	return err == nil && bytes.Equal(a, b)
}
