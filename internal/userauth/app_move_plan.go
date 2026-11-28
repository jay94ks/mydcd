// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/observability"
	"github.com/jay94ks/seafield/internal/sfcp"
)

func (s Service) appPlanArtifact(ctx context.Context, view cluster.View, session access.Session, tenant string, r control.AppPlanRequest) ([]byte, error) {
	if r.Move == nil {
		return s.Policy.AppPlanArtifact(view.State, session, time.Now().Unix(), tenant, r)
	}
	if s.VolumeMoveObserver == nil {
		return nil, sfcp.ErrAdmission
	}
	before, err := s.Policy.AppMovePlanSource(view.State, session, time.Now().Unix(), tenant, r)
	if err != nil {
		return nil, err
	}
	witness, err := s.VolumeMoveObserver(ctx, before)
	if err != nil {
		return nil, err
	}
	var reports []observability.Report
	if s.NodeObservations != nil {
		// Unavailable measurements are explicit unknown; they never replace
		// the actual target space check or publish a fabricated zero value.
		reports, _, err = s.NodeObservations(ctx, view)
		if err != nil {
			reports = nil
		}
	}
	// The adapter may block or the leader may change. Use a fresh quorum view,
	// then validate the same materialization AND original shared writer again.
	latest, err := s.Engine.Read(ctx, true)
	if err != nil || latest.Local || !s.Engine.IsLeader() {
		return nil, sfcp.ErrAdmission
	}
	policy, err := s.Policy.Current(latest.State)
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	raw, err := policy.AppMovePlanArtifact(latest.State, session, now, tenant, r, witness)
	if err != nil {
		return nil, err
	}
	plan, err := control.DecodeAppMovePlan(raw)
	if err != nil {
		return nil, err
	}
	preflight, err := policy.VolumeMoveStoragePreflight(latest.State, session, uint64(time.Now().UnixMilli()), tenant, plan.Begin.Target.Node, plan.Begin.CapacityBytes, reports)
	if err != nil {
		return nil, err
	}
	plan.StoragePreflight = &preflight
	raw, err = json.Marshal(plan)
	if err == nil {
		_, err = control.DecodeAppMovePlan(raw)
	}
	return raw, err
}
