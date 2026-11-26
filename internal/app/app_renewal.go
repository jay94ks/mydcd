// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/schema"
)

// Health renewals stay out of Raft (devel/refactor/14-raft-liveness.md). An
// owner whose stage facts are unchanged sends the re-signed observation to the
// leader over MyDCP; the leader keeps the last renewal in memory and records
// an expiry in Raft only when renewals stop.

// observationRenewal is the last renewal of the stored observation with
// sequence base.
type observationRenewal struct {
	base, at uint64
}

// renewedAt returns when o's owner last renewed it, or o.At.
func (r *Runtime) renewedAt(o deployment.Observation) uint64 {
	r.renewMu.Lock()
	defer r.renewMu.Unlock()
	if n, ok := r.renewSent[o.Key]; ok && n.base == o.Sequence {
		return max(o.At, n.at)
	}
	return o.At
}

// renewAppObservation sends report to the leader as a renewal when its
// observation only renews the stored fact. It reports false when the report
// carries a new fact (or revives an expired one) that Raft must record.
func (r *Runtime) renewAppObservation(ctx context.Context, report control.AppProgress) (bool, error) {
	v, err := r.Engine().Read(ctx, false)
	if err != nil {
		return false, err
	}
	apps, err := r.controlPolicy.Apps(v.State)
	if err != nil {
		return false, err
	}
	e, ok := apps.Execution(report.Tenant, report.App)
	if !ok {
		return false, nil
	}
	stage, ok := e.Stage(report.Key)
	if !ok || stage.Observation == nil || stage.Observation.Expired || !deployment.ObservationRenews(*stage.Observation, *report.Observation) {
		return false, nil
	}
	raw, _ := json.Marshal(report)
	if _, err = r.appCall(ctx, "app-observation-renew", raw); err != nil {
		// No Raft fallback on purpose: a lost renewal only lets the leader
		// expire the stage once, and the owner's next pass revives it with a
		// fresh observe.
		return true, err
	}
	r.renewMu.Lock()
	if r.renewSent == nil {
		r.renewSent = map[string]observationRenewal{}
	}
	r.renewSent[report.Key] = observationRenewal{base: stage.Observation.Sequence, at: report.Observation.At}
	r.renewMu.Unlock()
	return true, nil
}

// admitObservationRenewal is the leader side of app-observation-renew.
func (r *Runtime) admitObservationRenewal(input []byte, v cluster.View) (json.RawMessage, error) {
	report, err := schema.Decode[control.AppProgress](input)
	if err != nil || v.Local || !r.Engine().IsLeader() {
		return nil, mydcp.ErrAdmission
	}
	now := uint64(time.Now().Unix())
	if report.At > now || now-report.At > control.AppObservationMaxAge {
		return nil, mydcp.ErrAdmission
	}
	base, err := r.controlPolicy.CheckObservationRenewal(v.State, report, now)
	if err != nil {
		return nil, err
	}
	r.renewMu.Lock()
	if r.renewSeen == nil {
		r.renewSeen = map[string]observationRenewal{}
	}
	key := report.Tenant + "/" + report.App + "/" + report.Key
	if old, ok := r.renewSeen[key]; !ok || old.base != base || old.at < report.Observation.At {
		r.renewSeen[key] = observationRenewal{base: base, at: report.Observation.At}
	}
	r.renewMu.Unlock()
	return json.Marshal(struct{}{})
}

// expireAppObservations runs on the leader. It marks one observation Expired
// whose owner sent neither a new fact nor a renewal for AppObservationMaxAge,
// counting from when this node became leader at the earliest. One Raft write
// per outage; the owner's next fact clears it.
func (r *Runtime) expireAppObservations(ctx context.Context, v cluster.View, apps control.Apps) error {
	now := uint64(time.Now().Unix())
	r.renewMu.Lock()
	if !r.Engine().IsLeader() {
		r.leaderSince, r.renewSeen = 0, nil
		r.renewMu.Unlock()
		return nil
	}
	if r.leaderSince == 0 {
		r.leaderSince = now
	}
	since, seen := r.leaderSince, r.renewSeen
	r.renewMu.Unlock()
	for _, app := range apps.Records() {
		e, ok := apps.Execution(app.Tenant, app.App)
		if !ok || e.ActiveOperation() != app.Operation.ID {
			continue
		}
		for _, step := range e.Steps() {
			stage, ok := e.Stage(step.Key)
			if !ok || stage.Observation == nil || stage.Observation.Expired {
				continue
			}
			o := stage.Observation
			last := max(o.At, since)
			if n, ok := seen[app.Tenant+"/"+app.App+"/"+step.Key]; ok && n.base == o.Sequence {
				last = max(last, n.at)
			}
			if now <= last+control.AppObservationMaxAge || now-o.At <= control.AppObservationMaxAge {
				continue
			}
			report := r.newAppProgress(v, app, "expire-observation", step.Key, nil)
			report.ExpireSequence = o.Sequence
			// Each expiry moves the app revision; the next one waits for the
			// next pass so it is planned on the new revision.
			_, err := r.sendAppProgressAt(ctx, report)
			return err
		}
	}
	return nil
}
