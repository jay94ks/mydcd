// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"maps"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// Health renewals stay out of Raft (devel/refactor/14-raft-liveness.md). An
// owner whose stage facts are unchanged sends the re-signed observation to the
// leader over SFCP; the leader keeps the last renewal in memory and records
// an expiry in Raft only when renewals stop.
//
// A changed fact is reported at once, so renewals only prove the owner's loop
// still runs. While the owner and the leader stay connected (same leader, same
// term, no gap in the SFCP connection since the last renewal) both sides use
// AppObservationLinkedMaxAge instead of AppObservationMaxAge: the owner renews
// every 150s instead of every 15s, and the leader expires after 300s instead
// of 30s. Any break falls back to the short window on both sides. The cost:
// an owner whose connection stays up but whose reconcile loop has stopped is
// noticed only after up to 300s (5 minutes) instead of 30s.

// observationRenewal is the last renewal of the stored observation with
// sequence base.
type observationRenewal struct {
	base, at uint64
	link     leaderLink // owner: the leader link the renewal was sent over
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

// renewalFresh reports whether the owner can still skip renewing o: its last
// fact or renewal is younger than half the window the leader will apply.
func (r *Runtime) renewalFresh(o deployment.Observation, now uint64) bool {
	at := r.renewedAt(o)
	if at > now {
		return false
	}
	limit := control.AppObservationMaxAge / 2
	r.renewMu.Lock()
	n, ok := r.renewSent[o.Key]
	r.renewMu.Unlock()
	if ok && n.base == o.Sequence {
		if l, linked := r.leaderLink(); linked && l.heldSince(n.link, time.Unix(int64(n.at), 0)) {
			limit = control.AppObservationLinkedMaxAge / 2
		}
	}
	return now-at < limit
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
	link, _ := r.leaderLink()
	raw, _ := json.Marshal(report)
	if err = r.sendAppRenewal(ctx, raw); err != nil {
		// No Raft fallback on purpose: a lost renewal only lets the leader
		// expire the stage once, and the owner's next pass revives it with a
		// fresh observe.
		return true, err
	}
	r.renewMu.Lock()
	if r.renewSent == nil {
		r.renewSent = map[string]observationRenewal{}
	}
	r.renewSent[report.Key] = observationRenewal{base: stage.Observation.Sequence, at: report.Observation.At, link: link}
	r.renewMu.Unlock()
	return true, nil
}

// sendAppRenewal hands a renewal to the leader as an Observation report
// (KindAppRenewal), or admits it here when this node leads. A renewal is a
// liveness signal, so it never goes through a signed Management read.
func (r *Runtime) sendAppRenewal(ctx context.Context, raw []byte) error {
	if r.Engine().IsLeader() {
		v, err := r.currentView(ctx)
		if err != nil {
			return err
		}
		_, err = r.admitObservationRenewal(raw, v)
		return err
	}
	peer, err := r.leaderPeer(ctx)
	if err != nil {
		return err
	}
	session, err := r.Mesh.Dial(ctx, peer)
	if err != nil {
		return err
	}
	return session.Report(ctx, sfcp.KindAppRenewal, raw)
}

// receiveAppRenewal is the leader side of a KindAppRenewal report. The
// renewal is checked on a latest view; any other node refuses it.
func (r *Runtime) receiveAppRenewal(ctx context.Context, _ *sfcp.Session, raw []byte) error {
	if !r.Engine().IsLeader() {
		return sfcp.ErrAdmission
	}
	v, err := r.currentView(ctx)
	if err != nil {
		return err
	}
	_, err = r.admitObservationRenewal(raw, v)
	return err
}

// admitObservationRenewal checks and remembers a renewal on the leader.
func (r *Runtime) admitObservationRenewal(input []byte, v cluster.View) (json.RawMessage, error) {
	report, err := schema.Decode[control.AppProgress](input)
	if err != nil || v.Local || !r.Engine().IsLeader() {
		return nil, sfcp.ErrAdmission
	}
	now := uint64(time.Now().Unix())
	if !access.Recent(report.At, now, control.AppObservationMaxAge) {
		return nil, sfcp.ErrAdmission
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
	// admitObservationRenewal writes the map under renewMu; read a copy.
	since, seen := r.leaderSince, maps.Clone(r.renewSeen)
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
			limit := control.AppObservationMaxAge
			if r.ownerLinkedSince(o.Owner, time.Unix(int64(last), 0)) {
				limit = control.AppObservationLinkedMaxAge
			}
			if now <= last+limit || now-o.At <= control.AppObservationMaxAge {
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
