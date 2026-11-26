// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"encoding/json"
	"time"

	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/schema"
)

func parseAppInstance(stamp string) (int64, error) {
	t, err := time.Parse(time.RFC3339Nano, stamp)
	if err != nil || t.IsZero() || t.UnixNano() <= 0 || !time.Unix(0, t.UnixNano()).Equal(t) {
		return 0, deployment.ErrInputs
	}
	return t.UnixNano(), nil
}

func (r *Runtime) checkerRestartEvidence(stage deployment.StageRecord, started int64) (*deployment.TaskRestart, error) {
	old := stage.Observation
	if old == nil {
		return nil, nil
	}
	before := old.StartedAt
	if before == 0 && old.Exit != nil {
		before = old.Exit.StartedAt
	}
	if before == 0 || before == started {
		if old.Restart != nil {
			proof := old.Restart.Clone()
			return &proof, nil
		}
		return nil, nil
	}
	if r.reports == nil || stage.Result == nil {
		return nil, deployment.ErrInputs
	}
	r.checkerRunMu.Lock()
	defer r.checkerRunMu.Unlock()
	rows, err := r.reports.ScanBounded(checkerObservationPrefix, maxCheckerObservationSlots, maxCheckerObservationTotal)
	if err != nil {
		return nil, err
	}
	var found *deployment.TaskRestart
	for _, raw := range rows {
		p, err := schema.Decode[checkerObservation](raw)
		if err != nil || p.validate(r.controlPolicy.Cluster, r.Identity.Public) != nil {
			return nil, deployment.ErrInputs
		}
		if p.Task.Key != stage.Key || p.Task.Generation != stage.Result.Generation || p.Task.Revision != stage.Result.Revision {
			continue
		}
		proof := p.Previous
		if proof == nil {
			continue
		}
		c := proof.Control
		stamp, err := parseAppInstance(c.Target.StartedAt)
		if err != nil || stamp != before || c.Target.NativeID != old.Native {
			continue
		}
		copy := proof.Clone()
		if old.Exit != nil {
			exit := *old.Exit
			copy.PreviousExit = &exit
		}
		if found != nil {
			a, _ := json.Marshal(found)
			b, _ := json.Marshal(copy)
			if !bytes.Equal(a, b) {
				return nil, deployment.ErrInputs
			}
		}
		found = &copy
	}
	engine := r.Engine()
	if engine == nil {
		// No quorum to read an operator restart from (tests without a
		// cluster). The local receipt alone is the only evidence then.
		if found != nil {
			return found, nil
		}
		return nil, deployment.ErrInputs
	}
	current, err := engine.Read(r.ctx, false)
	if err != nil {
		return nil, err
	}
	apps, err := r.controlPolicy.ReadApps(current.State)
	if err != nil {
		return nil, err
	}
	for _, row := range apps.TaskRestartEvidence(r.Identity.Public, stage.Key, old.Native, stage.Result.Generation, stage.Result.Revision, time.Unix(0, before).UTC().Format(time.RFC3339Nano)) {
		initial, err := row.InitialControl()
		if err != nil {
			return nil, err
		}
		receipt, err := r.readTaskRestartReceipt(initial)
		if err != nil {
			return nil, err
		}
		proof := row.RestartEvidence()
		if proof == nil || proof.Control != receipt.Control {
			continue
		}
		if old.Exit != nil {
			exit := *old.Exit
			proof.PreviousExit = &exit
		}
		if found != nil {
			return nil, deployment.ErrInputs // two committed restarts for one instance
		}
		found = proof
	}
	if found == nil {
		return nil, deployment.ErrInputs
	}
	return found, nil
}
