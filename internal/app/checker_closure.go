// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"time"

	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/workload"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
	contract "github.com/jay94ks/seafield/lifecycle/v1"
)

// Caller holds checkerRunMu: the synchronous checker child/calls have already
// joined. Only their original reader tokens remain eligible for cleanup.
func (r *Runtime) settleInterruptedChecker(ctx context.Context, p *checkerObservation) error {
	active := p.Checkpoint.Active
	if active == nil {
		return nil
	}
	if active.Phase == checker.Dispatched && r.workload != nil {
		// A pending native exec must not retain already joined client I/O
		// pins and deadlock the original container's down/removal.
		if err := r.workload.ReturnReadRun(ctx, active.Request); err != nil {
			return err
		}
	}
	var pending error
	if err := r.recoverCheckerExecs(ctx, p); err != nil {
		if !errors.Is(err, workload.ErrProbeExecPending) {
			return err
		}
		pending = err
	}
	if err := r.recoverCheckerRemotes(ctx, p); err != nil {
		if !errors.Is(err, errCheckerRemotePending) {
			return err
		}
		pending = errors.Join(pending, err)
	}
	if pending != nil {
		return pending
	}
	machine, err := checker.Restore(p.Checkpoint)
	if err != nil {
		return err
	}
	now := time.Now().UnixMilli()
	if active.Phase == checker.Prepared {
		machine, err = machine.CancelPrepared(active.Request.RunID, now)
	} else {
		if r.workload == nil {
			return checker.ErrPending
		}
		machine, _, err = machine.Finish(checker.Completion{RunID: active.Request.RunID, RequestDigest: active.RequestDigest, Result: contract.Result{Schema: 1, Status: contract.Unknown, Reason: "check-interrupted"}, At: now, HelperExited: true, ProbesClosed: true})
	}
	if err != nil {
		return err
	}
	p.Checkpoint = machine.Checkpoint()
	return r.saveCheckerObservation(*p)
}

// Called ONLY after the original Manager.Gone proof in CollectAppTaskClosure.
// Native Gone is not inferred from a script result or expired deadline.
// This retires checker metadata; it neither removes cache data nor returns a
// shared pin. The shared FSM consumes the subsequent signed original closure.
func (r *Runtime) retireTaskCheckers(ctx context.Context, task deployment.ObjectRef) error {
	if ctx == nil || r.reports == nil {
		return checker.ErrContract
	}
	r.checkerRunMu.Lock()
	defer r.checkerRunMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := r.reports.Sync(); err != nil {
		return err
	}
	rows, err := r.reports.ScanBounded(checkerObservationPrefix, maxCheckerObservationSlots, maxCheckerObservationTotal)
	if err != nil {
		return err
	}
	// Rebuild the bounded index after a prior ambiguous save/reopen. Known
	// records are never silently forgotten because a read is missing.
	if r.checkerObservationSizes == nil {
		r.checkerObservationSizes = map[string]int{}
	}
	for key := range r.checkerObservationSizes {
		if _, found := rows[key]; !found {
			return checker.ErrContract
		}
	}
	for key, raw := range rows {
		p, err := schema.Decode[checkerObservation](raw)
		if err != nil || len(raw) > maxCheckerObservationBytes || p.validate(r.controlPolicy.Cluster, r.Identity.Public) != nil || checkerObservationKey(p.Checkpoint.Definition) != key {
			return checker.ErrContract
		}
		r.checkerObservationSizes[key] = len(key) + len(raw)
		if p.Task != task {
			continue
		}
		if err = r.settleInterruptedChecker(ctx, &p); err != nil {
			return err
		}
		if p.Control != nil && !p.Control.Terminal() {
			c := *p.Control
			c.Phase = checker.ControlCanceled
			p.setControl(c)
			if err = r.saveCheckerObservation(p); err != nil {
				return err
			}
		}
		machine, err := checker.Restore(p.Checkpoint)
		if err != nil {
			return err
		}
		if machine.Closed() {
			continue
		}
		machine, err = machine.Retire()
		if err != nil || !machine.Closed() {
			return errors.Join(checker.ErrPending, err)
		}
		p.Checkpoint = machine.Checkpoint()
		if err = r.saveCheckerObservation(p); err != nil {
			return err
		}
	}
	return nil
}
