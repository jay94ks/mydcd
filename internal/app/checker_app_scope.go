// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/storage"
	"github.com/jay94ks/seafield/internal/workload"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
	contract "github.com/jay94ks/seafield/lifecycle/v1"
)

func (r *Runtime) loadAppScopeCheck(def checker.Definition, task deployment.ObjectRef, program [32]byte, check checker.ResolvedCheck) (appCheckerState, error) {
	key := checkerObservationKey(def)
	raw, err := r.reports.GetBounded(key, maxCheckerObservationBytes)
	var point checkerObservation
	var machine checker.Machine
	changed := false
	if errors.Is(err, storage.ErrMissing) {
		if _, known := r.checkerObservationSizes[key]; known {
			return appCheckerState{}, checker.ErrContract
		}
		machine, err = checker.New(def, time.Now().UnixMilli())
		changed = true
	} else if err == nil {
		point, err = schema.Decode[checkerObservation](raw)
		if err == nil {
			err = point.validate(r.controlPolicy.Cluster, r.Identity.Public)
		}
		if err == nil && (point.Control != nil || point.Previous != nil) {
			err = checker.ErrContract
		}
		if err == nil && point.Checkpoint.Active != nil {
			return appCheckerState{}, checker.ErrPending
		}
		if err == nil {
			machine, err = checker.Restore(point.Checkpoint)
		}
		if err == nil && point.Checkpoint.Definition.Digest() != def.Digest() {
			machine, err = machine.Retire()
			if err == nil {
				machine, err = machine.Replace(def, time.Now().UnixMilli())
			}
			changed = true
			point.Executions = nil
			point.RemoteCalls = nil
		}
	}
	if err != nil {
		return appCheckerState{}, err
	}
	point = checkerObservation{Schema: 1, Task: task, Program: program, Checkpoint: machine.Checkpoint(), Executions: point.Executions, RemoteCalls: point.RemoteCalls}
	if changed {
		if err = r.saveCheckerObservation(point); err != nil {
			return appCheckerState{}, err
		}
	}
	return appCheckerState{check: check, point: point, machine: machine}, nil
}

func aggregateAppCheckStates(program [32]byte, states []appCheckerState, now int64) (deployment.AppCheckResult, error) {
	result := deployment.AppCheckResult{Program: program, Status: contract.Pass}
	var samples []checker.Sample
	for _, s := range states {
		status := s.machine.Status(now)
		samples = append(samples, checker.Sample{Checker: s.check.ID, Phase: s.check.Phase, Status: status})
	}
	for _, phase := range []contract.Phase{contract.Readiness, contract.Liveness} {
		status, err := checker.Aggregate(phase, samples)
		if err != nil {
			return result, err
		}
		if status == contract.Fail {
			result.Status = contract.Fail
			break
		}
		if status == contract.Unknown {
			result.Status = contract.Unknown
		}
	}
	if result.Status == contract.Unknown {
		return result, nil
	}
	for _, s := range states {
		status := s.machine.Status(now)
		cp := s.machine.Checkpoint()
		if result.Status == contract.Fail && status != contract.Fail || s.check.Phase == contract.Startup && cp.EverPassed {
			continue
		}
		if cp.Last == nil {
			return result, checker.ErrContract
		}
		expiry := cp.Last.At + cp.Definition.Timing.FreshForMS
		if expiry <= cp.Last.At {
			return result, checker.ErrClock
		}
		if result.Status == contract.Fail {
			result.ValidUntil = max(result.ValidUntil, expiry)
		} else if result.ValidUntil == 0 || expiry < result.ValidUntil {
			result.ValidUntil = expiry
		}
	}
	if result.ValidUntil != 0 && result.ValidUntil <= now {
		result.Status, result.ValidUntil = contract.Unknown, 0
	}
	return result, nil
}

func (r *Runtime) observeAppScopeChecks(ctx context.Context, view cluster.View, b deployment.Binding, task deployment.ObjectRef, status workload.ContainerStatus) (*deployment.AppCheckResult, error) {
	p, err := r.checkerTaskProgram(view, b, task)
	if err != nil || p == nil || len(p.AppChecks) == 0 {
		return nil, err
	}
	apps, err := r.controlPolicy.ReadApps(view.State)
	if err != nil {
		return nil, err
	}
	use := b.Needs().Use
	execution, exists := apps.Execution(use.Tenant, use.App)
	if !exists {
		return nil, checker.ErrReference
	}
	if coordinator, required := execution.AppCheckTask(); required && coordinator != task.Key {
		return nil, nil
	}
	r.checkerRunMu.Lock()
	defer r.checkerRunMu.Unlock()
	if err = r.recoverCheckerObservationsLocked(ctx); err != nil {
		return nil, err
	}
	var states []appCheckerState
	for _, check := range p.AppChecks {
		if check.Phase == contract.Shutdown {
			continue
		}
		def, err := r.appCheckDefinition(view, b, task, *p, check, status)
		if err != nil {
			if errors.Is(err, checker.ErrReference) {
				return &deployment.AppCheckResult{Program: p.Program, Status: contract.Unknown}, nil
			}
			return nil, err
		}
		state, err := r.loadAppScopeCheck(def, task, p.Program, check)
		if err != nil {
			if errors.Is(err, checker.ErrPending) {
				return &deployment.AppCheckResult{Program: p.Program, Status: contract.Unknown}, nil
			}
			return nil, err
		}
		states = append(states, state)
	}
	if len(states) == 0 {
		return nil, nil
	}
	visited := make([]bool, len(states))
	for completed := 0; completed < len(states); completed++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		selected, err := nextAppChecker(states, time.Now().UnixMilli(), visited)
		if err != nil {
			return nil, err
		}
		if selected < 0 {
			break
		}
		visited[selected] = true
		s := &states[selected]
		planned, run, err := s.machine.Plan(time.Now().UnixMilli())
		if err != nil {
			return nil, err
		}
		r.checkerRecovered = false
		s.point.Executions = nil
		s.point.RemoteCalls = nil
		s.point.Checkpoint = planned.Checkpoint()
		if err = r.saveCheckerObservation(s.point); err != nil {
			return nil, err
		}
		s.machine, err = planned.Dispatch(run.Request.RunID)
		if err != nil {
			return nil, err
		}
		s.point.Checkpoint = s.machine.Checkpoint()
		if err = r.saveCheckerObservation(s.point); err != nil {
			return nil, err
		}
		result, closed, runErr := r.runAppCheck(ctx, b, task, *p, s.check, run.Request, status, true, &s.point)
		if !closed {
			return nil, errors.Join(checker.ErrPending, runErr)
		}
		if runErr != nil && (checker.ValidateResult(result) != nil || result.Status != contract.Unknown) {
			result = contract.Result{Schema: 1, Status: contract.Unknown, Reason: "check-error"}
		}
		s.machine, _, err = s.machine.Finish(checker.Completion{RunID: run.Request.RunID, RequestDigest: run.RequestDigest, Result: result, At: time.Now().UnixMilli(), HelperExited: true, ProbesClosed: true})
		if err != nil {
			return nil, err
		}
		s.point.Checkpoint = s.machine.Checkpoint()
		if err = r.saveCheckerObservation(s.point); err != nil {
			return nil, err
		}
	}
	result, err := aggregateAppCheckStates(p.Program, states, time.Now().UnixMilli())
	return &result, err
}
