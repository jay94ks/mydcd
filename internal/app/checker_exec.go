// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"slices"

	"github.com/jay94ks/seafield/internal/workload"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
)

func (p checkerObservation) validateExecutions() error {
	if len(p.Executions) == 0 {
		return nil
	}
	if len(p.Executions) > checker.MaxProbeCalls {
		return checker.ErrContract
	}
	run := p.Checkpoint.Active
	if run == nil && p.Checkpoint.Last != nil {
		run = &p.Checkpoint.Last.Run
	}
	if run == nil || run.Phase != checker.Dispatched {
		return checker.ErrContract
	}
	seen := map[[32]byte]bool{}
	for _, e := range p.Executions {
		if e.Validate(run.Request) != nil || seen[e.Call] || p.Checkpoint.Active == nil && !e.Terminal() {
			return checker.ErrContract
		}
		seen[e.Call] = true
	}
	return nil
}

// Called under ServiceProbe's exec mutex while the polling owner holds
// checkerRunMu. Publish to the caller only after the same row saves.
func (r *Runtime) saveCheckerExec(p *checkerObservation, next workload.ProbeExecReceipt) error {
	if p == nil || p.Checkpoint.Active == nil || p.Checkpoint.Active.Phase != checker.Dispatched || next.Validate(p.Checkpoint.Active.Request) != nil {
		return checker.ErrContract
	}
	candidate := *p
	candidate.Executions = slices.Clone(p.Executions)
	index := -1
	for i, old := range candidate.Executions {
		if old.Call != next.Call {
			continue
		}
		if next.Phase == workload.ProbeExecCreating {
			return checker.ErrPending
		}
		if !next.CanFollow(old) {
			return checker.ErrContract
		}
		index = i
	}
	if index < 0 {
		if next.Phase != workload.ProbeExecCreating {
			return checker.ErrContract
		}
		candidate.Executions = append(candidate.Executions, next)
	} else {
		candidate.Executions[index] = next
	}
	if err := r.saveCheckerObservation(candidate); err != nil {
		return err
	}
	*p = candidate
	return nil
}

// No new SDK effect is permitted here. Original reader I/O is already joined
// and its pin cleanup does not imply the native exec has terminated.
func (r *Runtime) recoverCheckerExecs(ctx context.Context, p *checkerObservation) error {
	var result error
	for _, e := range slices.Clone(p.Executions) {
		if e.Terminal() {
			continue
		}
		if r.workload == nil {
			return workload.ErrProbeExecPending
		}
		err := r.workload.RecoverProbeExec(ctx, p.Checkpoint.Active.Request, e, func(next workload.ProbeExecReceipt) error { return r.saveCheckerExec(p, next) })
		if err != nil && !errors.Is(err, workload.ErrProbeExecPending) {
			return err
		}
		result = errors.Join(result, err)
	}
	return result
}
