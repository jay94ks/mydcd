// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/workload"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
	contract "github.com/jay94ks/seafield/lifecycle/v1"
)

func (p *checkerObservation) setControl(c checker.ContainerControl) {
	p.Control = &c
	if c.Phase == checker.ControlCompleted && (c.Action == checker.StartContainer || c.Action == checker.RestartContainer) && p.Checkpoint.Last != nil {
		p.Previous = &deployment.TaskRestart{Program: p.Program, Checker: p.Checkpoint.Last.Run.Request.Checker, Status: p.Checkpoint.Last.Result.Status, Control: c}
	}
}

// Publish the current instance before accepting another control. This keeps
// one durable transition sufficient even when a prior report reply was lost.
func (r *Runtime) checkerInstancePublished(ctx context.Context, binding deployment.Binding, task deployment.ObjectRef, status workload.ContainerStatus) (bool, error) {
	v, err := r.Engine().Read(ctx, false)
	if err != nil {
		return false, err
	}
	apps, err := r.controlPolicy.ReadApps(v.State)
	if err != nil {
		return false, err
	}
	u := binding.Needs().Use
	e, ok := apps.Execution(u.Tenant, u.App)
	if !ok {
		return false, deployment.ErrInputs
	}
	s, ok := e.Stage(task.Key)
	if !ok || s.Observation == nil || s.Observation.Released {
		return false, nil
	}
	stamp, err := parseAppInstance(status.StartedAt)
	if err != nil {
		return false, err
	}
	o := s.Observation
	return o.Native == status.NativeID && o.Generation == task.Generation && o.Revision == task.Revision && o.StartedAt == stamp, nil
}

func (r *Runtime) consumeAppCheckerControl(ctx context.Context, binding deployment.Binding, program checker.TaskProgram, point *checkerObservation) error {
	if point.Control == nil || point.Checkpoint.Last == nil {
		return checker.ErrContract
	}
	return r.workload.ControlContainer(ctx, *point.Checkpoint.Last, *point.Control, true, func(c checker.ContainerControl) error {
		point.setControl(c)
		return r.saveCheckerObservation(*point)
	}, func(ctx context.Context) error {
		if point.Program != program.Program || len(r.Identity.Certificate.Certificate) == 0 {
			return checker.ErrStale
		}
		boot := sha256.Sum256(r.Identity.Certificate.Certificate[0])
		if point.Control.Target.OwnerBoot != hex.EncodeToString(boot[:]) {
			return checker.ErrStale
		}
		if _, err := r.checkerAuthority(ctx, binding, point.Task, program, ""); err != nil {
			return err
		}
		if point.Control.Phase == checker.ControlPrepared {
			machine, err := checker.Restore(point.Checkpoint)
			if err != nil {
				return err
			}
			if machine.Status(time.Now().UnixMilli()) != point.Checkpoint.Last.Result.Status {
				return checker.ErrStale
			}
		}
		for _, check := range program.Checks {
			if check.ID != point.Checkpoint.Last.Run.Request.Checker || check.Phase != contract.Liveness || check.Actions == nil {
				continue
			}
			action := check.Actions.OnAlive
			if point.Checkpoint.Last.Result.Status == contract.Fail {
				action = check.Actions.OnDead
			}
			if action == point.Control.Action || action == checker.RestartContainer && point.Control.Action == checker.StartContainer {
				return nil
			}
			return checker.ErrContract
		}
		return checker.ErrReference
	})
}
