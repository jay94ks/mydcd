// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/storage"
	"github.com/jay94ks/seafield/internal/workload"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
	contract "github.com/jay94ks/seafield/lifecycle/v1"
)

func (r *Runtime) checkerShutdownView(ctx context.Context, b deployment.Binding, task deployment.ObjectRef, program checker.TaskProgram, stop checker.ShutdownScope, compiled *checker.CompiledFact) (cluster.View, error) {
	q := control.CheckerShutdownRequest{Schema: 1, Task: task, Binding: b.Digest(), Stop: stop, At: time.Now().Unix(), Compiled: compiled}
	raw, _ := json.Marshal(q)
	reply, err := r.appCall(ctx, "checker-shutdown-permit", raw)
	if err != nil {
		return cluster.View{}, err
	}
	permit, err := schema.Decode[control.CheckerShutdownPermit](reply.Data)
	if err != nil || permit.Schema != 1 || permit.Task != task || permit.Binding != q.Binding || permit.Stop != stop || permit.Program != checkerProgramHash(program) || permit.Index == 0 {
		return cluster.View{}, checker.ErrReference
	}
	v, err := r.Engine().Read(ctx, false)
	if err != nil {
		return cluster.View{}, err
	}
	if v.State.Index() < permit.Index {
		return cluster.View{}, checker.ErrPending
	}
	local, err := r.controlPolicy.CheckerShutdownPermit(v.State, r.commandIdentity().Public, q)
	if err != nil || local.Program != permit.Program {
		return cluster.View{}, checker.ErrReference
	}
	return v, nil
}

// loadShutdownCheck uses the existing reusable Machine. One accepted stop
// consumes at most one attempt, including a pre-dispatch crash/cancellation.
// A different explicit retirement may replace a settled old definition while
// retaining its sequence floor; it cannot replace an unsettled original run.
func (r *Runtime) loadShutdownCheck(def checker.Definition, task deployment.ObjectRef, program [32]byte) (checkerObservation, checker.Machine, bool, error) {
	var point checkerObservation
	var machine checker.Machine
	if r.reports == nil || r.checkerObservationSizes == nil || def.Validate() != nil || def.Stop == nil || def.Request.Phase != contract.Shutdown {
		return point, machine, false, checker.ErrContract
	}
	key := checkerObservationKey(def)
	raw, err := r.reports.GetBounded(key, maxCheckerObservationBytes)
	if errors.Is(err, storage.ErrMissing) {
		if _, known := r.checkerObservationSizes[key]; known {
			return point, machine, false, checker.ErrContract
		}
		machine, err = checker.New(def, time.Now().UnixMilli())
	} else if err == nil {
		point, err = schema.Decode[checkerObservation](raw)
		if err == nil {
			err = point.validate(r.controlPolicy.Cluster, r.Identity.Public)
		}
		if err == nil {
			machine, err = checker.Restore(point.Checkpoint)
			if err == nil && point.Task == task && point.Program == program && point.Checkpoint.Definition.Stop != nil && *point.Checkpoint.Definition.Stop == *def.Stop && point.Checkpoint.Sequence > 0 {
				return point, machine, false, nil
			}
			if err == nil && point.Checkpoint.Active != nil {
				return point, machine, false, checker.ErrPending
			}
			if err == nil && point.Checkpoint.Definition.Digest() != def.Digest() {
				machine, err = machine.Retire()
				if err == nil {
					machine, err = machine.Replace(def, time.Now().UnixMilli())
				}
				point.Executions = nil
				point.RemoteCalls = nil
			}
		}
	}
	if err != nil {
		return point, machine, false, err
	}
	point = checkerObservation{Schema: 1, Task: task, Program: program, Checkpoint: machine.Checkpoint(), Executions: point.Executions, RemoteCalls: point.RemoteCalls}
	if err = r.saveCheckerObservation(point); err != nil {
		return point, machine, false, err
	}
	return point, machine, true, nil
}

type taskShutdownCheck struct {
	check    checker.ResolvedCheck
	appScope bool
}

func taskShutdownChecks(p checker.TaskProgram) []taskShutdownCheck {
	var out []taskShutdownCheck
	for _, check := range p.Checks {
		if check.Phase == contract.Shutdown {
			out = append(out, taskShutdownCheck{check: check})
		}
	}
	if p.Service == p.Coordinator {
		for _, check := range p.AppChecks {
			if check.Phase == contract.Shutdown {
				out = append(out, taskShutdownCheck{check: check, appScope: true})
			}
		}
	}
	return out
}

// An unavailable live read may still name the original signed native in an
// Unknown observation. This fallback never asserts Running/Ready or grants IO.
func shutdownRecordedTarget(c deployment.Claim) (workload.ContainerStatus, bool) {
	status := workload.ContainerStatus{NativeID: c.Native}
	if c.Observation != nil {
		if status.NativeID != "" && status.NativeID != c.Observation.Native {
			return workload.ContainerStatus{}, false
		}
		status.NativeID = c.Observation.Native
		if c.Observation.StartedAt > 0 {
			status.StartedAt = time.Unix(0, c.Observation.StartedAt).UTC().Format(time.RFC3339Nano)
		}
	}
	return status, status.NativeID != ""
}

// reconcileTaskShutdown runs at most one bounded advisory check per poll,
// immediately before the original Task's drain is sent. The coordinator's app
// checks run here too, without a new cross-node stop barrier. Unknown native
// execs retain their Active/receipts but cannot indefinitely prevent down.
func (r *Runtime) reconcileTaskShutdown(ctx context.Context, v cluster.View, apps control.Apps, retirement deployment.RetirementView, c deployment.Claim) (bool, error) {
	if r.workload == nil {
		return false, nil
	}
	task := deployment.ObjectRef{Key: c.Step.Key, Generation: c.Result.Generation, Revision: c.Result.Revision}
	b, exists := apps.Binding(task)
	if !exists {
		return false, nil
	} // no accepted/started script consumer
	var goal deployment.GoalCommand
	var service deployment.ComposeService
	if json.Unmarshal([]byte(c.Command.Value), &goal) != nil || json.Unmarshal(goal.Config, &service) != nil {
		return false, checker.ErrContract
	}
	p := service.LifecycleProgram
	if p == nil {
		return false, nil
	}
	if p.Validate(r.controlPolicy.Cluster) != nil || service.CheckLifecycleNeeds(b.Needs()) != nil {
		return false, checker.ErrContract
	}
	checks := taskShutdownChecks(*p)
	if len(checks) == 0 {
		return false, nil
	}
	r.checkerRunMu.Lock()
	defer r.checkerRunMu.Unlock()
	if err := r.recoverCheckerObservationsLocked(ctx); err != nil {
		return false, err
	}
	target, err := r.workload.ProbeTarget(ctx, task.Key, task.Generation, task.Revision)
	status := target.Status
	blocked, unavailable := err != nil, err != nil
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		var known bool
		status, known = shutdownRecordedTarget(c)
		if !known {
			return false, nil
		} // no native witness to bind; never invent an ID
	}
	// Pending calls are already joined on the client side; don't create more
	// side effects on a Task with an unresolved original checker/control.
	rows, err := r.reports.ScanBounded(checkerObservationPrefix, maxCheckerObservationSlots, maxCheckerObservationTotal)
	if err != nil {
		return false, err
	}
	for _, raw := range rows {
		point, err := schema.Decode[checkerObservation](raw)
		if err != nil || point.validate(r.controlPolicy.Cluster, r.Identity.Public) != nil {
			return false, checker.ErrContract
		}
		if point.Task == task && (point.Checkpoint.Active != nil || point.Control != nil && !point.Control.Terminal()) {
			blocked = true
		}
	}
	stop := checker.ShutdownScope{Operation: retirement.ID, Revision: retirement.Revision}
	for _, candidate := range checks {
		check, appScope := candidate.check, candidate.appScope
		def, err := r.checkerDefinition(b, task, *p, check, status)
		if err != nil {
			return false, err
		}
		if appScope {
			def.Scope = ""
			// If other targets have already retired, record an Unknown attempt
			// against the coordinator; the runner's exact-target check rejects IO.
			if targets, e := r.appCheckTargets(v, b, task, *p, check, status); e == nil {
				def.Request.Targets = targets
			}
		}
		def.Stop = &stop
		point, machine, needed, err := r.loadShutdownCheck(def, task, p.Program)
		if errors.Is(err, checker.ErrPending) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if !needed {
			continue
		}
		machine, run, err := machine.Plan(time.Now().UnixMilli())
		if err != nil {
			return false, err
		}
		point.Checkpoint = machine.Checkpoint()
		if err = r.saveCheckerObservation(point); err != nil {
			return false, err
		}
		machine, err = machine.Dispatch(run.Request.RunID)
		if err != nil {
			return false, err
		}
		point.Checkpoint = machine.Checkpoint()
		if err = r.saveCheckerObservation(point); err != nil {
			return false, err
		}
		r.checkerRecovered = false
		result, closed, runErr := contract.Result{Schema: 1, Status: contract.Unknown, Reason: "shutdown-unavailable"}, true, error(nil)
		if unavailable {
			result.Reason = "shutdown-target-unavailable"
		}
		if !blocked {
			result, closed, runErr = r.runAppCheck(ctx, b, task, *p, check, run.Request, status, appScope, &point)
		}
		if !closed {
			return true, nil
		} // keep Active/exec records; next poll may drain
		if runErr != nil && (checker.ValidateResult(result) != nil || result.Status != contract.Unknown) {
			result = contract.Result{Schema: 1, Status: contract.Unknown, Reason: "shutdown-error"}
		}
		machine, _, err = machine.Finish(checker.Completion{RunID: run.Request.RunID, RequestDigest: run.RequestDigest, Result: result, At: time.Now().UnixMilli(), HelperExited: true, ProbesClosed: true})
		if err != nil {
			return false, err
		}
		point.Checkpoint = machine.Checkpoint()
		if err = r.saveCheckerObservation(point); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}
