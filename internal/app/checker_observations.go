// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/eventlog"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/storage"
	"github.com/jay94ks/seafield/internal/workload"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
	contract "github.com/jay94ks/seafield/lifecycle/v1"
)

const checkerObservationPrefix = "checker/observation/"
const maxCheckerObservationBytes = 256 << 10
const maxCheckerObservationTotal = 32 << 20
const maxCheckerObservationSlots = 16384

// Read already persisted control intent without taking checkerRunMu: a Stop
// can be waiting for Docker while this independent event reader consumes die.
// No diagnostic label is promoted to control or termination authority.
func (r *Runtime) checkerEventReason(target eventlog.Target, detail *eventlog.Detail, nano int64) {
	if r.reports == nil || target.Service == "" || nano <= 0 {
		return
	}
	prefix := checkerObservationPrefix + target.Tenant + "/" + target.App + "/service/" + target.Service + "/"
	rows, err := r.reports.ScanBounded(prefix, maxCheckerObservationSlots, maxCheckerObservationTotal)
	if err != nil {
		return
	}
	var found *checker.ContainerControl
	var checkerID string
	phase := checker.ControlStartSent
	if detail.Reason == "exit" {
		phase = checker.ControlStopSent
	}
	for _, raw := range rows {
		p, err := schema.Decode[checkerObservation](raw)
		if err != nil || p.Control == nil || p.Checkpoint.Last == nil || p.validate(r.controlPolicy.Cluster, r.Identity.Public) != nil {
			continue
		}
		c := p.Control
		if c.Phase != phase || c.Target.NativeID != target.Native || c.Target.TaskKey != target.Task || c.Target.Generation != target.Generation || c.Target.Revision != target.Revision || p.Checkpoint.Last.At > nano/int64(time.Millisecond) {
			continue
		}
		if found != nil && found.RunID != c.RunID {
			return // competing causes are unknown, never selected by map order
		}
		found, checkerID = c, p.Checkpoint.Definition.Request.Checker
	}
	if found != nil {
		detail.Reason, detail.Checker, detail.RunID = "health", checkerID, found.RunID
	}
}

type checkerObservation struct {
	Recent      []containerops.DetailCheck `json:",omitempty"`
	Schema      uint8
	Task        deployment.ObjectRef
	Program     [32]byte
	Checkpoint  checker.Checkpoint
	Control     *checker.ContainerControl   `json:",omitempty"`
	Previous    *deployment.TaskRestart     `json:",omitempty"`
	Executions  []workload.ProbeExecReceipt `json:",omitempty"`
	RemoteCalls []checkerRemoteReceipt      `json:",omitempty"`
	Diagnostic  *checkerRunDiagnostic       `json:",omitempty"`
}

func checkerObservationKey(d checker.Definition) string {
	scope := "app"
	if d.Scope != "" {
		scope = "service/" + d.Scope
	}
	r := d.Request
	return checkerObservationPrefix + strings.Join([]string{r.Tenant, r.App, scope, r.Checker, string(r.Phase)}, "/")
}

func (p checkerObservation) validate(cluster [32]byte, owner [32]byte) error {
	if !validCheckerRecent(p.Recent) {
		return checker.ErrContract
	}
	if p.Schema != 1 || p.Task.Key == "" || p.Task.Generation == 0 || p.Task.Revision < p.Task.Generation || p.Program == ([32]byte{}) || p.Checkpoint.Definition.ProgramDigest != hex.EncodeToString(p.Program[:]) || p.Checkpoint.Definition.Request.Cluster != hex.EncodeToString(cluster[:]) {
		return checker.ErrContract
	}
	if p.Diagnostic != nil && (!p.Diagnostic.valid() || p.Checkpoint.Last == nil) {
		return checker.ErrContract
	}
	if _, err := checker.Restore(p.Checkpoint); err != nil {
		return err
	}
	if err := p.validateExecutions(); err != nil {
		return err
	}
	if err := p.validateRemoteCalls(owner); err != nil {
		return err
	}
	if p.Control != nil && (p.Checkpoint.Active != nil || p.Checkpoint.Last == nil || p.Control.ValidateFor(*p.Checkpoint.Last) != nil) {
		return checker.ErrContract
	}
	if p.Previous != nil {
		previous := p.Previous
		c := previous.Control
		if p.Checkpoint.Definition.Scope == "" || p.Checkpoint.Definition.Request.Phase != contract.Liveness || len(p.Checkpoint.Definition.Request.Targets) != 1 || c.Target.Service != p.Checkpoint.Definition.Scope || c.Target.NativeID != p.Checkpoint.Definition.Request.Targets[0].NativeID || c.RequestDigest == ([32]byte{}) || len(c.RunID) != 64 {
			return checker.ErrContract
		}
		if _, err := parseAppInstance(c.Target.StartedAt); err != nil {
			return checker.ErrContract
		}
		if previous.Program != p.Program || previous.Checker != p.Checkpoint.Definition.Request.Checker || previous.Status != contract.Pass && previous.Status != contract.Fail || c.Schema != 1 || c.Phase != checker.ControlCompleted || c.Action != checker.StartContainer && c.Action != checker.RestartContainer || c.Target.TaskKey != p.Task.Key || c.Target.Generation != p.Task.Generation || c.Target.Revision != p.Task.Revision || c.Target.Owner != hex.EncodeToString(owner[:]) || previous.PreviousExit != nil {
			return checker.ErrContract
		}
	}
	coordinatorBound := false
	for _, target := range p.Checkpoint.Definition.Request.Targets {
		if target.TaskKey == p.Task.Key && target.Generation == p.Task.Generation && target.Revision == p.Task.Revision && target.Owner == hex.EncodeToString(owner[:]) {
			coordinatorBound = true
		}
		if p.Checkpoint.Definition.Scope != "" && (target.Owner != hex.EncodeToString(owner[:]) || target.TaskKey != p.Task.Key || target.Generation != p.Task.Generation || target.Revision != p.Task.Revision) {
			return checker.ErrContract
		}
	}
	if !coordinatorBound {
		return checker.ErrContract
	}
	return nil
}

func (r *Runtime) saveCheckerObservation(p checkerObservation) error {
	if err := p.validate(r.controlPolicy.Cluster, r.Identity.Public); err != nil {
		return err
	}
	key := checkerObservationKey(p.Checkpoint.Definition)
	if err := r.retainCheckerRecent(&p, key); err != nil {
		return err
	}
	raw, err := json.Marshal(p)
	if err != nil || len(raw) > maxCheckerObservationBytes || r.checkerObservationSizes == nil {
		return checker.ErrContract
	}
	total := 0
	for _, size := range r.checkerObservationSizes {
		total += size
	}
	before, exists := r.checkerObservationSizes[key]
	if !exists && len(r.checkerObservationSizes) >= maxCheckerObservationSlots || total-before+len(raw)+len(key) > maxCheckerObservationTotal {
		return checker.ErrContract
	}
	writes := map[string][]byte{key: raw}
	if r.events != nil && len(p.Recent) > 0 && p.Checkpoint.Last != nil {
		last := p.Recent[len(p.Recent)-1]
		if last.Status == "fail" && last.RunID == p.Checkpoint.Last.Run.Request.RunID {
			request := p.Checkpoint.Definition.Request
			parts := strings.Split(p.Task.Key, "/")
			if len(parts) != 5 {
				return checker.ErrContract
			}
			event := eventlog.Event{Kind: "probe-failed", Scope: "app", At: uint64(last.At.UnixMilli()), Target: eventlog.Target{Tenant: request.Tenant, App: request.App, Service: parts[4], Task: p.Task.Key, Native: last.NativeID, Node: r.Engine().ObservedNodeID(), Generation: p.Task.Generation, Revision: p.Task.Revision}, Detail: eventlog.Detail{Code: "CHECK_FAILED", Checker: last.Checker, RunID: last.RunID, ConsecutiveFailures: p.Checkpoint.Failures, State: "fail", Reason: "health"}}
			now := uint64(time.Now().UnixMilli())
			if event.At > now+30000 || event.At < now && now-event.At > eventlog.RetentionMillis {
				event = eventlog.Event{Kind: "event-source-gap", Scope: "node", At: now, Target: eventlog.Target{Node: r.Engine().ObservedNodeID()}, Detail: eventlog.Detail{Code: "CHECK_EVENT_TIME_UNAVAILABLE"}}
			}
			_, err = r.events.AppendRelated("checker-failure/"+p.Task.Key+"/"+last.RunID, event, now, writes)
		} else {
			err = r.reports.Write(writes)
		}
	} else {
		err = r.reports.Write(writes)
	}
	if err != nil {
		r.checkerRecovered = false
		return err
	}
	r.checkerObservationSizes[key] = len(raw) + len(key)
	if p.Control != nil && !p.Control.Terminal() {
		r.checkerRecovered = false
	}
	return nil
}

// The checker runs synchronously in the existing single polling flow. Every
// call waits for its compiled child and closes/joins its ServiceProbe before
// yielding this lock, including an execution/storage error. The direct child
// uses parent-death termination on daemon loss; it is not a container agent.
// A retained dispatch is recovered as the SAME unknown run, never replayed.
func (r *Runtime) recoverCheckerObservations(ctx context.Context) error {
	r.checkerRunMu.Lock()
	defer r.checkerRunMu.Unlock()
	return r.recoverCheckerObservationsLocked(ctx)
}

func (r *Runtime) recoverCheckerObservationsLocked(ctx context.Context) error {
	if r.checkerRecovered || r.workload == nil {
		return nil
	}
	if r.reports == nil || ctx == nil || ctx.Err() != nil {
		return checker.ErrContract
	}
	if err := r.reports.Sync(); err != nil {
		return err
	}
	rows, err := r.reports.ScanBounded(checkerObservationPrefix, maxCheckerObservationSlots, maxCheckerObservationTotal)
	if err != nil {
		return err
	}
	for key := range r.checkerObservationSizes {
		if _, found := rows[key]; !found {
			return checker.ErrContract
		}
	}
	r.checkerObservationSizes = make(map[string]int, len(rows))
	for key, raw := range rows {
		p, err := schema.Decode[checkerObservation](raw)
		if err != nil || len(raw) > maxCheckerObservationBytes || p.validate(r.controlPolicy.Cluster, r.Identity.Public) != nil || checkerObservationKey(p.Checkpoint.Definition) != key {
			return checker.ErrContract
		}
		r.checkerObservationSizes[key] = len(key) + len(raw)
	}
	pendingControls := false
	for _, raw := range rows {
		p, _ := schema.Decode[checkerObservation](raw)
		active := p.Checkpoint.Active
		if active == nil {
			if p.Control != nil && !p.Control.Terminal() {
				err := r.workload.ControlContainer(ctx, *p.Checkpoint.Last, *p.Control, false, func(c checker.ContainerControl) error { p.setControl(c); return r.saveCheckerObservation(p) }, nil)
				if err != nil && !errors.Is(err, reconcile.ErrPending) {
					return err
				}
				pendingControls = pendingControls || !p.Control.Terminal()
			}
			continue
		}
		if err = r.settleInterruptedChecker(ctx, &p); err != nil {
			if errors.Is(err, workload.ErrProbeExecPending) || errors.Is(err, errCheckerRemotePending) {
				pendingControls = true
				continue // original down/retirement must still reach Docker
			}
			return err
		}
	}
	r.checkerRecovered = !pendingControls
	return nil
}

func (r *Runtime) checkerAuthority(ctx context.Context, binding deployment.Binding, task deployment.ObjectRef, expected checker.TaskProgram, kind string) (checker.TenantPolicy, error) {
	v, err := r.checkerPreparationView(ctx, binding, task)
	if err != nil {
		return checker.TenantPolicy{}, err
	}
	return r.checkerAuthorityView(v, binding, task, expected, kind)
}

func (r *Runtime) checkerAuthorityView(v cluster.View, binding deployment.Binding, task deployment.ObjectRef, expected checker.TaskProgram, kind string) (checker.TenantPolicy, error) {
	actual, book, err := r.checkerTaskProgramCatalog(v, binding, task)
	if err != nil || actual == nil || checkerProgramHash(*actual) != checkerProgramHash(expected) {
		return checker.TenantPolicy{}, checker.ErrPreparation
	}
	current, found := book.Policy(expected.Tenant, 0)
	if !found || !current.Enabled || kind != "" && !slices.Contains(current.Execution.Capabilities, kind) {
		return checker.TenantPolicy{}, checker.ErrReference
	}
	for _, fact := range expected.Sources {
		if !current.AllowsSource(fact) {
			return checker.TenantPolicy{}, checker.ErrReference
		}
	}
	return current, nil
}

func (r *Runtime) checkerDefinition(binding deployment.Binding, task deployment.ObjectRef, program checker.TaskProgram, check checker.ResolvedCheck, status workload.ContainerStatus) (checker.Definition, error) {
	if len(r.Identity.Certificate.Certificate) == 0 {
		return checker.Definition{}, checker.ErrContract
	}
	boot := sha256.Sum256(r.Identity.Certificate.Certificate[0])
	source, err := program.CheckSourceDigest(check)
	if err != nil {
		return checker.Definition{}, err
	}
	request := contract.Request{Schema: 1, Cluster: hex.EncodeToString(r.controlPolicy.Cluster[:]), Tenant: program.Tenant, App: binding.Needs().Use.App, Checker: check.ID, SourceDigest: hex.EncodeToString(source[:]), Phase: check.Phase, Parameters: check.Parameters,
		Targets: []contract.Target{{Service: program.Service, TaskKey: task.Key, NativeID: status.NativeID, Owner: r.Identity.Actor(), OwnerBoot: hex.EncodeToString(boot[:]), Generation: task.Generation, Revision: task.Revision, StartedAt: status.StartedAt}}}
	d := checker.Definition{Scope: program.Service, ProgramDigest: hex.EncodeToString(program.Program[:]), Request: request, Timing: check.Timing, PolicyRevision: program.Policy.Revision}
	return d, d.Validate()
}

type appCheckerState struct {
	check   checker.ResolvedCheck
	point   checkerObservation
	machine checker.Machine
}

// Each finite polling pass runs a due checker at most once. Longer freshness
// windows run first, so short-lived results are not already stale at aggregate
// time. Re-evaluate due times between completions, without starting another
// full module reconciliation or repeating a run within this pass.
func nextAppChecker(states []appCheckerState, now int64, visited []bool) (int, error) {
	if len(visited) != len(states) {
		return -1, checker.ErrContract
	}
	selected := -1
	for i, state := range states {
		if visited[i] {
			continue
		}
		if _, _, err := state.machine.Plan(now); err != nil {
			if errors.Is(err, checker.ErrNotDue) {
				continue
			}
			return -1, err
		}
		if selected < 0 || state.point.Checkpoint.Definition.Timing.FreshForMS > states[selected].point.Checkpoint.Definition.Timing.FreshForMS || state.point.Checkpoint.Definition.Timing.FreshForMS == states[selected].point.Checkpoint.Definition.Timing.FreshForMS && state.point.Checkpoint.NextAt < states[selected].point.Checkpoint.NextAt {
			selected = i
		}
	}
	return selected, nil
}

func (r *Runtime) observeAppCheckers(ctx context.Context, view cluster.View, binding deployment.Binding, task deployment.ObjectRef, status workload.ContainerStatus) (workload.ContainerStatus, error) {
	program, err := r.checkerTaskProgram(view, binding, task)
	if err != nil || program == nil {
		return status, err
	}
	r.checkerRunMu.Lock()
	defer r.checkerRunMu.Unlock()
	if err = r.recoverCheckerObservationsLocked(ctx); err != nil {
		return status, err
	}
	apps, err := r.controlPolicy.ReadApps(view.State)
	if err != nil {
		return status, err
	}
	userRestart := apps.TaskRestartPending(r.Identity.Public, task.Key)
	var states []appCheckerState
	for _, check := range program.Checks {
		if check.Phase == contract.Shutdown {
			continue
		}
		definition, err := r.checkerDefinition(binding, task, *program, check, status)
		if err != nil {
			return status, err
		}
		key := checkerObservationKey(definition)
		raw, err := r.reports.GetBounded(key, maxCheckerObservationBytes)
		var point checkerObservation
		var machine checker.Machine
		changed := false
		if errors.Is(err, storage.ErrMissing) {
			if _, known := r.checkerObservationSizes[key]; known {
				return status, checker.ErrContract
			}
			machine, err = checker.New(definition, time.Now().UnixMilli())
			changed = true
		} else if err == nil {
			point, err = schema.Decode[checkerObservation](raw)
			if err == nil {
				err = point.validate(r.controlPolicy.Cluster, r.Identity.Public)
			}
			if err == nil && point.Control != nil && !point.Control.Terminal() {
				if err = r.consumeAppCheckerControl(ctx, binding, *program, &point); err != nil {
					return status, err
				}
				if err = r.workload.Step(ctx, task.Key); err != nil {
					return status, err
				}
				fresh, err := r.workload.Status(ctx, task.Key)
				fresh.Ready = false // next poll binds checks to the observed new instance
				return fresh, err
			}
			if err == nil {
				if point.Checkpoint.Active != nil {
					status.Ready = false
					return status, nil // this Task is unknown; others/down still progress
				}
				machine, err = checker.Restore(point.Checkpoint)
			}
			if err == nil && point.Checkpoint.Definition.Digest() != definition.Digest() {
				changed = true
				if point.Control != nil {
					point.setControl(*point.Control)
				}
				point.Control = nil
				point.Executions = nil // original calls settled before binding replacement
				point.RemoteCalls = nil
				if point.Previous != nil && (point.Previous.Program != program.Program || point.Previous.Control.Target.NativeID != status.NativeID || point.Previous.Control.Target.Generation != task.Generation || point.Previous.Control.Target.Revision != task.Revision) {
					point.Previous = nil
				}
				machine, err = machine.Retire()
				if err == nil {
					machine, err = machine.Replace(definition, time.Now().UnixMilli())
				}
			}
		}
		if err != nil {
			return status, err
		}
		if userRestart {
			continue
		}
		point = checkerObservation{Schema: 1, Task: task, Program: program.Program, Checkpoint: machine.Checkpoint(), Control: point.Control, Previous: point.Previous, Executions: point.Executions, RemoteCalls: point.RemoteCalls}
		if changed {
			// Persist initial/changed schedules even when another checker is
			// chosen now. Its due time must survive the next polling cycle.
			if err = r.saveCheckerObservation(point); err != nil {
				return status, err
			}
		}
		states = append(states, appCheckerState{check: check, point: point, machine: machine})
	}
	if userRestart {
		status.Ready = false
		return status, nil
	}
	visited := make([]bool, len(states))
	for completed := 0; completed < len(states); completed++ {
		if err := ctx.Err(); err != nil {
			return status, err
		}
		selected, err := nextAppChecker(states, time.Now().UnixMilli(), visited)
		if err != nil {
			return status, err
		}
		if selected < 0 {
			break
		}
		visited[selected] = true
		s := &states[selected]
		planned, run, err := s.machine.Plan(time.Now().UnixMilli())
		if err != nil {
			return status, err
		}
		r.checkerRecovered = false
		s.point.Diagnostic = nil // metadata must belong to this original run only
		s.point.Control = nil    // the previous terminal receipt cannot control this run
		s.point.Executions = nil // previous calls are terminal; new run has its own IDs
		s.point.RemoteCalls = nil
		s.point.Checkpoint = planned.Checkpoint()
		if err = r.saveCheckerObservation(s.point); err != nil {
			return status, err
		}
		s.machine, err = planned.Dispatch(run.Request.RunID)
		if err != nil {
			return status, err
		}
		s.point.Checkpoint = s.machine.Checkpoint()
		if err = r.saveCheckerObservation(s.point); err != nil {
			return status, err
		}
		result, probesClosed, runErr := r.runAppCheck(ctx, binding, task, *program, s.check, run.Request, status, false, &s.point)
		if !probesClosed {
			return status, errors.Join(checker.ErrPending, runErr)
		}
		if runErr != nil && (checker.ValidateResult(result) != nil || result.Status != contract.Unknown) {
			result = contract.Result{Schema: 1, Status: contract.Unknown, Reason: "check-error"}
		}
		s.machine, _, err = s.machine.Finish(checker.Completion{RunID: run.Request.RunID, RequestDigest: run.RequestDigest, Result: result, At: time.Now().UnixMilli(), HelperExited: true, ProbesClosed: true})
		if err != nil {
			return status, err
		}
		s.point.Checkpoint = s.machine.Checkpoint()
		if err = r.saveCheckerObservation(s.point); err != nil {
			return status, err
		}
	}
	// A result saved before instance publication may be consumed once that
	// report commits, without rerunning the script or waiting for its next due.
	for i := range states {
		s := &states[i]
		if s.check.Actions == nil || s.point.Checkpoint.Last == nil || s.point.Control != nil {
			continue
		}
		control, err := checker.NewContainerControl(*s.point.Checkpoint.Last, *s.check.Actions, s.machine.Status(time.Now().UnixMilli()), status.Running)
		if err != nil {
			return status, err
		}
		if control == nil {
			continue
		}
		published, err := r.checkerInstancePublished(ctx, binding, task, status)
		if err != nil {
			return status, err
		}
		if !published {
			continue
		}
		s.point.Control = control
		if err = r.saveCheckerObservation(s.point); err != nil {
			return status, err
		}
		if err = r.consumeAppCheckerControl(ctx, binding, *program, &s.point); err != nil {
			return status, err
		}
		if err = r.workload.Step(ctx, task.Key); err != nil {
			return status, err
		}
		fresh, err := r.workload.Status(ctx, task.Key)
		fresh.Ready = false
		return fresh, err
	}
	var samples []checker.Sample
	for _, s := range states {
		samples = append(samples, checker.Sample{Checker: s.check.ID, Phase: s.check.Phase, Status: s.machine.Status(time.Now().UnixMilli())})
	}
	for _, phase := range []contract.Phase{contract.Readiness, contract.Liveness} {
		observed, err := checker.Aggregate(phase, samples)
		if err != nil {
			return status, err
		}
		status.Ready = status.Ready && observed == contract.Pass
	}
	return status, nil
}
