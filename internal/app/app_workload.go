// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"cmp"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"slices"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/storage"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/workload"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

func (r *Runtime) appTaskAuthority(ctx context.Context, key string, op reconcile.Operation) error {
	v, err := r.Engine().Read(ctx, false)
	if err != nil {
		return err
	}
	a, err := r.controlPolicy.ReadApps(v.State)
	if err != nil {
		return err
	}
	for _, b := range a.Bindings().Live() {
		source, ok := a.BindingSource(b.Digest())
		if !ok || source.Task.Key != key || source.Task.Generation != op.Target.Generation {
			continue
		}
		if !a.StandaloneActivationAllowed(b.Needs().Use.Tenant, b.Needs().Use.App, time.Now().Unix()) {
			return deployment.ErrInputs
		}
		permit, err := r.appInputPermit(ctx, control.AppBindingRequest{Task: source.Task, Digest: b.Digest()})
		if err != nil {
			return fmt.Errorf("task start authority binding permit: %w", err)
		}
		// A quorum permit may precede this follower's FSM publication. Wait
		// for that same command ordinal within the original context; a local
		// lag is neither a denied grant nor a reason to mint another permit.
		v, err = r.Engine().ReadAtLeast(ctx, permit.CommandIndex)
		if err != nil {
			return fmt.Errorf("task start authority replica floor: %w", err)
		}
		material, err := r.controlPolicy.AppTaskMaterial(v.State, source.Task)
		if err != nil || material.Binding.Digest() != b.Digest() {
			return fmt.Errorf("task start authority current material: %w", deployment.ErrInputs)
		}
		a, err = r.controlPolicy.ReadApps(v.State)
		if err != nil {
			return err
		}
		e, ok := a.Execution(b.Needs().Use.Tenant, b.Needs().Use.App)
		spec, err := workload.DecodeContainer(op.Target.Spec)
		if !ok || err != nil {
			return fmt.Errorf("task start authority execution or recipe decode: %w", deployment.ErrInputs)
		}
		if !e.ActivationReady(key) {
			return fmt.Errorf("task start authority activation readiness: %w", deployment.ErrInputs)
		}
		taskID, err := deployment.ResourceIDFromKey("task", b.Needs().Use.Tenant, b.Needs().Use.App, source.Task.Key)
		if err != nil || !e.MatchesTaskRecipe(taskID, material, spec) {
			return fmt.Errorf("task start authority accepted recipe: %w", deployment.ErrInputs)
		}
		if err = r.appTaskDNSReady(ctx, v.State, a, key); err != nil {
			return fmt.Errorf("task start authority DNS readiness: %w", err)
		}
		program, err := r.checkerTaskProgram(v, b, source.Task)
		if err != nil {
			return fmt.Errorf("task start authority checker program: %w", err)
		}
		if program != nil {
			compiled := false
			for _, script := range program.Scripts {
				compiled = compiled || script.Compile
			}
			if compiled {
				u, ok := control.CheckerBindingUse(b)
				if !ok {
					return fmt.Errorf("task start authority checker use: %w", deployment.ErrInputs)
				}
				p, err := r.checkerSources.TaskPreparation(ctx, u.Tenant, checker.TaskCompileID(r.controlPolicy.Cluster, u.Digest()), false)
				if err != nil {
					return fmt.Errorf("task start authority checker preparation: %w", err)
				}
				if err = r.checkerPreparationReady(ctx, v, u, *program, p); err != nil {
					return fmt.Errorf("task start authority compiled readiness: %w", err)
				}
			}
		}
		if _, err = r.controlPolicy.RegistryImagePermit(v.State, r.Identity.Public, control.RegistryImageRequest{AppBindingRequest: control.AppBindingRequest{Task: source.Task, Digest: b.Digest(), At: time.Now().Unix()}, Image: spec.RunImage()}); err != nil {
			return fmt.Errorf("task start authority registry image: %w", err)
		}
		if err := r.restoredTaskWriter(v.State, material, spec); err != nil {
			return fmt.Errorf("task start authority original writer: %w", err)
		}
		return nil
	}
	return fmt.Errorf("task start authority live binding: %w", deployment.ErrInputs)
}

func (r *Runtime) appVolumePermit(ctx context.Context, request volumes.StartRequest) (volumes.Permit, error) {
	v, err := r.Engine().Read(ctx, false)
	if err != nil {
		return volumes.Permit{}, err
	}
	a, err := r.controlPolicy.ReadApps(v.State)
	if err != nil {
		return volumes.Permit{}, err
	}
	for _, b := range a.Bindings().Live() {
		for _, pin := range b.Pins() {
			if pin.Scope != request.Scope || pin.Consumer != request.Consumer {
				continue
			}
			source, ok := a.BindingSource(b.Digest())
			if !ok {
				return volumes.Permit{}, deployment.ErrInputs
			}
			if _, err = r.appInputPermit(ctx, control.AppBindingRequest{Task: source.Task, Digest: b.Digest()}); err != nil {
				return volumes.Permit{}, err
			}
			raw, _ := json.Marshal(request)
			reply, err := r.appCall(ctx, "volume-permit", raw)
			if err != nil {
				return volumes.Permit{}, err
			}
			permit, err := schema.Decode[volumes.Permit](reply.Data)
			if err != nil || permit.Request != request {
				return volumes.Permit{}, volumes.ErrActivation
			}
			return permit, nil
		}
	}
	return volumes.Permit{}, deployment.ErrInputs
}

func (r *Runtime) appObservation(app control.AppView, stage deployment.StageRecord, native string, healthy bool) (deployment.Observation, error) {
	if stage.Command == nil || stage.Result == nil {
		return deployment.Observation{}, deployment.ErrInputs
	}
	sequence := uint64(1)
	if stage.Observation != nil {
		sequence = stage.Observation.Sequence + 1
		if sequence == 0 {
			return deployment.Observation{}, deployment.ErrInputs
		}
	}
	o := deployment.Observation{Cluster: r.controlPolicy.Cluster, Plan: app.Operation.Plan, Operation: app.Operation.ID, Key: stage.Key, Native: native, Owner: r.Identity.Public, Command: state.Digest(*stage.Command), Generation: stage.Result.Generation, Revision: stage.Result.Revision, Sequence: sequence, At: uint64(time.Now().Unix()), Applied: true, Healthy: healthy}
	o.Signature = ed25519.Sign(r.Identity.Private, deployment.ObservationBytes(o))
	return o, nil
}

// appFailureObservation reports that this owner will never create the
// stage's container (deployment.PreparationFailure).
func (r *Runtime) appFailureObservation(app control.AppView, stage deployment.StageRecord, code string) (deployment.Observation, error) {
	o, err := r.appObservation(app, stage, deployment.NeverObservedNative, false)
	if err != nil {
		return o, err
	}
	o.Applied, o.Failure = false, code
	o.Signature = ed25519.Sign(r.Identity.Private, deployment.ObservationBytes(o))
	return o, nil
}

func (r *Runtime) freshAppObservation(stage deployment.StageRecord, native string, healthy bool) bool {
	return r.freshAppEvidence(stage, native, true, healthy)
}

func (r *Runtime) freshAppEvidence(stage deployment.StageRecord, native string, applied, healthy bool) bool {
	o := stage.Observation
	now := uint64(time.Now().Unix())
	if o == nil || o.Expired || o.Native != native || o.Applied != applied || o.Released || o.Healthy != healthy || o.At > now {
		return false
	}
	// A renewal sent over SFCP counts as fresh; Raft keeps only the fact.
	return r.renewalFresh(*o, now)
}

func (r *Runtime) freshAppTaskObservation(stage deployment.StageRecord, status workload.ContainerStatus, checks ...*deployment.AppCheckResult) bool {
	if len(checks) > 1 {
		return false
	}
	var gate *deployment.AppCheckResult
	if len(checks) == 1 {
		gate = checks[0]
	}
	if !r.freshAppEvidence(stage, status.NativeID, status.Running || status.Exit != nil, status.Ready) {
		return false
	}
	if status.StartedAt != "" {
		stamp, err := parseAppInstance(status.StartedAt)
		if err != nil || stage.Observation.StartedAt != stamp {
			return false
		}
	}
	if (stage.Observation.AppChecks == nil) != (gate == nil) || gate != nil && *stage.Observation.AppChecks != *gate {
		return false
	}
	previous := stage.Observation.Exit
	if (stage.Observation.TaskFact == nil) != (status.TaskFact == nil) {
		return false
	}
	if status.TaskFact != nil {
		left, _ := json.Marshal(stage.Observation.TaskFact)
		right, _ := json.Marshal(status.TaskFact)
		if !bytes.Equal(left, right) {
			return false
		}
	}
	if stage.Observation.LogDriver != status.LogDriver {
		return false
	}
	return previous == nil && status.Exit == nil || previous != nil && status.Exit != nil && *previous == *status.Exit
}

func (r *Runtime) appTaskObservation(app control.AppView, stage deployment.StageRecord, status workload.ContainerStatus, checks ...*deployment.AppCheckResult) (deployment.Observation, error) {
	if len(checks) > 1 {
		return deployment.Observation{}, deployment.ErrInputs
	}
	if status.Exit != nil && (status.Running || status.Ready || !status.Exit.Valid() || uint64(status.Exit.FinishedAt/1_000_000_000) > uint64(time.Now().Unix())) || status.Ready && !status.Running {
		return deployment.Observation{}, deployment.ErrInputs
	}
	o, err := r.appObservation(app, stage, status.NativeID, status.Ready)
	if err != nil {
		return o, err
	}
	if status.TaskFact != nil {
		fact := status.TaskFact.Clone()
		if fact.LastCheck != nil && fact.LastCheck.At > o.At {
			fact.LastCheck = nil
		}
		o.TaskFact = &fact
	}
	o.Applied = status.Running || status.Exit != nil
	o.LogDriver = status.LogDriver
	if len(r.Identity.Certificate.Certificate) > 0 {
		boot := sha256.Sum256(r.Identity.Certificate.Certificate[0])
		o.OwnerBoot = hex.EncodeToString(boot[:])
	}
	if len(checks) == 1 && checks[0] != nil {
		copy := *checks[0]
		if copy.ValidUntil != 0 && copy.ValidUntil <= int64(o.At)*1000 {
			copy.Status, copy.ValidUntil = "unknown", 0
		}
		o.AppChecks = &copy
	}
	if status.StartedAt != "" {
		o.StartedAt, err = parseAppInstance(status.StartedAt)
		if err != nil {
			return o, err
		}
		o.Restart, err = r.checkerRestartEvidence(stage, o.StartedAt)
		if err != nil {
			return o, err
		}
	}
	if status.Exit != nil {
		exit := *status.Exit
		o.Exit = &exit
	}
	o.Signature = ed25519.Sign(r.Identity.Private, deployment.ObservationBytes(o))
	return o, nil
}

// A stable task key may have an old, fully retired journal. Reuse an original
// same-generation recipe through Unknown; resolve a new one only after positive
// local settlement and a strictly newer committed generation/revision.
func appTaskRecipeState(record reconcile.Record, source deployment.ObjectRef) (reuse bool, err error) {
	s := record.State
	if reconcile.Validate(s) != nil || source.Generation == 0 || source.Revision < source.Generation || source.Revision < s.Desired.Revision {
		return false, deployment.ErrInputs
	}
	if s.Desired.Present && s.Desired.Generation == source.Generation {
		return true, nil
	}
	if s.Desired.Present || s.Applied.Present || s.Pending != nil || s.Stopped || len(record.Consumers) != 0 || source.Generation <= s.GenerationFloor || source.Revision <= s.Desired.Revision {
		return false, deployment.ErrInputs
	}
	return false, nil
}

type appWorkload struct {
	app       control.AppView
	execution deployment.Execution
	step      deployment.Step
	stage     deployment.StageRecord
}

// The execution plan retains its dependency order. Only Runtime polling order
// changes: a successful early report must not starve later stages or apps.
func appWorkloads(apps control.Apps, owner [32]byte) []appWorkload {
	var work []appWorkload
	for _, app := range apps.Records() {
		var retirement *deployment.RetirementView
		if inventory, exists := apps.Inventory(app.Tenant, app.App); exists {
			if wave, retiring := inventory.Retirement(); retiring {
				if !wave.KeepExecution || wave.Down {
					continue
				}
				retirement = &wave
			}
		}
		e, ok := apps.Execution(app.Tenant, app.App)
		if !ok || e.Status() == "Stopping" || e.Status() == "Closed" {
			continue
		}
		for _, step := range e.Steps() {
			if retirement != nil && !retirement.Preserves(step.Key) {
				continue
			}
			stage, _ := e.Stage(step.Key)
			if stage.Held() {
				original := stage.Previous.Step
				if original.Owner == owner && original.Kind == "task" {
					work = append(work, appWorkload{app: app, execution: e, step: original, stage: stage})
				}
				continue
			}
			if e.Status() == "Paused" || e.Status() == "Failed" {
				continue
			}
			if step.Owner != owner || step.Kind != "volume" && step.Kind != "inputs" && step.Kind != "task" {
				continue
			}
			if stage.Result == nil || stage.Result.Code != state.Applied || stage.Command == nil {
				continue
			}
			work = append(work, appWorkload{app: app, execution: e, step: step, stage: stage})
		}
	}
	orderAppWorkloads(work)
	return work
}

func orderAppWorkloads(work []appWorkload) {
	observedAt := func(w appWorkload) uint64 {
		if o := w.stage.Observation; o != nil && o.Applied && !o.Released {
			return o.At
		}
		return 0
	}
	slices.SortStableFunc(work, func(a, b appWorkload) int {
		return cmp.Compare(observedAt(a), observedAt(b))
	})
}

// reconcileAppWorkloads consumes the same committed execution and native A2
// journals. No source/gen, resolved image or dispatched operation is replaced.
func (r *Runtime) reconcileAppWorkloads(ctx context.Context, v cluster.View, apps control.Apps) (bool, error) {
	r.imageUseMu.Lock()
	defer r.imageUseMu.Unlock()
	if r.workload == nil {
		return false, nil
	}
	works := appWorkloads(apps, r.Identity.Public)
	r.forgetStaleAppInputs(works)
	r.retainSecretSockets(works)
	var failures []error
	for _, work := range works {
		progressed, err := r.reconcileAppWorkload(ctx, v, apps, work)
		if err != nil {
			if ctx.Err() != nil {
				return false, err
			}
			// One app's failure must not hold back the other apps on this
			// node: record it with its app and step and go on.
			failures = append(failures, fmt.Errorf("app %s/%s %s %s: %w", work.app.Tenant, work.app.App, work.step.Kind, work.step.Key, err))
			continue
		}
		if progressed {
			return true, errors.Join(failures...)
		}
	}
	return false, errors.Join(failures...)
}

// reconcileAppWorkload advances one owned step. It reports true after it
// sent one progress report; the caller then starts a fresh pass.
func (r *Runtime) reconcileAppWorkload(ctx context.Context, v cluster.View, apps control.Apps, work appWorkload) (bool, error) {
	app, e, step, stage := work.app, work.execution, work.step, work.stage
	if stage.Held() {
		original, _ := stage.HeldSource()
		source := deployment.ObjectRef{Key: step.Key, Revision: original.Result.Revision, Generation: original.Result.Generation}
		binding, bound := apps.Binding(source)
		if !bound {
			return false, deployment.ErrInputs
		}
		material, err := r.controlPolicy.AppTaskMaterial(v.State, source)
		if err != nil || material.Binding.Digest() != binding.Digest() {
			return false, deployment.ErrInputs
		}
		record, err := r.workload.View(step.Key)
		if err != nil {
			return false, err
		}
		reuse, err := appTaskRecipeState(record, source)
		if err != nil || !reuse {
			return false, deployment.ErrInputs
		}
		spec, err := workload.DecodeContainer(record.State.Desired.Spec)
		taskID, idErr := deployment.ResourceIDFromKey("task", app.Tenant, app.App, step.Key)
		if err != nil || idErr != nil || !e.MatchesTaskRecipe(taskID, material, spec) {
			return false, deployment.ErrInputs
		}
		// Continue only the original local journal. No Desired(new target),
		// image re-resolution or replacement request is manufactured here.
		if err = r.workload.Step(ctx, step.Key); err != nil {
			return false, err
		}
		status, err := r.workload.Status(ctx, step.Key)
		if err != nil {
			return false, err
		}
		if status.NativeID != stage.Previous.Native {
			return false, deployment.ErrInputs
		}
		status, err = r.observeAppCheckers(ctx, v, binding, source, status)
		if err != nil {
			return false, err
		}
		if err = r.publishTaskMeasurement(v, app, original, status); err != nil {
			return false, err
		}
		if r.freshAppTaskObservation(original, status) {
			return false, nil
		}
		o, err := r.appTaskObservation(app, original, status)
		if err != nil {
			return false, err
		}
		return true, r.appProgress(ctx, v, app, "observe", step.Key, &o)
	}
	source := deployment.ObjectRef{Key: step.Key, Generation: stage.Result.Generation, Revision: stage.Result.Revision}
	switch step.Kind {
	case "volume":
		material, err := r.controlPolicy.AppVolumeMaterial(v.State, source)
		if err != nil {
			return false, err
		}
		key := volumes.NativeKey(material.Spec)
		record, err := r.nativeVolumes.View(key)
		if err != nil && !errors.Is(err, storage.ErrMissing) {
			return false, err
		}
		capacity := record.Capacity
		// A move/restore prepares an exclusive staging slot before this
		// app owns the materialization. Its existing Applied journal must
		// adopt the current app consumer limit as well. The local policy
		// only detects a change; the quorum permit authorizes the resize.
		resources, err := r.controlPolicy.Resources(v.State)
		if err != nil {
			return false, err
		}
		currentCapacity, err := appVolumeConsumerCapacity(resources.Quotas, app, step, material, r.Identity.Public)
		if err != nil {
			return false, err
		}
		capacityChanged := capacity != currentCapacity
		if !record.State.Applied.Present || record.State.Pending != nil && record.State.Pending.Phase == reconcile.Prepared || capacityChanged {
			raw, _ := json.Marshal(control.NativeRequest{Source: source})
			reply, err := r.appCall(ctx, "app-native-permit", raw)
			if err != nil {
				return false, err
			}
			permit, err := schema.Decode[control.NativePermit](reply.Data)
			expected, _ := json.Marshal(material)
			if err != nil || permit.Source != source || permit.Owner != r.Identity.Public || permit.Kind != "volume" || permit.Spec != sha256.Sum256(expected) || permit.MaxConsumers < 1 {
				return false, deployment.ErrInputs
			}
			capacity = permit.MaxConsumers
			// A previously published native volume cannot be recreated from
			// an empty local journal, including after external reuse.
			registry, err := r.controlPolicy.Volumes(v.State)
			if err != nil {
				return false, err
			}
			if _, exists := registry.Native(app.Tenant, app.App, material.Spec.Scope.ID); exists && record.State.LastID == 0 {
				return false, volumes.ErrNativeVolume
			}
		}
		if capacity < 1 {
			return false, deployment.ErrInputs
		}
		if _, err = r.nativeVolumes.Desired(material.Spec, max(source.Revision, record.State.Desired.Revision), material.Generation, capacity); err != nil {
			return false, err
		}
		if err = r.nativeVolumes.Step(ctx, key); err != nil {
			return false, err
		}
		ready, err := r.nativeVolumes.Ready(ctx, key, r.Identity.Private)
		if err != nil {
			return false, err
		}
		if r.freshAppObservation(stage, ready.Owner.Native, false) {
			return false, nil
		}
		o, err := r.appObservation(app, stage, ready.Owner.Native, false)
		if err != nil {
			return false, err
		}
		registry, err := r.controlPolicy.Volumes(v.State)
		if err != nil {
			return false, err
		}
		registered, exists := registry.Native(app.Tenant, app.App, ready.Spec.Scope.ID)
		if appVolumeObservationOnly(stage, registered, ready, exists) {
			// Registration is already committed. Refresh only this original
			// owner's fact; other stages cannot starve it with root CAS churn.
			return true, r.appProgress(ctx, v, app, "observe", step.Key, &o)
		}
		report := r.newAppProgress(v, app, "volume-ready", step.Key, &o)
		report.Volume = &ready
		return true, r.sendAppProgress(ctx, report)
	case "inputs":
		service, idErr := deployment.ResourceIDFromKey("inputs", app.Tenant, app.App, step.Key)
		if idErr != nil {
			return false, idErr
		}
		task, ok := e.Stage(deployment.ResourceKey("task", app.Tenant, app.App, service))
		if !ok || task.Result == nil {
			return false, nil
		}
		taskRef := deployment.ObjectRef{Key: task.Key, Generation: task.Result.Generation, Revision: task.Result.Revision}
		b, ok := apps.Binding(taskRef)
		if !ok {
			return false, nil
		}
		request := control.AppBindingRequest{Task: taskRef, Digest: b.Digest()}
		ref, err := r.PrepareAppInputs(ctx, request)
		if err != nil {
			request.At = time.Now().Unix()
			if r.controlPolicy.AppBindingRevisionChanged(v.State, request) {
				// A secret was updated after this deployment: the app keeps
				// what it already has and needs a redeploy for the new value.
				// Not an error of this pass; said once per binding.
				r.noteStaleAppInputs(app, step.Key, b.Digest())
				return r.observeStaleAppInputs(ctx, v, apps, app, stage, step.Key, request)
			}
			return false, err
		}
		r.clearStaleAppInputs(step.Key)
		native := "projection/" + fmtBinding(ref.Binding)
		if r.freshAppObservation(stage, native, false) {
			return false, nil
		}
		o, err := r.appObservation(app, stage, native, false)
		if err != nil {
			return false, err
		}
		return true, r.appProgress(ctx, v, app, "observe", step.Key, &o)
	case "task":
		if apps.StandaloneStopped(app.Tenant, app.App) {
			status, err := r.workload.Status(ctx, step.Key)
			if err != nil {
				return false, err
			}
			if r.freshAppTaskObservation(stage, status) {
				return false, nil
			}
			o, err := r.appTaskObservation(app, stage, status)
			if err != nil {
				return false, err
			}
			return true, r.appProgress(ctx, v, app, "observe", step.Key, &o)
		}
		taskID, idErr := deployment.ResourceIDFromKey("task", app.Tenant, app.App, step.Key)
		if idErr != nil {
			return false, idErr
		}
		b, ok := apps.Binding(source)
		if !ok {
			service, idErr := deployment.ResourceIDFromKey("task", app.Tenant, app.App, step.Key)
			if idErr != nil {
				return false, idErr
			}
			if inputs, exists := e.Stage(deployment.ResourceKey("inputs", app.Tenant, app.App, service)); exists && (inputs.Result == nil || inputs.Result.Code != state.Applied) {
				return false, nil
			}
			return true, r.appProgress(ctx, v, app, "bind-inputs", step.Key, nil)
		}
		material, err := r.controlPolicy.AppTaskMaterial(v.State, source)
		if err != nil {
			return false, err
		}
		if material.Projection != nil {
			input, ok := e.Stage(material.Projection.Key)
			if !ok || input.Observation == nil || !input.Observation.Applied {
				return false, nil
			}
		}
		record, err := r.workload.View(step.Key)
		if err != nil && !errors.Is(err, storage.ErrMissing) {
			return false, err
		}
		var spec workload.ContainerSpec
		capacity := record.Capacity
		reuse, err := appTaskRecipeState(record, source)
		if err != nil {
			return false, err
		}
		// Prepare exact source inputs outside the native actor's authority
		// callback/lock. Cached reads remain content checked; no runner Ready
		// is inferred from source/cache preparation or its finite build job.
		if !reuse {
			if err := r.queueAppCheckers(ctx, v, b, source); err != nil {
				return false, err
			}
		}
		if reuse {
			resource := record.State.Desired.Resource
			spec, err = workload.DecodeContainer(resource.Spec)
			if err != nil {
				return false, deployment.ErrInputs
			}
			if !e.MatchesTaskRecipe(taskID, material, spec) {
				// A same-generation update that attaches networks: the
				// driver connects them to the same container in place.
				attached, ok := e.TaskRecipeAttached(taskID, material, spec)
				if !ok {
					return false, deployment.ErrInputs
				}
				spec = attached
			}
		} else {
			permit, err := r.appInputPermit(ctx, control.AppBindingRequest{Task: source, Digest: b.Digest()})
			if err != nil {
				return false, err
			}
			// Another app may have committed observations while the permit
			// was read. Consume its minimum committed index now instead of
			// comparing it with the immutable view from the loop's start.
			authorized, err := r.Engine().Read(ctx, false)
			if err != nil {
				return false, err
			}
			if authorized.State.Index() < permit.CommandIndex {
				return false, fmt.Errorf("task %s local index %d below permit %d: %w", step.Key, authorized.State.Index(), permit.CommandIndex, deployment.ErrInputs)
			}
			material, err = r.controlPolicy.AppTaskMaterial(authorized.State, source)
			if err != nil {
				return false, err
			}
			if material.Binding.Digest() != b.Digest() {
				return false, deployment.ErrInputs
			}
			catalog, err := r.controlPolicy.Catalog(authorized.State)
			if err != nil {
				return false, err
			}
			capacity = permit.MaxConsumers
			taskImage, imageErr := appTaskImage(authorized.State, source)
			if imageErr != nil {
				return false, imageErr
			}
			// A tag is made from the deploy's digest, or from this
			// server's copy when the deploy could not resolve it.
			local := ""
			if tag, ok := deployment.TagReference(taskImage); ok {
				local, _ = r.imageTags.Get(app.Tenant, tag)
			}
			image, tag, failure := e.TaskImageFor(taskImage, local)
			if failure != "" && stage.Observation == nil {
				o, oerr := r.appFailureObservation(app, stage, failure)
				if oerr != nil {
					return false, oerr
				}
				log.Printf("app task %s cannot start: image %s: %s", step.Key, taskImage, failure)
				return true, r.appProgress(ctx, v, app, "observe", step.Key, &o)
			}
			if image.Digest != "" {
				taskImage = image.Digest
			}
			var auth engine.RegistryAuth
			if image.Source == "" {
				var authErr error
				if auth, authErr = r.appRegistryImageAuth(ctx, source, b.Digest(), taskImage); authErr != nil {
					return false, authErr
				}
			} else {
				log.Printf("app task %s: image %s: %s, using this server's copy %s", step.Key, tag, image.Source, image.Digest)
			}
			spec, err = e.ResolveTask(ctx, taskID, material, catalog, r.docker, image.Source == "", image, auth)
			if err == nil && tag != "" && image.Source == "" {
				if err := r.imageTags.Set(app.Tenant, tag, image.Digest, time.Now()); err != nil {
					log.Printf("app task %s: remembering image %s: %v", step.Key, tag, err)
				}
			}
			if code := deployment.PreparationFailure(err); code != "" && stage.Observation == nil {
				// Retrying cannot change a fixed goal on a digest-pinned
				// image; end the deployment instead of reading its source again.
				o, oerr := r.appFailureObservation(app, stage, code)
				if oerr != nil {
					return false, oerr
				}
				log.Printf("app task %s cannot start: %v", step.Key, err)
				return true, r.appProgress(ctx, v, app, "observe", step.Key, &o)
			}
			if err != nil {
				return false, err
			}
			if spec.Process == nil {
				return false, deployment.ErrInputs
			}
			// An earlier bare-config cache delete may be Unknown even though
			// this exact image was loaded again. Do not publish a new recipe
			// until that original deletion's shared admission fence is gone.
			if _, err = r.appRegistryImagePermit(ctx, source, b.Digest(), spec.RunImage(), spec.Process.ImageID); err != nil {
				return false, err
			}
		}
		if err = r.parkSurgedOriginal(stage); err != nil {
			return false, err
		}
		if err = r.workload.Desired(step.Key, source.Revision, source.Generation, &spec, capacity); err != nil {
			return false, err
		}
		if err = r.workload.Step(ctx, step.Key); err != nil {
			return false, err
		}
		status, err := r.workload.Status(ctx, step.Key)
		if err != nil {
			return false, err
		}
		if spec.SecretSocket {
			r.syncSecretSocket(ctx, step.Key, control.AppBindingRequest{Task: source, Digest: b.Digest()})
		}
		status, err = r.observeAppCheckers(ctx, v, b, source, status)
		if err != nil {
			return false, err
		}
		gate, err := r.observeAppScopeChecks(ctx, v, b, source, status)
		if err != nil {
			return false, err
		}
		if err := r.publishTaskMeasurement(v, app, stage, status); err != nil {
			return false, err
		}
		if r.freshAppTaskObservation(stage, status, gate) {
			return false, nil
		}
		o, err := r.appTaskObservation(app, stage, status, gate)
		if err != nil {
			return false, err
		}
		return true, r.appProgress(ctx, v, app, "observe", step.Key, &o)
	}
	return false, nil
}

func fmtBinding(digest [32]byte) string { return hex.EncodeToString(digest[:]) }

// Only an already registered and published full signed native fact can use
// an owner observation refresh. This never registers or replaces a Volume.
func appVolumeObservationOnly(stage deployment.StageRecord, registered, ready volumes.NativeReady, exists bool) bool {
	o := stage.Observation
	return exists && registered.Verify() == nil && ready.Verify() == nil && volumes.NativeBindingDigest(registered) == volumes.NativeBindingDigest(ready) && stage.Result != nil && stage.Result.Code == state.Applied && o != nil && o.Applied && !o.Released && o.Native == ready.Owner.Native && o.Generation == stage.Result.Generation && o.Revision == stage.Result.Revision
}

// Quota admission follows the current physical-node key, while this local
// journal and the exact committed volume material retain their native owner.
// Reading the consumer budget grants neither native creation nor a resize;
// both still require the existing current-quorum NativePermit above.
func appVolumeConsumerCapacity(quotas tenancy.Quotas, app control.AppView, step deployment.Step, material control.AppVolumeMaterial, nativeOwner [32]byte) (int, error) {
	spec := material.Spec
	if spec.Scope.Cluster != quotas.Cluster() || step.Kind != "volume" || step.Node != spec.Node || step.Owner != nativeOwner || spec.NodeKey != nativeOwner || spec.Scope.Tenant != app.Tenant || spec.Scope.App != app.App || step.Key != deployment.ResourceKey("volume", spec.Scope.Tenant, spec.Scope.App, spec.Scope.ID) {
		return 0, deployment.ErrInputs
	}
	global, globalOK := quotas.Limit("", step.Node)
	scoped, scopedOK := quotas.Limit(app.Tenant, step.Node)
	if !globalOK || !scopedOK || !quotas.SameOwner(step.Node, global.Owner, nativeOwner) || !quotas.SameOwner(step.Node, scoped.Owner, nativeOwner) {
		return 0, deployment.ErrInputs
	}
	return min(global.MaxConsumers, scoped.MaxConsumers), nil
}

// noteStaleAppInputs logs once per inputs step and binding that its secret was updated
// after the deployment, so the operator knows a redeploy applies it.
func (r *Runtime) noteStaleAppInputs(app control.AppView, step string, digest [32]byte) {
	r.inputPermitMu.Lock()
	defer r.inputPermitMu.Unlock()
	if r.staleInputs == nil {
		r.staleInputs = map[string][32]byte{}
	}
	if seen, ok := r.staleInputs[step]; ok && seen == digest {
		return
	}
	r.staleInputs[step] = digest
	log.Printf("app %s/%s %s: a secret was updated after this deployment; the running app keeps its current value until the app is deployed again", app.Tenant, app.App, step)
}

// clearStaleAppInputs forgets step once its inputs are current again, so a
// later secret update is said again.
func (r *Runtime) clearStaleAppInputs(step string) {
	r.inputPermitMu.Lock()
	defer r.inputPermitMu.Unlock()
	delete(r.staleInputs, step)
}

// forgetStaleAppInputs keeps only the steps this node still owns, so the
// log-once record stays as large as the current inputs steps.
func (r *Runtime) forgetStaleAppInputs(works []appWorkload) {
	r.inputPermitMu.Lock()
	defer r.inputPermitMu.Unlock()
	if len(r.staleInputs) == 0 {
		return
	}
	owned := make(map[string]bool, len(works))
	for _, work := range works {
		owned[work.step.Key] = true
	}
	for step := range r.staleInputs {
		if !owned[step] {
			delete(r.staleInputs, step)
		}
	}
}

// observeStaleAppInputs keeps the inputs step's observation of the files
// already published for request while they still exist. Nothing is read or
// written again.
func (r *Runtime) observeStaleAppInputs(ctx context.Context, v cluster.View, apps control.Apps, app control.AppView, stage deployment.StageRecord, step string, request control.AppBindingRequest) (bool, error) {
	source, ok := apps.BindingSource(request.Digest)
	if !ok || source.Inputs.Key == "" {
		return false, nil
	}
	store, err := r.appProjectionStore()
	if err != nil {
		return false, err
	}
	gone, err := store.Gone(workload.InputRef{Key: source.Inputs.Key, Generation: request.Task.Generation, Binding: request.Digest})
	if err != nil || gone {
		return false, err
	}
	native := "projection/" + fmtBinding(request.Digest)
	if r.freshAppObservation(stage, native, false) {
		return false, nil
	}
	o, err := r.appObservation(app, stage, native, false)
	if err != nil {
		return false, err
	}
	return true, r.appProgress(ctx, v, app, "observe", step, &o)
}
