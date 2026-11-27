// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/raft"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/workload"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
	contract "github.com/jay94ks/seafield/lifecycle/v1"
)

// Local diagnostic metadata is not a result, grant, or control receipt. It
// retains bounded phase/cost information when Machine.Finish normalizes a late
// result. Raw script/probe/provider error text never enters this record.
type checkerRunDiagnostic struct {
	Phase, Cause                string
	ElapsedMS, RemainingMS      int64
	AuthorityCalls, AuthorityMS int64
	AuthorityCause              string `json:",omitempty"`
	AuthorityError              string `json:",omitempty"`
	TargetCalls, TargetMS       int64  `json:",omitempty"`
	TargetCause                 string `json:",omitempty"`
}

func (d checkerRunDiagnostic) valid() bool {
	validCause := func(c string) bool {
		return c == "" || c == "deadline" || c == "canceled" || c == "error" || c == "unknown"
	}
	return slices.Contains([]string{"request-deadline", "initial-authority", "target-validation", "probe-setup", "source-policy", "compiled-preparation", "compiled-run", "yaegi-run", "builtin", "probe-cleanup"}, d.Phase) && validCause(d.Cause) && validCause(d.AuthorityCause) && validCause(d.TargetCause) && validCheckerAuthorityError(d.AuthorityError) && d.ElapsedMS >= 0 && d.AuthorityCalls >= 0 && d.AuthorityMS >= 0 && d.TargetCalls >= 0 && d.TargetMS >= 0
}

func validCheckerAuthorityError(code string) bool {
	return slices.Contains([]string{"", "deadline", "canceled", "not-leader", "leadership-lost", "shutdown", "recovering", "no-leader", "denied", "admission", "preparation", "source-reference", "error", "management-not-leader", "management-unavailable", "management-denied", "management-invalid", "management-unknown", "management-transport"}, code)
}

// Only bounded existing error codes are diagnostic data. Never persist raw
// messages: they may contain source paths, input values or provider details.
func checkerAuthorityErrorCode(err error) string {
	for _, item := range []struct {
		err  error
		code string
	}{
		{context.DeadlineExceeded, "deadline"}, {context.Canceled, "canceled"},
		{raft.ErrNotLeader, "not-leader"}, {raft.ErrLeadershipLost, "leadership-lost"},
		{raft.ErrRaftShutdown, "shutdown"}, {cluster.ErrRecovering, "recovering"},
		{errNoAppLeader, "no-leader"}, {errAppLeaderPeerUnavailable, "management-transport"}, {access.ErrDenied, "denied"},
		{sfcp.ErrAdmission, "admission"}, {checker.ErrPreparation, "preparation"},
		{checker.ErrReference, "source-reference"},
	} {
		if errors.Is(err, item.err) {
			return item.code
		}
	}
	var remote *cluster.ManagementError
	if errors.As(err, &remote) && remote != nil {
		code := "management-" + remote.Code
		if validCheckerAuthorityError(code) {
			return code
		}
	}
	if err == nil {
		return ""
	}
	return "error"
}

type checkerAuthorityDiagnostic struct{ cause, code string }

func checkerFailureCause(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, context.Canceled):
		return "canceled"
	default:
		return "error"
	}
}

func (r *Runtime) runAppCheck(ctx context.Context, binding deployment.Binding, task deployment.ObjectRef, program checker.TaskProgram, check checker.ResolvedCheck, request contract.Request, status workload.ContainerStatus, appScope bool, point *checkerObservation) (result contract.Result, probesClosed bool, runErr error) {
	result = contract.Result{Schema: 1, Status: contract.Unknown, Reason: "check-error"}
	probesClosed = true
	if ctx == nil || checker.ValidateRequest(request) != nil {
		return result, true, checker.ErrContract
	}
	started := time.Now()
	remainingMS := request.DeadlineUnixMilli - started.UnixMilli()
	phase := "request-deadline"
	var authorityCalls, authorityNanos atomic.Int64
	var authorityFailure atomic.Pointer[checkerAuthorityDiagnostic]
	var targetCalls, targetNanos atomic.Int64
	var targetCause atomic.Pointer[string]
	defer func() {
		if point == nil {
			return
		}
		cause := checkerFailureCause(runErr)
		if cause == "" && result.Status == contract.Unknown {
			cause = "unknown"
		}
		if !probesClosed {
			phase = "probe-cleanup"
		}
		d := &checkerRunDiagnostic{Phase: phase, Cause: cause, ElapsedMS: time.Since(started).Milliseconds(), RemainingMS: remainingMS, AuthorityCalls: authorityCalls.Load(), AuthorityMS: time.Duration(authorityNanos.Load()).Milliseconds()}
		if failure := authorityFailure.Load(); failure != nil {
			d.AuthorityCause, d.AuthorityError = failure.cause, failure.code
		}
		d.TargetCalls, d.TargetMS = targetCalls.Load(), time.Duration(targetNanos.Load()).Milliseconds()
		if c := targetCause.Load(); c != nil {
			d.TargetCause = *c
		}
		point.Diagnostic = d
	}()
	deadlineContext, cancelRun := context.WithDeadline(ctx, time.UnixMilli(request.DeadlineUnixMilli))
	defer cancelRun()
	ctx = deadlineContext
	if err := ctx.Err(); err != nil {
		return result, true, err
	}
	validateTargets := func(ctx context.Context) (targetErr error) {
		began := time.Now()
		targetCalls.Add(1)
		defer func() {
			targetNanos.Add(time.Since(began).Nanoseconds())
			if cause := checkerFailureCause(targetErr); cause != "" {
				targetCause.CompareAndSwap(nil, &cause)
			}
		}()
		return r.validateAppCheckTargets(ctx, binding, task, program, check, request)
	}
	// The root is immutable while callbacks update whole observation rows.
	// Do not race those saves by reading point's fields from authorization.
	var probeParent checkerObservation
	if point != nil {
		probeParent = checkerObservation{Task: point.Task, Program: point.Program, Checkpoint: point.Checkpoint}
	}
	localRun := check.Script != "" && !appScope && request.Phase != contract.Shutdown
	var compiledAuthority func(context.Context, cluster.View) error
	runAuthority := func(ctx context.Context, kind string) (policy checker.TenantPolicy, authorityErr error) {
		callStarted := time.Now()
		authorityCalls.Add(1)
		defer func() {
			authorityNanos.Add(time.Since(callStarted).Nanoseconds())
			if cause := checkerFailureCause(authorityErr); cause != "" {
				authorityFailure.CompareAndSwap(nil, &checkerAuthorityDiagnostic{cause, checkerAuthorityErrorCode(authorityErr)})
			}
		}()
		var v cluster.View
		var err error
		if request.Phase == contract.Shutdown {
			if probeParent.Checkpoint.Definition.Stop == nil {
				return checker.TenantPolicy{}, checker.ErrContract
			}
			v, err = r.checkerShutdownView(ctx, binding, task, program, *probeParent.Checkpoint.Definition.Stop, nil)
		} else {
			v, err = r.checkerPreparationView(ctx, binding, task)
		}
		if err != nil {
			return checker.TenantPolicy{}, err
		}
		if compiledAuthority != nil {
			if err = compiledAuthority(ctx, v); err != nil {
				return checker.TenantPolicy{}, err
			}
		}
		return r.checkerAuthorityView(v, binding, task, program, kind)
	}
	loadLocalAuthority := func(ctx context.Context, kind string) (policy checker.TenantPolicy, authorityErr error) {
		began := time.Now()
		authorityCalls.Add(1)
		defer func() {
			authorityNanos.Add(time.Since(began).Nanoseconds())
			if cause := checkerFailureCause(authorityErr); cause != "" {
				authorityFailure.CompareAndSwap(nil, &checkerAuthorityDiagnostic{cause, checkerAuthorityErrorCode(authorityErr)})
			}
		}()
		return r.checkerLocalReadAuthority(ctx, binding, task, program, kind)
	}
	phase = "initial-authority"
	initialAuthority := runAuthority
	if localRun {
		// Read metadata only. No source I/O, helper or Probe is dispatched
		// until the runner's mandatory fresh source-start authorization.
		initialAuthority = loadLocalAuthority
	}
	current, err := initialAuthority(ctx, "")
	if err != nil {
		return result, true, err
	}
	phase = "target-validation"
	if appScope {
		if err := validateTargets(ctx); err != nil {
			return result, true, err
		}
	}
	deadline := request.DeadlineUnixMilli
	if now := time.Now().UnixMilli(); deadline > now && deadline-now > current.Execution.TimeoutMS {
		deadline = now + current.Execution.TimeoutMS
	}
	ctx, cancel := context.WithDeadline(ctx, time.UnixMilli(deadline))
	defer cancel()
	authorize := func(ctx context.Context, kind string) error {
		latest, err := runAuthority(ctx, kind)
		if err != nil {
			return err
		}
		if latest.Revision != current.Revision {
			return checker.ErrStale
		}
		if appScope {
			return validateTargets(ctx)
		}
		return nil
	}
	phase = "probe-setup"
	var checkpointMu sync.Mutex
	localRead := func(ctx context.Context, kind string) error {
		latest, err := loadLocalAuthority(ctx, kind)
		if err != nil {
			return err
		}
		if latest.Revision != current.Revision {
			return checker.ErrStale
		}
		return nil
	}
	beforeExecute := func(ctx context.Context) error { return authorize(ctx, "") }
	if localRun {
		beforeExecute = func(ctx context.Context) error { return localRead(ctx, "") }
	}
	probeAuthority := checkerProbeAuthorizer(request, appScope, r.Identity.Actor(), authorize, localRead)
	probe, err := r.workload.OpenServiceProbe(ctx, request, func(ctx context.Context, kind string, target contract.Target) error {
		if !appScope && target.Service != program.Service {
			return checker.ErrContract
		}
		return probeAuthority(ctx, kind, target)
	}, func(receipt workload.ProbeExecReceipt) error {
		checkpointMu.Lock()
		defer checkpointMu.Unlock()
		return r.saveCheckerExec(point, receipt)
	})
	if err != nil {
		return result, true, err
	}
	defer func() {
		// The node's polling goroutine is joined before its DB/SDK close.
		// A request deadline does not let it abandon an original Probe call.
		if err := probe.Close(context.Background()); err != nil {
			probesClosed = false
			runErr = errors.Join(runErr, err)
		}
		if point != nil && !point.remoteCallsClosed() {
			probesClosed = false
			runErr = errors.Join(runErr, errCheckerRemotePending)
		}
	}()
	var native contract.Probe = probe
	if appScope {
		native = &appCheckProbe{ServiceProbe: probe, request: request, localOwner: r.Identity.Actor(), remote: func(ctx context.Context, call checker.ProbeCall) (checker.ProbeReply, error) {
			return r.sendCheckerRemote(ctx, binding, task, program, current, &probeParent, call, func(receipt checkerRemoteReceipt) error {
				checkpointMu.Lock()
				defer checkpointMu.Unlock()
				return r.saveCheckerRemoteReceipt(point, receipt)
			})
		}, dependency: func(ctx context.Context, q contract.DependencyProbe) (contract.DependencyResult, error) {
			return r.appProbeDependency(ctx, binding, request, q, authorize)
		}}
	}
	guard, err := checker.GuardProbe(ctx, request, current, native)
	if err != nil {
		return result, true, err
	}
	guard, err = checker.GuardProbe(ctx, request, program.Policy, guard)
	if err != nil {
		return result, true, err
	}
	phase = "source-policy"
	if check.Script != "" {
		if r.checkerSources == nil {
			result.Reason = "source-unavailable"
			return result, true, checker.ErrPreparation
		}
		script, exists := program.Scripts[check.Script]
		fact, found := program.Sources[check.Script]
		if !exists || !found {
			result.Reason = "source-unavailable"
			return result, true, checker.ErrPreparation
		}
		// Both accepted and current import rules apply. The runner already
		// authorizes before source I/O and before accepting its result; attach
		// current-policy resolution to those same fresh edges instead of a
		// separate preceding quorum call after every policy revision change.
		var resolveCurrent func(context.Context) error
		if current.Revision != program.Policy.Revision {
			resolveCurrent = func(ctx context.Context) error {
				_, err := r.checkerSources.Resolve(ctx, fact.Descriptor(), current, checker.ResolverTarget{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Toolchain: runtime.Version()})
				return err
			}
		}
		sourceAuthorize := checkerSourceAuthorizer(func(ctx context.Context) error { return authorize(ctx, "") }, resolveCurrent)
		policy := program.Policy.Clone()
		policy.Execution.OutputBytes = min(policy.Execution.OutputBytes, current.Execution.OutputBytes)
		policy.Execution.ProbeBytes = min(policy.Execution.ProbeBytes, current.Execution.ProbeBytes)
		if script.Compile {
			phase = "compiled-preparation"
			u, ok := control.CheckerBindingUse(binding)
			if !ok {
				return result, true, checker.ErrPreparation
			}
			p, err := r.checkerSources.TaskPreparation(ctx, u.Tenant, checker.TaskCompileID(r.controlPolicy.Cluster, u.Digest()), false)
			if err != nil {
				return result, true, err
			}
			if p.Plan == nil || p.Validate() != nil {
				return result, true, checker.ErrPreparation
			}
			if localRun {
				// Cached bytes remain subject to the same artifact policy, in
				// the fresh source-start/result view rather than a second RPC.
				compiledAuthority = func(ctx context.Context, view cluster.View) error {
					return r.checkerPreparationReady(ctx, view, u, program, p, func(ctx context.Context, compiled checker.CompiledFact) error {
						book, err := r.controlPolicy.Lifecycles(view.State)
						if err != nil {
							return err
						}
						members, err := r.controlPolicy.Members(view.State)
						if err != nil {
							return err
						}
						return checkerLocalCompiledAuthority(book, members, r.commandIdentity().Public, r.Identity.Public, u, program, compiled)
					})
				}
			}
			if !localRun {
				var view cluster.View
				if request.Phase == contract.Shutdown {
					view, err = r.checkerShutdownView(ctx, binding, task, program, *probeParent.Checkpoint.Definition.Stop, nil)
				} else {
					view, err = r.checkerPreparationView(ctx, binding, task)
				}
				if err != nil {
					return result, true, err
				}
				var extra []func(context.Context, checker.CompiledFact) error
				if request.Phase == contract.Shutdown {
					extra = append(extra, func(ctx context.Context, fact checker.CompiledFact) error {
						_, err := r.checkerShutdownView(ctx, binding, task, program, *probeParent.Checkpoint.Definition.Stop, &fact)
						return err
					})
				}
				if err = r.checkerPreparationReady(ctx, view, u, program, p, extra...); err != nil {
					return result, true, err
				}
			}
			for _, recipe := range p.Plan.Recipes {
				if recipe.Source != fact.ContentDigest() {
					continue
				}
				phase = "compiled-run"
				value, err := r.checkerSources.RunCachedCompiled(ctx, fact.Descriptor(), policy, recipe, request, guard, sourceAuthorize, nil, beforeExecute)
				return value, true, err
			}
			return result, true, checker.ErrPreparation
		}
		phase = "yaegi-run"
		returnValue, err := r.checkerSources.RunInterpreted(ctx, fact.Descriptor(), policy, request, guard, sourceAuthorize, nil, beforeExecute)
		return returnValue, true, err
	}
	phase = "builtin"
	if check.Builtin == nil {
		return result, true, checker.ErrContract
	}
	pass := false
	switch b := check.Builtin; b.Kind {
	case "docker_health":
		if !status.Running {
			break
		}
		if !status.HealthConfigured || status.Health != "healthy" && status.Health != "unhealthy" {
			return result, true, nil
		}
		pass = status.Health == "healthy"
	case "healthz":
		if b.HTTP == nil {
			return result, true, checker.ErrContract
		}
		observed, err := guard.Healthz(ctx, *b.HTTP)
		if err != nil {
			return result, true, err
		}
		pass = observed.Match
	case "file":
		if b.File == nil {
			return result, true, checker.ErrContract
		}
		query := contract.FileProbe{Service: b.File.Service, Path: b.File.Path, Kind: b.File.Kind, ContentDigest: b.File.ContentDigest}
		if query.ContentDigest != "" {
			query.MaxBytes = min(program.Policy.Execution.ProbeBytes, current.Execution.ProbeBytes)
		}
		observed, err := guard.File(ctx, query)
		if err != nil {
			return result, true, err
		}
		pass = observed.Exists && observed.Match && (b.File.Mode == nil || observed.Mode == *b.File.Mode)
	case "cmd":
		if b.Exec == nil {
			return result, true, checker.ErrContract
		}
		observed, err := guard.Exec(ctx, *b.Exec)
		if err != nil {
			return result, true, err
		}
		pass = observed.Exited && observed.ExitCode == 0
	case "depends_on":
		if b.Dependency == nil {
			return result, true, checker.ErrContract
		}
		if appScope {
			value := contract.Result{Schema: 1, Status: contract.Pass, Reason: "dependencies-ready"}
			for _, service := range b.Dependency.Services {
				dependency, err := r.appProbeDependency(ctx, binding, request, contract.DependencyProbe{Service: service, Condition: b.Dependency.Condition}, func(c context.Context, _ string) error { return authorize(c, "") })
				if err != nil {
					return result, true, err
				}
				if dependency.Status == contract.Fail {
					value.Status, value.Reason = contract.Fail, "dependency-not-ready"
					break
				}
				if dependency.Status == contract.Unknown {
					value.Status, value.Reason = contract.Unknown, "dependency-unknown"
				}
			}
			if err := authorize(ctx, ""); err != nil {
				return result, true, err
			}
			return value, true, nil
		}
		observed, _, err := r.appCheckerDependencies(ctx, binding, *b.Dependency)
		if err != nil {
			return result, true, err
		}
		if err = authorize(ctx, ""); err != nil {
			return result, true, err
		}
		return observed, true, nil
	default:
		result.Reason = "builtin-unavailable"
		return result, true, checker.ErrContract
	}
	if err := authorize(ctx, ""); err != nil {
		return result, true, err
	}
	result = contract.Result{Schema: 1, Status: contract.Fail, Reason: "not-alive"}
	if pass {
		result.Status, result.Reason = contract.Pass, "alive"
	}
	return result, true, nil
}

func (r *Runtime) appCheckerDependencies(ctx context.Context, binding deployment.Binding, condition checker.DependencyCondition) (contract.Result, bool, error) {
	result := contract.Result{Schema: 1, Status: contract.Pass, Reason: "dependencies-ready"}
	v, err := r.Engine().Read(ctx, false)
	if err != nil {
		return result, true, err
	}
	apps, err := r.controlPolicy.ReadApps(v.State)
	if err != nil {
		return result, true, err
	}
	use := binding.Needs().Use
	execution, exists := apps.Execution(use.Tenant, use.App)
	if !exists {
		return result, true, checker.ErrReference
	}
	for _, service := range condition.Services {
		instances, err := execution.Blueprint().ServiceInstances(service)
		if err != nil || len(instances) == 0 {
			return result, true, checker.ErrReference
		}
		for _, instance := range instances {
			stage, found := execution.Stage(deployment.ResourceKey("task", use.Tenant, use.App, instance.ResourceID()))
			if !found || stage.Observation == nil || stage.Observation.Released {
				result.Status, result.Reason = contract.Unknown, "dependency-unknown"
				continue
			}
			switch reason := taskDependencyReason(*stage.Observation, condition.Condition, uint64(time.Now().Unix())); reason {
			case "":
			case "dependency-not-ready":
				return contract.Result{Schema: 1, Status: contract.Fail, Reason: reason}, true, nil
			default:
				result.Status, result.Reason = contract.Unknown, reason
			}
		}
	}
	return result, true, nil
}

// checkerLocalCompiledAuthority consumes metadata only after the enclosing
// fresh Binding check. A retained local Task/cache keeps its original keys;
// current authority belongs to their installed successor, never those keys.
// This issues no artifact-transfer or remote cache adoption permission.
func checkerLocalCompiledAuthority(book checker.Catalog, members membership.Directory, caller, localOwner [32]byte, u checker.Use, program checker.TaskProgram, compiled checker.CompiledFact) error {
	actual, known := book.Use(u.Tenant, u.ID)
	if !known || actual.Digest() != u.Digest() || u.Kind != "app-binding" || u.Owner != localOwner || program.Tenant != u.Tenant {
		return checker.ErrPreparation
	}
	_, policy, err := book.SourceForUse(actual, compiled.Build.Recipe.Source)
	if err != nil {
		return err
	}
	if !members.WorkKey(caller) || !members.OwnsResource(caller, u.Owner) || !members.OwnsResource(caller, compiled.Owner) {
		return checker.ErrPreparation
	}
	return control.ValidateCheckerCompiledMetadata(book, &program, policy, compiled.Build.Recipe.Source, compiled)
}

// taskDependencyReason judges one dependency task observation: "" passes,
// "dependency-not-ready" fails, anything else is Unknown. The reducer's
// Expired mark, not the stored At, says the owner stopped reporting.
func taskDependencyReason(observed deployment.Observation, condition string, now uint64) string {
	if !observed.Live(now) {
		return "owner-stopped-reporting"
	}
	pass := condition == "service_started" && observed.Applied || condition == "service_healthy" && observed.Healthy || condition == "service_completed_successfully" && observed.Exit != nil && observed.Exit.Code == 0
	if !pass {
		return "dependency-not-ready"
	}
	return ""
}
