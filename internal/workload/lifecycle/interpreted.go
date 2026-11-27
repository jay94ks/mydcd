// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"maps"
	"os"
	"path"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/traefik/yaegi/interp"
	"github.com/traefik/yaegi/stdlib"

	contract "github.com/jay94ks/seafield/lifecycle/v1"
)

var ErrInterpreted = errors.New("lifecycle interpreted checker failed")

// RunInterpreted resolves the store's actual pinned source/module bytes and
// uses the same interpreter as the SDK tests. The caller supplies current
// tenant/Task authority and retains its Probe until all calls are closed.
// This function reports a script result; it does not publish or execute a
// container-control decision.
func (m *SourceStore) RunInterpreted(ctx context.Context, descriptor SourceDescriptor, policy TenantPolicy, request contract.Request, probe contract.Probe, authorize func(context.Context) error, diagnostic io.Writer, beforeExecute ...func(context.Context) error) (contract.Result, error) {
	unknown := func(reason string) contract.Result {
		return contract.Result{Schema: 1, Status: contract.Unknown, Reason: reason}
	}
	if m == nil || ctx == nil || authorize == nil || probe == nil || len(beforeExecute) > 1 || len(beforeExecute) == 1 && beforeExecute[0] == nil || ValidateRequest(request) != nil || descriptor.Validate() != nil || policy.Validate() != nil || request.Tenant != descriptor.Tenant || request.Cluster != hex.EncodeToString(m.identity.Cluster[:]) {
		return unknown("invalid-check"), ErrInterpreted
	}
	request, descriptor, policy = ownRequest(request), descriptor.Clone(), policy.Clone()
	ctx, cancel := context.WithDeadline(ctx, time.UnixMilli(request.DeadlineUnixMilli))
	defer cancel()
	if err := authorize(ctx); err != nil {
		return unknown("check-not-authorized"), err
	}
	source, err := m.Resolve(ctx, descriptor, policy, ResolverTarget{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Toolchain: runtime.Version()})
	if err != nil {
		return unknown("source-unavailable"), err
	}
	// Source resolution and final acceptance always use authorize. A caller
	// may select a current local check inside an already admitted read run.
	executionAuthority := authorize
	if len(beforeExecute) == 1 {
		executionAuthority = beforeExecute[0]
	}
	if err = executionAuthority(ctx); err != nil {
		return unknown("check-not-authorized"), err
	}
	result, runErr := evaluateInterpreted(ctx, source, request, probe, diagnostic)
	if err = authorize(ctx); err != nil {
		// Probe side effects may already have occurred. Keep the original
		// run ID and let the caller record Unknown instead of rerunning it.
		return unknown("check-authority-changed"), errors.Join(runErr, err)
	}
	if runErr != nil || ctx.Err() != nil {
		if ValidateResult(result) == nil && result.Status == contract.Unknown {
			return result, errors.Join(runErr, ctx.Err())
		}
		return unknown("check-error"), errors.Join(runErr, ctx.Err())
	}
	return result, nil
}

// evaluateInterpreted uses one fresh interpreter and a bounded context per
// check. It reports the script result; it never starts/stops a container.
// Yaegi is an interpreter, not an OS security or process-termination boundary.
func evaluateInterpreted(ctx context.Context, source *ResolvedSource, request contract.Request, probe contract.Probe, diagnostic io.Writer) (result contract.Result, err error) {
	unknown := func(reason string) contract.Result {
		return contract.Result{Schema: contract.Schema, Status: contract.Unknown, Reason: reason}
	}
	result = unknown("interpreter-error")
	defer func() {
		if recover() != nil {
			result, err = unknown("interpreter-panic"), ErrInterpreted
		}
	}()
	if ctx == nil || source == nil || source.files == nil || probe == nil || ValidateRequest(request) != nil || source.target.GOOS != runtime.GOOS || source.target.GOARCH != runtime.GOARCH || source.target.Toolchain != runtime.Version() || source.policy.Validate() != nil || !source.policy.Enabled || request.Tenant != source.descriptor.Tenant {
		return result, ErrInterpreted
	}
	digest := source.descriptor.ContentDigest()
	if request.SourceDigest != hex.EncodeToString(digest[:]) {
		return result, ErrInterpreted
	}
	// Yaegi consults these host variables even with an explicit empty Options
	// environment. Reject inherited debug/exec switches; never mutate daemon env.
	for _, variable := range os.Environ() {
		if strings.HasPrefix(variable, "YAEGI_") {
			return result, ErrInterpreted
		}
	}
	ctx, cancel := context.WithDeadline(ctx, time.UnixMilli(request.DeadlineUnixMilli))
	defer cancel()
	if ctx.Err() != nil {
		return unknown("deadline-expired"), ctx.Err()
	}
	probe, err = GuardProbe(ctx, request, source.policy, probe)
	if err != nil {
		return result, ErrInterpreted
	}
	if diagnostic == nil {
		diagnostic = io.Discard
	}
	output := &checkerDiagnostic{out: diagnostic, remaining: source.policy.Execution.OutputBytes}
	i := interp.New(interp.Options{GoPath: resolverGoPath, Stdin: bytes.NewReader(nil), Stdout: output, Stderr: output,
		Args: []string{"sfc-checker"}, Env: []string{}, SourcecodeFilesystem: source.files})
	exports := sdkSymbols()
	wrappers := map[reflect.Value][]reflect.Type{}
	for _, pkg := range source.standard {
		key := pkg + "/" + path.Base(pkg)
		symbols, ok := stdlib.Symbols[key]
		if !ok {
			return result, ErrInterpreted
		}
		exports[key] = maps.Clone(symbols)
		for _, value := range symbols {
			if types, ok := stdlib.MapTypes[value]; ok {
				wrappers[value] = types
			}
		}
	}
	exports["."] = map[string]reflect.Value{"MapTypes": reflect.ValueOf(wrappers)}
	// The script's inspected import graph cannot name this private package.
	// Native functions avoid reflecting mutable request/result storage into it.
	var mu sync.Mutex
	completed, repeated := false, false
	var completedResult contract.Result
	var completedError error
	publicContext := checkerContext{deadline: ctx.Deadline, done: ctx.Done, err: ctx.Err}
	publicProbe := opaqueCheckerProbe{
		healthz: probe.Healthz, connect: probe.Connect, exec: probe.Exec, file: probe.File, dependency: probe.Dependency,
	}
	exports[checkerBridge+"/bridge"] = map[string]reflect.Value{
		"Context": reflect.ValueOf(func() context.Context { return publicContext }),
		"Request": reflect.ValueOf(func() contract.Request { return ownRequest(request) }),
		"Probe":   reflect.ValueOf(func() contract.Probe { return publicProbe }),
		"Accept": reflect.ValueOf(func(r contract.Result, e error) {
			mu.Lock()
			defer mu.Unlock()
			if completed {
				repeated = true
				return
			}
			completed, completedResult, completedError = true, r, e
		}),
	}
	if i.Use(exports) != nil {
		return result, ErrInterpreted
	}
	for _, code := range []string{
		`import checker "sfc.local/checker"`,
		`import bridge "sfc.internal/lifecyclebridge"`,
		`bridge.Accept(checker.Check(bridge.Context(), bridge.Request(), bridge.Probe()))`,
	} {
		if _, evalErr := i.EvalWithContext(ctx, code); evalErr != nil {
			if ctx.Err() != nil {
				return unknown("deadline-expired"), ctx.Err()
			}
			return result, ErrInterpreted // raw parser/panic/probe text is private
		}
	}
	if ctx.Err() != nil {
		return unknown("deadline-expired"), ctx.Err()
	}
	mu.Lock()
	defer mu.Unlock()
	if !completed || repeated || completedError != nil || ValidateResult(completedResult) != nil || output.exceeded() {
		return result, ErrInterpreted
	}
	return completedResult, nil
}

type checkerDiagnostic struct {
	mu        sync.Mutex
	out       io.Writer
	remaining int
	failed    bool
}

func (w *checkerDiagnostic) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(p) > w.remaining || w.failed {
		w.failed = true
		return 0, ErrInterpreted
	}
	n, err := w.out.Write(p)
	w.remaining -= n
	if err != nil || n != len(p) {
		w.failed = true
	}
	return n, err
}
func (w *checkerDiagnostic) exceeded() bool { w.mu.Lock(); defer w.mu.Unlock(); return w.failed }

// Native SDK types, constants and the Yaegi interface wrapper are deliberately
// explicit. No cluster identity, native handles or management functions export.
func sdkSymbols() interp.Exports {
	return interp.Exports{checkerSDK + "/lifecycle": {
		"Schema":  reflect.ValueOf(contract.Schema),
		"Startup": reflect.ValueOf(contract.Startup), "Readiness": reflect.ValueOf(contract.Readiness),
		"Liveness": reflect.ValueOf(contract.Liveness), "Shutdown": reflect.ValueOf(contract.Shutdown),
		"Pass": reflect.ValueOf(contract.Pass), "Fail": reflect.ValueOf(contract.Fail), "Unknown": reflect.ValueOf(contract.Unknown),
		"Phase": reflect.ValueOf((*contract.Phase)(nil)), "Status": reflect.ValueOf((*contract.Status)(nil)),
		"Target": reflect.ValueOf((*contract.Target)(nil)), "Request": reflect.ValueOf((*contract.Request)(nil)),
		"Result": reflect.ValueOf((*contract.Result)(nil)), "Checker": reflect.ValueOf((*contract.Checker)(nil)),
		"HTTPProbe": reflect.ValueOf((*contract.HTTPProbe)(nil)), "HTTPResult": reflect.ValueOf((*contract.HTTPResult)(nil)),
		"TCPProbe": reflect.ValueOf((*contract.TCPProbe)(nil)), "TCPResult": reflect.ValueOf((*contract.TCPResult)(nil)),
		"ExecProbe": reflect.ValueOf((*contract.ExecProbe)(nil)), "ExecResult": reflect.ValueOf((*contract.ExecResult)(nil)),
		"FileProbe": reflect.ValueOf((*contract.FileProbe)(nil)), "FileResult": reflect.ValueOf((*contract.FileResult)(nil)),
		"DependencyProbe": reflect.ValueOf((*contract.DependencyProbe)(nil)), "DependencyResult": reflect.ValueOf((*contract.DependencyResult)(nil)),
		"Probe": reflect.ValueOf((*contract.Probe)(nil)), "_Probe": reflect.ValueOf((*checkerProbeWrapper)(nil)),
	}}
}

type checkerProbeWrapper struct {
	IValue      any
	WHealthz    func(context.Context, contract.HTTPProbe) (contract.HTTPResult, error)
	WConnect    func(context.Context, contract.TCPProbe) (contract.TCPResult, error)
	WExec       func(context.Context, contract.ExecProbe) (contract.ExecResult, error)
	WFile       func(context.Context, contract.FileProbe) (contract.FileResult, error)
	WDependency func(context.Context, contract.DependencyProbe) (contract.DependencyResult, error)
}

func (w checkerProbeWrapper) Healthz(ctx context.Context, p contract.HTTPProbe) (contract.HTTPResult, error) {
	return w.WHealthz(ctx, p)
}
func (w checkerProbeWrapper) Connect(ctx context.Context, p contract.TCPProbe) (contract.TCPResult, error) {
	return w.WConnect(ctx, p)
}
func (w checkerProbeWrapper) Exec(ctx context.Context, p contract.ExecProbe) (contract.ExecResult, error) {
	return w.WExec(ctx, p)
}
func (w checkerProbeWrapper) File(ctx context.Context, p contract.FileProbe) (contract.FileResult, error) {
	return w.WFile(ctx, p)
}
func (w checkerProbeWrapper) Dependency(ctx context.Context, p contract.DependencyProbe) (contract.DependencyResult, error) {
	return w.WDependency(ctx, p)
}
