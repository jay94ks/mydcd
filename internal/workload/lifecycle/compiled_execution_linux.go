// SPDX-License-Identifier: Apache-2.0

//go:build linux

package lifecycle

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"syscall"
	"time"

	contract "github.com/jay94ks/mydcd/lifecycle/v1"
	"golang.org/x/sys/unix"
)

var ErrCompiledExecution = errors.New("lifecycle compiled checker failed")

// RunCachedCompiled consumes the original recipe and verified cached bytes.
// It never builds, downloads, publishes a result or controls a container.
// The caller retains its original Task/read leases through this synchronous
// call and separately closes the supplied Probe after every call has joined.
func (m *SourceStore) RunCachedCompiled(ctx context.Context, descriptor SourceDescriptor, policy TenantPolicy, recipe CompileRecipe, request contract.Request, probe contract.Probe, authorize func(context.Context) error, diagnostic io.Writer, beforeExecute ...func(context.Context) error) (contract.Result, error) {
	unknown := func(reason string) contract.Result {
		return contract.Result{Schema: 1, Status: contract.Unknown, Reason: reason}
	}
	if m == nil || ctx == nil || authorize == nil || probe == nil || len(beforeExecute) > 1 || len(beforeExecute) == 1 && beforeExecute[0] == nil || descriptor.Validate() != nil || policy.Validate() != nil || recipe.Validate() != nil || ValidateRequest(request) != nil || request.Cluster != hex.EncodeToString(m.identity.Cluster[:]) || request.Tenant != descriptor.Tenant || recipe.Tenant != descriptor.Tenant || recipe.Source != descriptor.ContentDigest() {
		return unknown("invalid-check"), ErrCompiledExecution
	}
	request, descriptor, policy = ownRequest(request), descriptor.Clone(), policy.Clone()
	recipe.Flags = slices.Clone(recipe.Flags)
	deadline := request.DeadlineUnixMilli
	if now := time.Now().UnixMilli(); deadline > now && deadline-now > policy.Execution.TimeoutMS {
		deadline = now + policy.Execution.TimeoutMS
	}
	ctx, cancel := context.WithDeadline(ctx, time.UnixMilli(deadline))
	defer cancel()
	if err := authorize(ctx); err != nil {
		return unknown("check-not-authorized"), err
	}
	source, err := m.Resolve(ctx, descriptor, policy, ResolverTarget{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Toolchain: runtime.Version()})
	if err != nil {
		return unknown("source-unavailable"), err
	}
	input, err := PrepareCompilation(source)
	if err != nil || input.Key() != recipe.Key() || request.SourceDigest != hex.EncodeToString(recipe.Source[:]) {
		return unknown("compiled-recipe-changed"), errors.Join(ErrCompiledExecution, err)
	}
	fact, data, err := m.CompiledArtifact(ctx, descriptor.Tenant, recipe.Key())
	defer clear(data)
	if err != nil || fact.Build.Recipe.Key() != recipe.Key() {
		return unknown("compiled-cache-unavailable"), errors.Join(ErrCompiledExecution, err)
	}
	executionAuthority := authorize
	if len(beforeExecute) == 1 {
		executionAuthority = beforeExecute[0]
	}
	if err = executionAuthority(ctx); err != nil {
		return unknown("check-not-authorized"), err
	}
	result, runErr := executeCompiledCLI(ctx, data, policy, request, probe, diagnostic)
	if err = authorize(ctx); err != nil {
		return unknown("check-authority-changed"), errors.Join(runErr, err)
	}
	if err = ctx.Err(); err != nil {
		return unknown("deadline-expired"), errors.Join(runErr, err)
	}
	return result, runErr
}

// A sealed, anonymous copy executes exactly the bytes read from the tenant
// cache without creating an executable in a global or user-writable directory.
// This is an artifact transport, not a sandbox or process supervisor.
func compiledExecutable(data []byte) (*os.File, error) {
	fd, err := unix.MemfdCreate("mydc-checker", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "mydc-checker")
	n, err := f.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = f.Chmod(0500)
	}
	if err == nil {
		_, err = unix.FcntlInt(f.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL)
	}
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

type compiledRunDiagnostic struct {
	checkerDiagnostic
	cancel context.CancelFunc
}

func (w *compiledRunDiagnostic) Write(p []byte) (int, error) {
	n, err := w.checkerDiagnostic.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	if err != nil {
		w.cancel()
	}
	return n, err
}

func executeCompiledCLI(ctx context.Context, data []byte, policy TenantPolicy, request contract.Request, probe contract.Probe, diagnostic io.Writer) (contract.Result, error) {
	unknown := func(reason string) contract.Result {
		return contract.Result{Schema: 1, Status: contract.Unknown, Reason: reason}
	}
	if ctx == nil || ValidateRequest(request) != nil || len(data) == 0 || len(data) > MaxCompiledArtifactBytes || verifyCompileELF(bytes.NewReader(data), runtime.GOARCH) != nil {
		return unknown("invalid-check"), ErrCompiledExecution
	}
	ctx, cancel := context.WithDeadline(ctx, time.UnixMilli(request.DeadlineUnixMilli))
	defer cancel()
	guard, err := GuardProbe(ctx, request, policy, probe)
	if err != nil {
		return unknown("invalid-check"), err
	}
	binary, err := compiledExecutable(data)
	if err != nil {
		return unknown("compiled-start-failed"), err
	}
	defer binary.Close()
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return unknown("compiled-start-failed"), err
	}
	serverFile, childFile := os.NewFile(uintptr(pair[0]), "checker-parent-probe"), os.NewFile(uintptr(pair[1]), "checker-child-probe")
	defer childFile.Close()
	parent, err := net.FileConn(serverFile)
	_ = serverFile.Close()
	if err != nil {
		return unknown("compiled-start-failed"), err
	}
	defer parent.Close()
	reader, writer, err := os.Pipe()
	if err != nil {
		return unknown("compiled-start-failed"), err
	}
	defer reader.Close()
	defer writer.Close()
	stop := context.AfterFunc(ctx, func() { _ = parent.Close(); _ = reader.Close() })
	defer stop()
	input, err := json.Marshal(request)
	if err != nil {
		return unknown("invalid-check"), err
	}
	defer clear(input)
	command := exec.CommandContext(ctx, "/proc/self/fd/5", "run", "--contract", "1")
	command.ExtraFiles = []*os.File{childFile, writer, binary}
	command.Stdin = bytes.NewReader(input)
	command.Env = []string{"GOMAXPROCS=2"}
	command.Dir = "/"
	// Kill the direct checker child if its daemon parent disappears. No
	// cgroup, container agent or descendant-termination claim is introduced.
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	command.WaitDelay = 2 * time.Second
	if diagnostic == nil {
		diagnostic = io.Discard
	}
	output := &compiledRunDiagnostic{checkerDiagnostic: checkerDiagnostic{out: diagnostic, remaining: int(policy.Execution.OutputBytes)}, cancel: cancel}
	command.Stdout, command.Stderr = output, output
	if err = command.Start(); err != nil {
		return unknown("compiled-start-failed"), err
	}
	_ = childFile.Close()
	_ = writer.Close()
	probeDone := make(chan error, 1)
	go func() {
		probeDone <- ServeProbes(ctx, request, parent, func(c context.Context, call ProbeCall) (ProbeReply, error) { return DispatchProbe(c, call, guard) })
	}()
	type response struct {
		raw []byte
		err error
	}
	resultDone := make(chan response, 1)
	go func() {
		raw, err := io.ReadAll(io.LimitReader(reader, MaxResultBytes+1))
		if len(raw) > MaxResultBytes {
			cancel()
		}
		resultDone <- response{raw, err}
	}()
	waitErr := command.Wait()
	value, probeErr := <-resultDone, <-probeDone
	defer clear(value.raw)
	if output.exceeded() {
		return unknown("diagnostic-limit"), errors.Join(ErrCompiledExecution, waitErr, probeErr)
	}
	if ctx.Err() != nil {
		return unknown("deadline-expired"), errors.Join(ctx.Err(), waitErr, probeErr, value.err)
	}
	exit := command.ProcessState.ExitCode()
	result, decodeErr := DecodeExitResult(value.raw, exit)
	// exit 1/2 are part of the checker contract. All other process failures,
	// malformed/oversized results and Probe failures remain unknown.
	var exited *exec.ExitError
	expectedExit := waitErr == nil || errors.As(waitErr, &exited) && exited.Exited() && (exit == 1 || exit == 2)
	if decodeErr != nil || value.err != nil || probeErr != nil || !expectedExit {
		return unknown("compiled-check-error"), errors.Join(ErrCompiledExecution, decodeErr, value.err, probeErr, waitErr)
	}
	return result, nil
}
