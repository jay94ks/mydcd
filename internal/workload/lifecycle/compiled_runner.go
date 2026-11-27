// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"runtime"
	"time"

	contract "github.com/jay94ks/seafield/lifecycle/v1"
)

type CompiledExpectation struct{ Tenant, SourceDigest, Toolchain, GOOS, GOARCH string }

// RunCompiled is embedded from this SAME file in the generated standalone
// checker. Input is one bounded Request; result is a dedicated private FD.
// stdout/stderr (including package init) are diagnostics owned by the parent.
// A script result/exit code is not a container exit or a control permission.
func RunCompiled(ctx context.Context, expected CompiledExpectation, check contract.Checker, input io.Reader, probes net.Conn, result io.Writer) (exitCode int) {
	out := contract.Result{Schema: 1, Status: contract.Unknown, Reason: "checker-error"}
	exitCode = 2
	var channel *ProbeChannel
	var cancel context.CancelFunc
	defer func() {
		if recover() != nil {
			out = contract.Result{Schema: 1, Status: contract.Unknown, Reason: "checker-panic"}
		}
		if channel != nil {
			_ = channel.Close()
			if channel.Err() != nil {
				out = contract.Result{Schema: 1, Status: contract.Unknown, Reason: "probe-error"}
			}
		}
		if ctx != nil && ctx.Err() != nil {
			out = contract.Result{Schema: 1, Status: contract.Unknown, Reason: "deadline-expired"}
		}
		if cancel != nil {
			cancel()
		}
		if ValidateResult(out) != nil {
			out = contract.Result{Schema: 1, Status: contract.Unknown, Reason: "invalid-response"}
		}
		exitCode = 2
		if out.Status == contract.Pass {
			exitCode = 0
		} else if out.Status == contract.Fail {
			exitCode = 1
		}
		raw, err := json.Marshal(out)
		if result == nil || err != nil || writeProbeBytes(result, raw) != nil {
			exitCode = 2
		}
	}()
	if ctx == nil || check == nil || input == nil || probes == nil || !name(expected.Tenant) || !digest(expected.SourceDigest) || expected.Toolchain != runtime.Version() || expected.GOOS != runtime.GOOS || expected.GOARCH != runtime.GOARCH {
		return
	}
	raw, err := io.ReadAll(io.LimitReader(input, MaxRequestBytes+1))
	if err != nil {
		return
	}
	defer clear(raw)
	request, err := DecodeRequest(raw)
	if err != nil || request.Tenant != expected.Tenant || request.SourceDigest != expected.SourceDigest {
		return
	}
	// The deferred result writer cancels after it has read ctx.Err().
	deadlineCtx, stop := context.WithDeadline(ctx, time.UnixMilli(request.DeadlineUnixMilli))
	ctx, cancel = deadlineCtx, stop
	if ctx.Err() != nil {
		return
	}
	probe, opened, err := OpenProbeClient(ctx, request, probes)
	if err != nil {
		return
	}
	channel = opened
	publicContext := checkerContext{deadline: ctx.Deadline, done: ctx.Done, err: ctx.Err}
	value, err := check(publicContext, ownRequest(request), probe)
	if err == nil && ValidateResult(value) == nil {
		out = value
	}
	return
}
