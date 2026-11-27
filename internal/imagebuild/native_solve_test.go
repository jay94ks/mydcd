// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/registryclient"
)

func TestSDKNativePlanIsFinitePrivateAndDoesNotRewriteLegacyJournal(t *testing.T) {
	f := newNativeFixture(t, false)
	legacy, err := f.plan.CreateOptions(f.spec)
	if err != nil {
		t.Fatal(err)
	}
	sdk, err := f.plan.createOptionsWithTLS(f.spec, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if sdk.Config.Entrypoint[len(sdk.Config.Entrypoint)-1] != "/usr/bin/rootlesskit" || strings.Join(sdk.Config.Cmd, " ") != "/usr/bin/buildkitd --addr unix:///output/buildkit.sock --oci-worker-snapshotter=native --containerd-worker=false --root /home/user/.local/share/buildkit --config /input/buildkitd.toml" || legacy.Config.Entrypoint[len(legacy.Config.Entrypoint)-1] != "/usr/bin/buildctl-daemonless.sh" || len(sdk.HostConfig.PortBindings) != 0 || sdk.HostConfig.Privileged {
		t.Fatal("SDK daemon broadened exposure or rewrote old mode")
	}
	f.prepare(f.ctx())
	if err := f.jobs.UseSDK(f.ctx(), f.spec); !errors.Is(err, ErrConflict) {
		t.Fatal("created legacy object changed mode", err)
	}
}

func TestSDKSocketReadinessAndForeignLeafDoNotDispatchSolve(t *testing.T) {
	f := newNativeFixture(t, false)
	ctx := f.ctx()
	if err := f.jobs.UseSDK(ctx, f.spec); err != nil {
		t.Fatal(err)
	}
	options, err := f.plan.createOptionsWithTLS(f.spec, true, true)
	if err != nil {
		t.Fatal(err)
	}
	f.edit(func() { f.options = options })
	f.prepare(ctx)
	if err := f.jobs.Start(ctx, f.spec); err != nil {
		t.Fatal(err)
	}
	auth, err := NewBuildKitPullAuth(f.spec, nil, func(context.Context) error { return nil }, func(context.Context, []Source, registryclient.PullTokenChallenge) (registryclient.PullToken, error) {
		return registryclient.PullToken{}, ErrSourceFetch
	})
	if err != nil {
		t.Fatal(err)
	}
	defer auth.Close()
	var logs bytes.Buffer
	filter, err := containerops.NewRedactor(&logs, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer filter.Destroy()
	if _, err := f.jobs.StartSolve(ctx, f.spec, auth, filter); !errors.Is(err, reconcile.ErrPending) {
		t.Fatal("missing socket was not a readiness wait", err)
	}
	record, err := f.jobs.Record(f.spec)
	if err != nil || record.Solve == nil || record.Solve.Sent {
		t.Fatal("readiness dispatched solve", err)
	}
	paths := nativeWorkspacePaths(f.spec, f.plan)
	if err := os.Symlink(filepath.Join(t.TempDir(), "foreign.sock"), filepath.Join(paths[1], "buildkit.sock")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.jobs.StartSolve(ctx, f.spec, auth, filter); !errors.Is(err, ErrStorage) {
		t.Fatal("foreign socket symlink accepted", err)
	}
	record, err = f.jobs.Record(f.spec)
	if err != nil || record.Solve.Sent {
		t.Fatal("foreign leaf dispatched solve", err)
	}
}

// SDK result is injected here to isolate durable result/process distinction.
// The Engine HTTP/Stop/Wait/Remove clients and original journal are real;
// actual BuildKit execution is an RQ6 final adapter requirement.
func TestSDKPositiveResultStillNeedsNativeClosureAndStopIsNotUserCancel(t *testing.T) {
	f := newNativeFixture(t, false)
	ctx := f.ctx()
	if err := f.jobs.UseSDK(ctx, f.spec); err != nil {
		t.Fatal(err)
	}
	options, err := f.plan.createOptionsWithTLS(f.spec, true, true)
	if err != nil {
		t.Fatal(err)
	}
	f.edit(func() { f.options = options })
	f.prepare(ctx)
	if err := f.jobs.Start(ctx, f.spec); err != nil {
		t.Fatal(err)
	}
	f.jobs.mu.Lock()
	record, err := f.jobs.load(f.spec)
	if err == nil {
		record.Solve.Sent, record.Solve.Returned, record.Solve.Code = true, true, "OK"
		record.Solve.Directory = NativeDirectory{Device: 1, Inode: 1, Mode: 0700}
		err = f.jobs.save(record)
	}
	f.jobs.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if nativeOutputSucceeded(record) {
		t.Fatal("SDK result substituted for process closure")
	}
	var calls atomic.Int32
	f.jobs.authorize = func(context.Context, JobSpec, bool) (NativeGrant, error) {
		calls.Add(1)
		return NativeGrant{}, ErrConflict
	}
	if err := f.jobs.StopSDK(ctx, f.spec); err != nil {
		t.Fatal(err)
	}
	if err := f.jobs.Remove(ctx, f.spec); err != nil {
		t.Fatal(err)
	}
	record, err = f.jobs.Record(f.spec)
	if err != nil || record.Cancel || !record.Solve.Stopping || !nativeOutputSucceeded(record) || calls.Load() != 0 {
		t.Fatal("positive stop queried quorum or became user cancel", err, calls.Load())
	}
	record.ExitCode = 143
	if !nativeOutputSucceeded(record) {
		t.Fatal("daemon TERM code erased positive SDK result")
	}
	record.Solve.Returned, record.Solve.Code = false, ""
	record.ExitCode = 0
	if nativeOutputSucceeded(record) {
		t.Fatal("daemon exit zero fabricated solve success")
	}
}

func TestSDKSentOriginalSurvivesRestartWithoutAnotherSolveDispatch(t *testing.T) {
	f := newNativeFixture(t, false)
	ctx := f.ctx()
	if err := f.jobs.UseSDK(ctx, f.spec); err != nil {
		t.Fatal(err)
	}
	options, err := f.plan.createOptionsWithTLS(f.spec, true, true)
	if err != nil {
		t.Fatal(err)
	}
	f.edit(func() { f.options = options })
	f.prepare(ctx)
	if err := f.jobs.Start(ctx, f.spec); err != nil {
		t.Fatal(err)
	}
	f.jobs.mu.Lock()
	record, err := f.jobs.load(f.spec)
	if err == nil {
		record.Solve.Sent = true
		record.Solve.Directory = NativeDirectory{Device: 1, Inode: 1, Mode: 0700}
		err = f.jobs.save(record)
	}
	f.jobs.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	f.reopen()
	auth, err := NewBuildKitPullAuth(f.spec, nil, func(context.Context) error { return nil }, func(context.Context, []Source, registryclient.PullTokenChallenge) (registryclient.PullToken, error) {
		return registryclient.PullToken{}, ErrSourceFetch
	})
	if err != nil {
		t.Fatal(err)
	}
	defer auth.Close()
	var logs bytes.Buffer
	filter, err := containerops.NewRedactor(&logs, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer filter.Destroy()
	if _, err := f.jobs.StartSolve(ctx, f.spec, auth, filter); !errors.Is(err, ErrConflict) {
		t.Fatal("sent original was resubmitted after restart", err)
	}
	record, err = f.jobs.Record(f.spec)
	if err != nil || record.Solve.Returned || !record.Solve.Sent || f.count("POST /containers/create") != 1 {
		t.Fatal("restart changed original dispatch evidence", err)
	}
}
