// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	contract "github.com/jay94ks/seafield/lifecycle/v1"
)

func probeRequest() contract.Request {
	r := testDefinition().Request
	r.RunID = hashText("guarded-probe-run")
	r.DeadlineUnixMilli = time.Now().Add(time.Second).UnixMilli()
	return r
}

type probeFixture struct {
	healthz    func(context.Context, contract.HTTPProbe) (contract.HTTPResult, error)
	connect    func(context.Context, contract.TCPProbe) (contract.TCPResult, error)
	exec       func(context.Context, contract.ExecProbe) (contract.ExecResult, error)
	file       func(context.Context, contract.FileProbe) (contract.FileResult, error)
	dependency func(context.Context, contract.DependencyProbe) (contract.DependencyResult, error)
}

func (p *probeFixture) Healthz(c context.Context, q contract.HTTPProbe) (contract.HTTPResult, error) {
	return p.healthz(c, q)
}
func (p *probeFixture) Connect(c context.Context, q contract.TCPProbe) (contract.TCPResult, error) {
	if p.connect == nil {
		return contract.TCPResult{}, ErrContract
	}
	return p.connect(c, q)
}
func (p *probeFixture) Exec(c context.Context, q contract.ExecProbe) (contract.ExecResult, error) {
	return p.exec(c, q)
}
func (p *probeFixture) File(c context.Context, q contract.FileProbe) (contract.FileResult, error) {
	return p.file(c, q)
}
func (p *probeFixture) Dependency(c context.Context, q contract.DependencyProbe) (contract.DependencyResult, error) {
	return p.dependency(c, q)
}

func TestCustomConnectionKeepsOriginalServiceCapabilityAndByteBudget(t *testing.T) {
	request, policy := probeRequest(), sourcePolicy()
	policy.Execution.Capabilities = append([]string{"connect"}, policy.Execution.Capabilities...)
	calls := 0
	output := []byte("PONG")
	native := &probeFixture{connect: func(ctx context.Context, q contract.TCPProbe) (contract.TCPResult, error) {
		calls++
		deadline, ok := ctx.Deadline()
		if !ok || deadline.UnixMilli() > request.DeadlineUnixMilli || q.Service != "web" || string(q.Request) != "PING" || q.ReadBytes != 4 {
			t.Fatal("custom connection widened its original input", q)
		}
		q.Request[0] = 'X'
		return contract.TCPResult{Connected: true, Data: output}, nil
	}}
	guard, err := GuardProbe(context.Background(), request, policy, native)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []contract.TCPProbe{
		{Service: "other", Port: 80}, {Port: 0}, {Port: 80, ReadBytes: -1},
		{Port: 80, ReadBytes: policy.Execution.ProbeBytes, Request: []byte("too-much")},
	} {
		if _, err := guard.Connect(context.Background(), bad); err == nil {
			t.Fatal("invalid connection reached the native adapter")
		}
	}
	if calls != 0 {
		t.Fatal("rejected input produced a connection")
	}
	q := contract.TCPProbe{Port: 80, Request: []byte("PING"), ReadBytes: 4}
	r, err := guard.Connect(context.Background(), q)
	if err != nil || !r.Connected || string(r.Data) != "PONG" || calls != 1 || string(q.Request) != "PING" {
		t.Fatal(r, err)
	}
	r.Data[0] = 'X'
	if string(output) != "PONG" {
		t.Fatal("script mutated native response storage")
	}
	policy.Execution.Capabilities = sourcePolicy().Execution.Capabilities
	denied, err := GuardProbe(context.Background(), request, policy, native)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = denied.Connect(context.Background(), q); err == nil || calls != 1 {
		t.Fatal("missing connect capability bypassed")
	}
}

func TestCheckerProbeSharesBuiltinValidationWithoutWideningTargetsOrCapabilities(t *testing.T) {
	request, policy := probeRequest(), sourcePolicy()
	calls := 0
	native := &probeFixture{file: func(ctx context.Context, q contract.FileProbe) (contract.FileResult, error) {
		calls++
		deadline, ok := ctx.Deadline()
		if !ok || deadline.UnixMilli() != request.DeadlineUnixMilli || q.Service != "web" || q.Kind != "any" {
			t.Fatal("native call escaped original bounds")
		}
		return contract.FileResult{Exists: true, Match: true, Kind: "regular", Mode: 0444}, nil
	}}
	guard, err := GuardProbe(context.Background(), request, policy, native)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []contract.FileProbe{{Service: "other", Path: "/ready"}, {Service: "web", Path: "../host"}, {Service: "web", Path: "/"}, {Service: "web", Path: "/ready", Kind: "unsupported"}} {
		if _, err := guard.File(context.Background(), q); err == nil {
			t.Fatal("invalid probe reached native")
		}
	}
	if _, err := guard.Exec(context.Background(), contract.ExecProbe{Service: "web", Argv: []string{"echo", "no-exec-capability"}}); err == nil {
		t.Fatal("scope capability bypass")
	}
	if calls != 0 {
		t.Fatal("invalid input produced external effect")
	}
	if r, err := guard.File(context.Background(), contract.FileProbe{Service: "web", Path: "/ready"}); err != nil || !r.Match || calls != 1 {
		t.Fatal(r, err)
	}
	if _, err := guard.File(nil, contract.FileProbe{Service: "web", Path: "/ready"}); err == nil {
		t.Fatal("nil context accepted")
	}
}

func TestCheckerProbeOriginalCancellationAndPolicySnapshotSurviveCallerMutation(t *testing.T) {
	request, policy := probeRequest(), sourcePolicy()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	native := &probeFixture{file: func(child context.Context, _ contract.FileProbe) (contract.FileResult, error) {
		cancel()
		select {
		case <-child.Done():
			return contract.FileResult{}, child.Err()
		case <-time.After(time.Second):
			t.Fatal("Background bypassed original cancellation")
			return contract.FileResult{}, nil
		}
	}}
	guard, err := GuardProbe(ctx, request, policy, native)
	if err != nil {
		t.Fatal(err)
	}
	request.Targets[0].Service = "other"
	policy.Execution.Capabilities[0] = "exec"
	if _, err := guard.File(context.Background(), contract.FileProbe{Service: "web", Path: "/ready"}); !errors.Is(err, context.Canceled) {
		t.Fatal("original request/policy not retained", err)
	}
}

func TestCheckerProbeBoundsNativeOutputAndChecksOriginalDependencyGeneration(t *testing.T) {
	request, policy := probeRequest(), sourcePolicy()
	policy.Execution.Capabilities = []string{"dependency", "exec", "file", "healthz"}
	stdout := []byte("ready")
	native := &probeFixture{
		exec: func(_ context.Context, q contract.ExecProbe) (contract.ExecResult, error) {
			if !slices.Equal(q.Argv, []string{"/bin/ready", "--once"}) {
				t.Fatal("implicit shell or changed argv")
			}
			return contract.ExecResult{Exited: true, Stdout: stdout}, nil
		},
		healthz: func(context.Context, contract.HTTPProbe) (contract.HTTPResult, error) {
			return contract.HTTPResult{StatusCode: 503, Match: true}, nil
		},
		file: func(context.Context, contract.FileProbe) (contract.FileResult, error) {
			return contract.FileResult{Exists: false, Match: true}, nil
		},
		dependency: func(context.Context, contract.DependencyProbe) (contract.DependencyResult, error) {
			return contract.DependencyResult{Status: contract.Pass, Generation: request.Targets[0].Generation, Revision: request.Targets[0].Revision - 1}, nil
		},
	}
	guard, err := GuardProbe(context.Background(), request, policy, native)
	if err != nil {
		t.Fatal(err)
	}
	q := contract.ExecProbe{Service: "web", Argv: []string{"/bin/ready", "--once"}, MaxBytes: 1}
	if _, err := guard.Exec(context.Background(), q); err == nil {
		t.Fatal("oversized native output became usable")
	}
	q.MaxBytes = 10
	r, err := guard.Exec(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	r.Stdout[0] ^= 1
	if string(stdout) != "ready" {
		t.Fatal("SDK output aliases native storage")
	}
	q.MaxBytes = policy.Execution.ProbeBytes + 1
	if _, err := guard.Exec(context.Background(), q); err == nil {
		t.Fatal("per-probe output policy bypass")
	}
	if _, err := guard.Healthz(context.Background(), contract.HTTPProbe{Service: "web", Path: "/ready", Port: 80}); err == nil {
		t.Fatal("contradictory HTTP Match accepted")
	}
	if _, err := guard.File(context.Background(), contract.FileProbe{Service: "web", Path: "/ready"}); err == nil {
		t.Fatal("missing file became a match")
	}
	if _, err := guard.Dependency(context.Background(), contract.DependencyProbe{Service: "web", Condition: "service_healthy"}); !errors.Is(err, ErrStale) {
		t.Fatal("old generation/revision became current", err)
	}
}
