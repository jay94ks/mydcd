// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"runtime"
	"testing"
	"time"

	contract "github.com/jay94ks/mydcd/lifecycle/v1"
)

func TestCompiledCheckerCustomTCPUsesSameGuardAndOriginalProbeChannel(t *testing.T) {
	request, policy := probeRequest(), sourcePolicy()
	policy.Execution.Capabilities = append([]string{"connect"}, policy.Execution.Capabilities...)
	ctx, cancel := context.WithDeadline(context.Background(), time.UnixMilli(request.DeadlineUnixMilli))
	defer cancel()
	calls := 0
	guard, err := GuardProbe(ctx, request, policy, &probeFixture{connect: func(_ context.Context, q contract.TCPProbe) (contract.TCPResult, error) {
		calls++
		if q.Service != "web" || string(q.Request) != "PING" || q.ReadBytes != 4 {
			t.Error("compiled connection changed", q)
		}
		return contract.TCPResult{Connected: true, Data: []byte("PONG")}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	parent, child := net.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- ServeProbes(ctx, request, parent, func(ctx context.Context, call ProbeCall) (ProbeReply, error) { return DispatchProbe(ctx, call, guard) })
	}()
	raw, _ := json.Marshal(request)
	var out bytes.Buffer
	exit := RunCompiled(ctx, CompiledExpectation{Tenant: request.Tenant, SourceDigest: request.SourceDigest, Toolchain: runtime.Version(), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH},
		func(ctx context.Context, _ contract.Request, p contract.Probe) (contract.Result, error) {
			r, err := p.Connect(ctx, contract.TCPProbe{Port: 80, Request: []byte("PING"), ReadBytes: 4})
			if err != nil || !r.Connected || string(r.Data) != "PONG" {
				return contract.Result{Schema: 1, Status: contract.Unknown, Reason: "connect-error"}, err
			}
			return contract.Result{Schema: 1, Status: contract.Pass, Reason: "alive"}, nil
		}, bytes.NewReader(raw), child, &out)
	if err = <-done; err != nil || calls != 1 {
		t.Fatal("compiled probe channel", err, calls)
	}
	result, err := DecodeExitResult(out.Bytes(), exit)
	if err != nil || result.Status != contract.Pass {
		t.Fatal("same compiled SDK result", result, err)
	}
}

func TestCheckerProbeFDUsesOriginalBindingAndStableEffectID(t *testing.T) {
	request := probeRequest()
	request.DeadlineUnixMilli = time.Now().Add(5 * time.Second).UnixMilli()
	ctx, cancel := context.WithDeadline(context.Background(), time.UnixMilli(request.DeadlineUnixMilli))
	defer cancel()
	parent, child := net.Pipe()
	done := make(chan error, 1)
	var original ProbeCall
	go func() {
		done <- ServeProbes(ctx, request, parent, func(_ context.Context, c ProbeCall) (ProbeReply, error) {
			original = c
			return ProbeReply{Schema: 1, Binding: c.Binding, Sequence: c.Sequence, Kind: c.Kind, File: &contract.FileResult{Exists: true, Match: true, Kind: "regular", Mode: 0444}}, nil
		})
	}()
	probe, channel, err := OpenProbeClient(ctx, request, child)
	if err != nil {
		t.Fatal(err)
	}
	r, err := probe.File(context.Background(), contract.FileProbe{Service: "web", Path: "/ready", Kind: "regular"})
	if err != nil || !r.Match {
		t.Fatal(r, err)
	}
	_ = channel.Close()
	if channel.Err() != nil || <-done != nil || original.Sequence != 1 || original.Binding != requestDigest(request) {
		t.Fatal("original probe FD binding")
	}
	changed := original
	changed.DeadlineUnixMilli--
	changed.File = &contract.FileProbe{Service: "web", Path: "/changed", Kind: "regular"}
	if changed.ID() != original.ID() || changed.Digest() == original.Digest() {
		t.Fatal("changed payload created replacement native effect ID")
	}
	changed.Sequence++
	if changed.ID() == original.ID() {
		t.Fatal("probe sequence reused effect identity")
	}
}

func TestCheckerProbeLostReplyDoesNotRepeatEffectOrPublishSwallowedError(t *testing.T) {
	request := probeRequest()
	request.DeadlineUnixMilli = time.Now().Add(5 * time.Second).UnixMilli()
	ctx, cancel := context.WithDeadline(context.Background(), time.UnixMilli(request.DeadlineUnixMilli))
	defer cancel()
	parent, child := net.Pipe()
	calls := 0
	done := make(chan error, 1)
	go func() {
		done <- ServeProbes(ctx, request, parent, func(_ context.Context, c ProbeCall) (ProbeReply, error) {
			calls++
			_ = parent.Close() // the fake native effect happened, its reply is lost
			return ProbeReply{Schema: 1, Binding: c.Binding, Sequence: c.Sequence, Kind: c.Kind, File: &contract.FileResult{Exists: true, Match: true, Kind: "regular"}}, nil
		})
	}()
	raw, _ := json.Marshal(request)
	var out bytes.Buffer
	exit := RunCompiled(ctx, CompiledExpectation{Tenant: request.Tenant, SourceDigest: request.SourceDigest, Toolchain: runtime.Version(), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH},
		func(c context.Context, _ contract.Request, p contract.Probe) (contract.Result, error) {
			_, _ = p.File(c, contract.FileProbe{Service: "web", Path: "/ready", Kind: "regular"})
			_, _ = p.File(c, contract.FileProbe{Service: "web", Path: "/ready", Kind: "regular"})
			return contract.Result{Schema: 1, Status: contract.Pass, Reason: "ignored-error"}, nil
		}, bytes.NewReader(raw), child, &out)
	if err := <-done; err == nil || calls != 1 {
		t.Fatal("lost reply repeated or erased original effect", err, calls)
	}
	result, err := DecodeExitResult(out.Bytes(), exit)
	if err != nil || result.Status != contract.Unknown || exit != 2 {
		t.Fatal("swallowed probe error published pass", result, exit, err)
	}
}

func TestCheckerProbeFDRejectsWrongBindingAndUnboundedFrameBeforeDispatch(t *testing.T) {
	request := probeRequest()
	request.DeadlineUnixMilli = time.Now().Add(5 * time.Second).UnixMilli()
	ctx, cancel := context.WithDeadline(context.Background(), time.UnixMilli(request.DeadlineUnixMilli))
	defer cancel()
	parent, child := net.Pipe()
	done := make(chan error, 1)
	calls := 0
	go func() {
		done <- ServeProbes(ctx, request, parent, func(context.Context, ProbeCall) (ProbeReply, error) {
			calls++
			return ProbeReply{}, errors.New("private-native-error")
		})
	}()
	wrong := ProbeCall{Schema: 1, Binding: [32]byte{1}, DeadlineUnixMilli: request.DeadlineUnixMilli, Kind: "hello"}
	if err := writeProbeFrame(child, wrong); err != nil {
		t.Fatal(err)
	}
	_ = child.Close()
	if <-done == nil || calls != 0 {
		t.Fatal("wrong run reached native")
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], MaxProbeFrameBytes+1)
	if _, err := readProbeFrame[ProbeCall](bytes.NewReader(size[:])); err == nil {
		t.Fatal("oversized frame accepted")
	}
	if _, err := readProbeFrame[ProbeCall](bytes.NewReader([]byte{0, 0})); err == nil {
		t.Fatal("truncated prefix accepted")
	}
}
