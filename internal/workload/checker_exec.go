// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
	contract "github.com/jay94ks/seafield/lifecycle/v1"
	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/client"
)

var ErrProbeExecPending = errors.New("original Docker checker exec not settled")
var ErrProbeExecStream = errors.New("incomplete or invalid Docker checker exec stream")

type ProbeExecPhase string

const (
	ProbeExecCreating    ProbeExecPhase = "creating"
	ProbeExecCreated     ProbeExecPhase = "created"
	ProbeExecSent        ProbeExecPhase = "start-sent"
	ProbeExecRunning     ProbeExecPhase = "running"
	ProbeExecStreamEnded ProbeExecPhase = "stream-ended"
	ProbeExecCompleted   ProbeExecPhase = "completed"
	ProbeExecCanceled    ProbeExecPhase = "canceled"
)

// ProbeExecReceipt is private metadata in the original checker observation,
// not another operation/journal. It contains neither command output nor keys.
type ProbeExecReceipt struct {
	Schema        uint8
	RunID         string
	Call, Payload [32]byte
	Target        contract.Target
	Phase         ProbeExecPhase
	ExecID        string
}

func (p ProbeExecReceipt) Terminal() bool {
	return p.Phase == ProbeExecCompleted || p.Phase == ProbeExecCanceled
}

func (p ProbeExecReceipt) Validate(request contract.Request) error {
	if checker.ValidateRequest(request) != nil || p.Schema != 1 || p.RunID != request.RunID || p.Call == ([32]byte{}) || p.Payload == ([32]byte{}) || !slices.Contains(request.Targets, p.Target) {
		return checker.ErrContract
	}
	stamp, err := time.Parse(time.RFC3339Nano, p.Target.StartedAt)
	if err != nil || stamp.IsZero() || len(p.ExecID) > 256 || strings.ContainsAny(p.ExecID, "\x00\r\n/") {
		return checker.ErrContract
	}
	switch p.Phase {
	case ProbeExecCreating:
		if p.ExecID != "" {
			return checker.ErrContract
		}
	case ProbeExecCreated, ProbeExecSent, ProbeExecRunning, ProbeExecStreamEnded, ProbeExecCompleted:
		if p.ExecID == "" {
			return checker.ErrContract
		}
	case ProbeExecCanceled:
	default:
		return checker.ErrContract
	}
	return nil
}

// CanFollow protects the immutable original call and forward-only receipts.
func (p ProbeExecReceipt) CanFollow(old ProbeExecReceipt) bool {
	if p.Schema != old.Schema || p.RunID != old.RunID || p.Call != old.Call || p.Payload != old.Payload || p.Target != old.Target {
		return false
	}
	if old.ExecID != "" && p.ExecID != old.ExecID {
		return false
	}
	if old.ExecID == "" && p.ExecID != "" && (old.Phase != ProbeExecCreating || p.Phase != ProbeExecCreated) {
		return false
	}
	if p == old {
		return true
	}
	if old.Terminal() {
		return false
	}
	if p.Phase == ProbeExecCanceled {
		return true
	}
	switch old.Phase {
	case ProbeExecCreating:
		return p.Phase == ProbeExecCreated
	case ProbeExecCreated:
		return p.Phase == ProbeExecSent
	case ProbeExecSent:
		return p.Phase == ProbeExecRunning || p.Phase == ProbeExecStreamEnded || p.Phase == ProbeExecCompleted
	case ProbeExecRunning:
		return p.Phase == ProbeExecStreamEnded || p.Phase == ProbeExecCompleted
	case ProbeExecStreamEnded:
		return p.Phase == ProbeExecRunning || p.Phase == ProbeExecCompleted
	}
	return false
}

func validExecProbe(q contract.ExecProbe) bool {
	if q.Service == "" || len(q.Argv) == 0 || len(q.Argv) > 128 || q.Argv[0] == "" || q.MaxBytes < 1 || q.MaxBytes > 1<<20 {
		return false
	}
	for _, arg := range q.Argv {
		if len(arg) > 4096 || strings.ContainsAny(arg, "\x00\r\n") {
			return false
		}
	}
	return true
}

type probeExecOutput struct {
	data      []byte
	max       int
	truncated bool
}

// The pinned stdcopy implementation treats a partial frame's EOF as a clean
// end and allocates by its declared size. Validate framing before handing it
// to the library's demultiplexer; do not interpret a broken pipe as completion.
type probeExecFrames struct {
	source    io.Reader
	header    [8]byte
	headerAt  int
	remaining uint32
	ready     bool
}

func (r *probeExecFrames) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if !r.ready || r.headerAt == len(r.header) && r.remaining == 0 {
		n, err := io.ReadFull(r.source, r.header[:])
		if err != nil {
			if n == 0 && errors.Is(err, io.EOF) {
				return 0, io.EOF
			}
			return 0, ErrProbeExecStream
		}
		if r.header[0] < 1 || r.header[0] > 3 || r.header[1] != 0 || r.header[2] != 0 || r.header[3] != 0 {
			return 0, ErrProbeExecStream
		}
		r.remaining = binary.BigEndian.Uint32(r.header[4:])
		if r.remaining > 1<<20 {
			return 0, ErrProbeExecStream
		}
		r.headerAt, r.ready = 0, true
	}
	if r.headerAt < len(r.header) {
		n := copy(b, r.header[r.headerAt:])
		r.headerAt += n
		return n, nil
	}
	if uint32(len(b)) > r.remaining {
		b = b[:int(r.remaining)]
	}
	n, err := r.source.Read(b)
	r.remaining -= uint32(n)
	if err != nil {
		if errors.Is(err, io.EOF) && r.remaining == 0 && n > 0 {
			return n, nil
		}
		return n, ErrProbeExecStream
	}
	return n, nil
}

func (w *probeExecOutput) Write(b []byte) (int, error) {
	n := min(len(b), w.max-len(w.data))
	w.data = append(w.data, b[:n]...)
	w.truncated = w.truncated || n != len(b)
	return len(b), nil // drain the finite-context stream without growing memory
}

// ExecuteProbeExec starts one explicitly requested argv inside the exact
// original container. save must durably update the calling checker row.
// The read lease protects client I/O, not the lifetime of a native exec.
func (m *Manager) ExecuteProbeExec(ctx context.Context, request contract.Request, l ReadProbeLease, q contract.ExecProbe, save func(ProbeExecReceipt) error, authorize func(context.Context) error) (contract.ExecResult, error) {
	var result contract.ExecResult
	if m == nil || m.driver == nil || m.driver.Engine == nil || m.driver.Engine.API == nil || ctx == nil || save == nil || authorize == nil || !validExecProbe(q) || checker.ValidateRequest(request) != nil {
		return result, checker.ErrContract
	}
	var target contract.Target
	for _, t := range request.Targets {
		if t.Service == q.Service {
			target = t
		}
	}
	raw, _ := json.Marshal(q)
	p := ProbeExecReceipt{Schema: 1, RunID: request.RunID, Call: l.Call, Payload: sha256.Sum256(raw), Target: target, Phase: ProbeExecCreating}
	if p.Validate(request) != nil || l.RunID != p.RunID || l.Target.Key != target.TaskKey || l.Target.Generation != target.Generation || l.Target.Revision != target.Revision || l.Target.Status.NativeID != target.NativeID || l.Target.Status.StartedAt != target.StartedAt || m.driver.Engine.Owner != request.Cluster+"/"+target.Owner {
		return result, checker.ErrContract
	}
	check := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := authorize(ctx); err != nil {
			return err
		}
		return m.CheckReadProbe(ctx, l)
	}
	if err := check(); err != nil {
		return result, err
	}
	if !l.Target.Status.Running {
		return result, nil
	}
	if err := save(p); err != nil {
		return result, err
	}
	if err := check(); err != nil {
		p.Phase = ProbeExecCanceled
		return result, errors.Join(err, save(p))
	}
	created, err := m.driver.Engine.API.ExecCreate(ctx, target.NativeID, client.ExecCreateOptions{Cmd: slices.Clone(q.Argv), AttachStdout: true, AttachStderr: true})
	if err != nil {
		// Docker Create configures an exec but cannot start it. No Start was
		// sent even if its ID reply is unknown; preserve the original receipt.
		p.Phase = ProbeExecCanceled
		return result, errors.Join(err, save(p))
	}
	p.ExecID, p.Phase = created.ID, ProbeExecCreated
	if p.Validate(request) != nil {
		return result, checker.ErrContract
	}
	if err = save(p); err != nil {
		return result, err
	}
	if err = check(); err != nil {
		p.Phase = ProbeExecCanceled
		return result, errors.Join(err, save(p))
	}
	p.Phase = ProbeExecSent
	if err = save(p); err != nil {
		return result, err
	}
	if err = check(); err != nil {
		// The marker is durable but this owner has not called Attach yet.
		p.Phase = ProbeExecCanceled
		return result, errors.Join(err, save(p))
	}
	attached, err := m.driver.Engine.API.ExecAttach(ctx, p.ExecID, client.ExecAttachOptions{})
	if err != nil {
		return result, errors.Join(ErrProbeExecPending, err)
	}
	defer attached.Close()
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { attached.Close(); close(closed) })
	defer func() {
		if !stop() {
			<-closed
		}
	}()
	output := &probeExecOutput{max: q.MaxBytes}
	_, err = stdcopy.StdCopy(output, io.Discard, &probeExecFrames{source: attached.Reader})
	if err != nil || ctx.Err() != nil {
		// stdcopy's daemon-system-error text is private too; do not surface it.
		return result, errors.Join(ErrProbeExecPending, ErrProbeExecStream, ctx.Err())
	}
	p.Phase = ProbeExecStreamEnded
	if err = save(p); err != nil {
		return result, err
	}
	var observed contract.ExecResult
	for {
		observed, err = m.recoverProbeExec(ctx, p, func(next ProbeExecReceipt) error {
			if err := save(next); err != nil {
				return err
			}
			p = next
			return nil
		})
		if !errors.Is(err, ErrProbeExecPending) {
			break
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return result, errors.Join(ErrProbeExecPending, ctx.Err())
		case <-timer.C:
		}
	}
	if err != nil {
		return result, err
	}
	if !observed.Exited {
		return result, ErrProbeExecPending
	}
	if err = check(); err != nil {
		return result, err
	}
	observed.Stdout, observed.Truncated = output.data, output.truncated
	return observed, nil
}

// RecoverProbeExec only observes the original exec/native. It never calls
// Create/Start/Attach again, changes a Task, or uses current permission for
// cleanup. A start-sent marker alone and !Running do not prove completion.
func (m *Manager) RecoverProbeExec(ctx context.Context, request contract.Request, p ProbeExecReceipt, save func(ProbeExecReceipt) error) error {
	if p.Validate(request) != nil || save == nil || m == nil || m.driver == nil || m.driver.Engine == nil || m.driver.Engine.API == nil || m.driver.Engine.Owner != request.Cluster+"/"+p.Target.Owner || ctx == nil {
		return checker.ErrContract
	}
	_, err := m.recoverProbeExec(ctx, p, save)
	return err
}

func (m *Manager) recoverProbeExec(ctx context.Context, p ProbeExecReceipt, save func(ProbeExecReceipt) error) (contract.ExecResult, error) {
	var result contract.ExecResult
	if p.Terminal() {
		return result, nil
	}
	if p.Phase == ProbeExecCreating || p.Phase == ProbeExecCreated {
		p.Phase = ProbeExecCanceled // positive pre-Start marker
		return result, save(p)
	}
	_, err := m.driver.Engine.API.ContainerInspect(ctx, p.Target.NativeID, client.ContainerInspectOptions{})
	if cerrdefs.IsNotFound(err) {
		p.Phase = ProbeExecCanceled
		return result, save(p)
	}
	if err != nil {
		return result, errors.Join(ErrProbeExecPending, err)
	}
	got, exitKnown, err := m.driver.Engine.InspectExec(ctx, p.ExecID)
	if err != nil {
		return result, errors.Join(ErrProbeExecPending, err)
	}
	if got.ID != p.ExecID || got.ContainerID != p.Target.NativeID || got.ExitCode < 0 || got.ExitCode > 255 {
		return result, checker.ErrContract
	}
	if got.Running {
		if p.Phase != ProbeExecRunning {
			p.Phase = ProbeExecRunning
			if err = save(p); err != nil {
				return result, err
			}
		}
		return result, ErrProbeExecPending
	}
	if !exitKnown {
		return result, ErrProbeExecPending
	}
	p.Phase = ProbeExecCompleted
	if err = save(p); err != nil {
		return result, err
	}
	return contract.ExecResult{Exited: true, ExitCode: got.ExitCode}, nil
}
