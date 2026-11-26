// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/jay94ks/mydcd/internal/engine"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
	contract "github.com/jay94ks/mydcd/lifecycle/v1"
)

// ServiceProbe owns this check's network/read/explicit exec calls. Each call
// borrows the original Task's A3 consumer. Exec additionally needs a durable
// receipt and its current capability; this does not grant container control.
type ServiceProbe struct {
	manager   *Manager
	request   contract.Request
	authorize func(context.Context, string, contract.Target) error
	ctx       context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	closed    bool
	sequence  uint64
	active    sync.WaitGroup
	done      chan struct{}
	cleanupMu sync.Mutex
	pending   []ReadProbeLease
	execMu    sync.Mutex
	execSave  func(ProbeExecReceipt) error
	execs     []ProbeExecReceipt
}

func (m *Manager) OpenServiceProbe(ctx context.Context, request contract.Request, authorize func(context.Context, string, contract.Target) error, execSave ...func(ProbeExecReceipt) error) (*ServiceProbe, error) {
	if m == nil || ctx == nil || authorize == nil || checker.ValidateRequest(request) != nil || ctx.Err() != nil || len(execSave) > 1 || len(execSave) == 1 && execSave[0] == nil {
		return nil, ErrPlacement
	}
	raw, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	owned, err := checker.DecodeRequest(raw)
	if err != nil {
		return nil, err
	}
	child, cancel := context.WithDeadline(ctx, time.UnixMilli(owned.DeadlineUnixMilli))
	if child.Err() != nil {
		cancel()
		return nil, child.Err()
	}
	p := &ServiceProbe{manager: m, request: owned, authorize: authorize, ctx: child, cancel: cancel, done: make(chan struct{})}
	if len(execSave) == 1 {
		p.execSave = execSave[0]
	}
	return p, nil
}

// withCall shares the SAME run ordinal, cancellation and active-call join
// across local and remote native I/O. A foreign target never borrows here.
func (p *ServiceProbe) withCall(ctx context.Context, kind, service string, remote bool, invoke func(context.Context, contract.Target, uint64, func(context.Context) error) error) error {
	if p == nil || ctx == nil || invoke == nil {
		return ErrPlacement
	}
	p.mu.Lock()
	if p.closed || p.manager == nil || p.ctx.Err() != nil || ctx.Err() != nil || p.sequence >= checker.MaxProbeCalls {
		p.mu.Unlock()
		return ErrPlacement
	}
	if service == "" && len(p.request.Targets) == 1 {
		service = p.request.Targets[0].Service
	}
	var target contract.Target
	for _, candidate := range p.request.Targets {
		if candidate.Service == service {
			target = candidate
		}
	}
	if target.TaskKey == "" || p.manager.driver == nil || p.manager.driver.Engine == nil || (p.manager.driver.Engine.Owner != p.request.Cluster+"/"+target.Owner) != remote {
		p.mu.Unlock()
		return ErrPlacement
	}
	p.sequence++
	sequence := p.sequence
	p.active.Add(1)
	p.mu.Unlock()
	defer p.active.Done()
	child, cancel := context.WithDeadline(ctx, time.UnixMilli(p.request.DeadlineUnixMilli))
	stop := context.AfterFunc(p.ctx, cancel)
	defer func() { stop(); cancel() }()
	authorize := func(ctx context.Context) error { return p.authorize(ctx, kind, target) }
	if err := authorize(child); err != nil {
		return err
	}
	return invoke(child, target, sequence, authorize)
}

func (p *ServiceProbe) withLease(ctx context.Context, kind, service string, read func(context.Context, ReadProbeLease, func(context.Context) error) error) (resultErr error) {
	if read == nil {
		return ErrPlacement
	}
	return p.withCall(ctx, kind, service, false, func(child context.Context, target contract.Target, sequence uint64, authorize func(context.Context) error) (resultErr error) {
		call := checker.ProbeCall{Binding: checker.ProbeBinding(p.request), Sequence: sequence}.ID()
		lease, err := p.manager.BorrowReadProbe(child, target.TaskKey, target.Generation, target.Revision, target.NativeID, p.request.RunID, call)
		if lease.Pin.Generation != 0 {
			defer func() {
				if err := p.manager.ReturnReadProbe(lease); err != nil {
					p.mu.Lock()
					p.pending = append(p.pending, lease)
					p.mu.Unlock()
					resultErr = errors.Join(resultErr, err)
				}
			}()
		}
		if err != nil {
			return err
		}
		if target.StartedAt != "" && lease.Target.Status.StartedAt != target.StartedAt {
			return engine.ErrOwnership
		}
		return read(child, lease, authorize)
	})
}

// RemoteCall only routes a foreign target through an authenticated dispatcher.
// The calling Runtime persists sent/closure in its ORIGINAL observation; Close
// joins this callback's client I/O, never infers the remote exec has ended.
func (p *ServiceProbe) RemoteCall(ctx context.Context, call checker.ProbeCall, dispatch checker.ProbeDispatch) (reply checker.ProbeReply, err error) {
	if p == nil || ctx == nil || dispatch == nil {
		return reply, ErrPlacement
	}
	call.Schema, call.Binding, call.Sequence = 1, checker.ProbeBinding(p.request), 1
	call.DeadlineUnixMilli = p.request.DeadlineUnixMilli
	if deadline, ok := ctx.Deadline(); ok && deadline.UnixMilli() < call.DeadlineUnixMilli {
		call.DeadlineUnixMilli = deadline.UnixMilli()
	}
	service, e := call.TargetService(p.request)
	if e != nil || call.Kind == "dependency" {
		return reply, checker.ErrContract
	}
	err = p.withCall(ctx, call.Kind, service, true, func(ctx context.Context, _ contract.Target, sequence uint64, _ func(context.Context) error) error {
		call.Sequence = sequence
		if deadline, ok := ctx.Deadline(); ok && deadline.UnixMilli() < call.DeadlineUnixMilli {
			call.DeadlineUnixMilli = deadline.UnixMilli()
		}
		var err error
		reply, err = dispatch(ctx, call)
		if err != nil {
			return err
		}
		if err = reply.Validate(call); err != nil {
			return err
		}
		if reply.Failed {
			return checker.ErrProbeRPC
		}
		return nil
	})
	return reply, err
}

func (p *ServiceProbe) Connect(ctx context.Context, q contract.TCPProbe) (result contract.TCPResult, err error) {
	err = p.withLease(ctx, "connect", q.Service, func(ctx context.Context, lease ReadProbeLease, authorize func(context.Context) error) error {
		result, err = p.manager.ReadProbeTCP(ctx, lease, q, authorize)
		return err
	})
	return result, err
}

func (p *ServiceProbe) Healthz(ctx context.Context, q contract.HTTPProbe) (result contract.HTTPResult, err error) {
	err = p.withLease(ctx, "healthz", q.Service, func(ctx context.Context, lease ReadProbeLease, authorize func(context.Context) error) error {
		result, err = p.manager.ReadProbeHTTP(ctx, lease, q, authorize)
		return err
	})
	return result, err
}

func (p *ServiceProbe) File(ctx context.Context, q contract.FileProbe) (result contract.FileResult, err error) {
	err = p.withLease(ctx, "file", q.Service, func(ctx context.Context, lease ReadProbeLease, authorize func(context.Context) error) error {
		result, err = p.manager.ReadProbeFile(ctx, lease, q, authorize)
		return err
	})
	return result, err
}

func (p *ServiceProbe) Dependency(ctx context.Context, q contract.DependencyProbe) (result contract.DependencyResult, err error) {
	if q.Condition != "service_started" && q.Condition != "service_healthy" && q.Condition != "service_completed_successfully" {
		return result, ErrPlacement
	}
	err = p.withLease(ctx, "dependency", q.Service, func(ctx context.Context, lease ReadProbeLease, authorize func(context.Context) error) error {
		status := lease.Target.Status
		if q.Condition == "service_healthy" {
			var err error
			status, err = p.manager.Status(ctx, lease.Target.Key)
			if err != nil || status.NativeID != lease.Target.Status.NativeID {
				return errors.Join(ErrPlacement, err)
			}
		}
		pass := q.Condition == "service_started" && (status.Running || status.Exit != nil) || q.Condition == "service_healthy" && status.Ready || q.Condition == "service_completed_successfully" && status.Exit != nil && status.Exit.Code == 0
		result = contract.DependencyResult{Status: contract.Fail, Generation: lease.Target.Generation, Revision: lease.Target.Revision}
		if pass {
			result.Status = contract.Pass
		}
		if err := p.manager.CheckReadProbe(ctx, lease); err != nil {
			return err
		}
		return authorize(ctx)
	})
	return result, err
}

func (p *ServiceProbe) Exec(ctx context.Context, q contract.ExecProbe) (result contract.ExecResult, err error) {
	if p == nil || p.execSave == nil {
		return result, ErrProcess
	}
	if q.Service == "" && len(p.request.Targets) == 1 {
		q.Service = p.request.Targets[0].Service
	}
	if !validExecProbe(q) {
		return result, checker.ErrContract
	}
	err = p.withLease(ctx, "exec", q.Service, func(ctx context.Context, lease ReadProbeLease, authorize func(context.Context) error) error {
		result, err = p.manager.ExecuteProbeExec(ctx, p.request, lease, q, p.saveExec, authorize)
		return err
	})
	return result, err
}

func (p *ServiceProbe) saveExec(next ProbeExecReceipt) error {
	p.execMu.Lock()
	defer p.execMu.Unlock()
	if next.Validate(p.request) != nil {
		return checker.ErrContract
	}
	index := -1
	for i, old := range p.execs {
		if old.Call != next.Call {
			continue
		}
		if !next.CanFollow(old) {
			return checker.ErrContract
		}
		index = i
	}
	if index < 0 && (len(p.execs) >= checker.MaxProbeCalls || next.Phase != ProbeExecCreating) {
		return checker.ErrContract
	}
	if err := p.execSave(next); err != nil {
		return err
	}
	if index < 0 {
		p.execs = append(p.execs, next)
	} else {
		p.execs[index] = next
	}
	return nil
}

// Close blocks new calls, cancels/joins I/O and returns its original pins.
// A short wait keeps the same handle. Native exec uncertainty survives in the
// saved checker row and is recovered by Runtime, never inferred from I/O close.
func (p *ServiceProbe) Close(ctx context.Context) error {
	if p == nil || ctx == nil {
		return ErrPlacement
	}
	p.mu.Lock()
	if p.manager == nil || p.cancel == nil || p.done == nil {
		p.mu.Unlock()
		return ErrPlacement
	}
	if !p.closed {
		p.closed = true
		p.cancel()
		go func() { p.active.Wait(); close(p.done) }()
	}
	done := p.done
	p.mu.Unlock()
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	p.cleanupMu.Lock()
	defer p.cleanupMu.Unlock()
	p.mu.Lock()
	pending := p.pending
	p.pending = nil
	p.mu.Unlock()
	var result error
	for _, lease := range pending {
		if err := p.manager.ReturnReadProbe(lease); err != nil {
			p.mu.Lock()
			p.pending = append(p.pending, lease)
			p.mu.Unlock()
			result = errors.Join(result, err)
		}
	}
	p.execMu.Lock()
	for _, exec := range p.execs {
		if !exec.Terminal() {
			result = errors.Join(result, ErrProbeExecPending)
			break
		}
	}
	p.execMu.Unlock()
	return result
}
