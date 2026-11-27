// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/internal/workload"
)

func (r *Runtime) runContainerSession(parent context.Context, session access.Session, intent containerops.SessionIntent, channel *userauth.ContainerChannel) error {
	if intent.Target.Owner != r.Identity.Public {
		owner, ok := r.nativeOwner(intent.Target.Owner)
		if !ok || !r.acceptsResourceOwner(parent, intent.Target.Node, intent.Target.Owner) {
			return sfcp.ErrAdmission
		}
		return owner.runContainerSession(parent, session, intent, channel)
	}
	r.life.RLock()
	defer r.life.RUnlock()
	if r.closed || r.workload == nil || intent.Target.Owner != r.Identity.Public {
		return sfcp.ErrAdmission
	}
	ctx, cancel := context.WithCancelCause(parent)
	defer cancel(context.Canceled)
	stop := context.AfterFunc(r.ctx, func() { cancel(context.Canceled) })
	defer stop()
	permit := func(call context.Context) error {
		call, finish := context.WithTimeout(call, 5*time.Second)
		defer finish()
		q := control.ContainerSessionPermit{Session: session, Original: session, Intent: intent}
		check := r.containerSessionPermit
		if intent.Spec.Kind == "logs" {
			check = r.localContainerSessionPermit
		}
		if err := check(call, q); err != nil {
			return err
		}
		t := intent.Target
		actual, err := r.workload.ProbeTarget(call, t.Instance, t.Generation, t.Revision)
		if err != nil || actual.Status.NativeID != t.NativeID || actual.Status.StartedAt != t.StartedAt {
			return errors.Join(engine.ErrOwnership, err)
		}
		return nil
	}
	if err := permit(ctx); err != nil {
		return channel.Send(containerops.SessionRecord{Kind: "error", Code: containerSessionError(err)})
	}
	guardCtx, stopGuard := context.WithCancel(ctx)
	guardDone := make(chan struct{})
	go func() {
		defer close(guardDone)
		tick := time.NewTicker(2 * time.Second)
		defer tick.Stop()
		ping := time.NewTicker(10 * time.Second)
		defer ping.Stop()
		for {
			select {
			case <-guardCtx.Done():
				return
			case <-tick.C:
				if err := permit(guardCtx); err != nil {
					cancel(err)
					return
				}
			case <-ping.C:
				if err := channel.Send(containerops.SessionRecord{Kind: "ping"}); err != nil {
					cancel(err)
					return
				}
			}
		}
	}()
	defer func() { stopGuard(); <-guardDone }()
	if intent.Spec.Kind == "attach" {
		return r.runStandaloneAttach(ctx, cancel, intent, channel, permit)
	}
	if intent.Spec.Kind == "exec" {
		return r.runContainerExec(ctx, cancel, session, intent, channel, permit, func() { stopGuard(); <-guardDone })
	}
	inputDone := make(chan struct{})
	var stopping atomic.Bool
	go func() {
		defer close(inputDone)
		for {
			record, err := channel.Receive()
			if err != nil {
				if !stopping.Load() {
					cancel(err)
				}
				return
			}
			if record.Kind == "cancel" {
				cancel(context.Canceled)
				return
			}
		}
	}()
	defer func() { stopping.Store(true); channel.StopReceive(); <-inputDone }()
	var err error
	if intent.Spec.Kind == "logs" {
		err = r.workload.FollowContainerLogs(ctx, intent.Target, *intent.Spec.Query, channel.Send)
		if err == nil {
			err = channel.Send(containerops.SessionRecord{Kind: "output-eof"})
		}
	} else {
		tick := time.NewTicker(intent.Spec.Interval)
		defer tick.Stop()
		for {
			if err = permit(ctx); err != nil {
				break
			}
			var sample containerops.Result
			sample, err = r.workload.ObserveContainer(ctx, intent.Target, *intent.Spec.Query)
			if err != nil {
				break
			}
			if err = channel.Send(containerops.SessionRecord{Kind: "sample", Sample: &sample}); err != nil {
				break
			}
			select {
			case <-ctx.Done():
				err = context.Cause(ctx)
			case <-tick.C:
				continue
			}
			break
		}
	}
	stopGuard()
	<-guardDone
	if err != nil {
		return channel.Send(containerops.SessionRecord{Kind: "error", Code: containerSessionError(err)})
	}
	return channel.Send(containerops.SessionRecord{Kind: "end"})
}

func containerSessionError(err error) string {
	if errors.Is(err, engine.ErrOwnership) {
		return "target-changed"
	}
	if errors.Is(err, access.ErrDenied) || errors.Is(err, sfcp.ErrAdmission) {
		return "denied"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	return "unavailable"
}

func (r *Runtime) runContainerExec(ctx context.Context, cancel context.CancelCauseFunc, session access.Session, intent containerops.SessionIntent, channel *userauth.ContainerChannel, permit func(context.Context) error, stopGuard func()) error {
	attached, receipt, err := r.workload.StartContainerExec(ctx, intent, func(p containerops.ExecReceipt) (containerops.ExecReceipt, bool, error) {
		return r.reserveUserExec(session, intent, p)
	}, func(p containerops.ExecReceipt) error { return r.updateUserExec(intent, p) }, permit)
	if err != nil {
		if row, loadErr := r.userExecRecord(intent); loadErr == nil {
			if sendErr := channel.Send(containerops.SessionRecord{Kind: "receipt", Receipt: &row.Receipt}); sendErr != nil {
				return sendErr
			}
		}
		// A delivered terminal application error is a completed protocol
		// exchange. Returning the native cause would make QUIC reset its send
		// side and discard the receipt/error records just written above.
		return channel.Send(containerops.SessionRecord{Kind: "error", Code: containerSessionError(err)})
	}
	if err = channel.Send(containerops.SessionRecord{Kind: "receipt", Receipt: &receipt}); err != nil {
		if attached != nil {
			_ = attached.Close()
		}
		return err
	}
	if attached == nil {
		stopGuard()
		return channel.Send(containerops.SessionRecord{Kind: "end"})
	}
	defer attached.Close()
	inputDone := make(chan struct{})
	var stopping atomic.Bool
	go func() {
		defer close(inputDone)
		for {
			record, err := channel.Receive()
			if err != nil {
				if !stopping.Load() {
					cancel(err)
				}
				return
			}
			switch record.Kind {
			case "stdin":
				for len(record.Data) > 0 {
					var n int
					n, err = attached.Write(record.Data)
					if err != nil || n == 0 {
						if err == nil {
							err = io.ErrNoProgress
						}
						break
					}
					record.Data = record.Data[n:]
				}
			case "stdin-eof":
				err = attached.CloseWrite()
				if err == nil {
					_, err = r.userExecIOFacts(intent, true, false, false)
				}
			case "resize":
				err = attached.Resize(ctx, record.Rows, record.Cols)
			case "cancel":
				cancel(context.Canceled)
				return
			}
			if err != nil {
				if !stopping.Load() {
					cancel(err)
				}
				return
			}
		}
	}()
	err = workload.StreamContainerExecOutput(attached, intent.Spec.Exec.TTY, channel.Send)
	stopping.Store(true)
	channel.StopReceive()
	_ = attached.Close()
	<-inputDone
	stopGuard()
	detached := err != nil || ctx.Err() != nil
	_, saveErr := r.userExecIOFacts(intent, false, err == nil, detached)
	if saveErr != nil {
		return saveErr
	}
	if err == nil {
		if err = channel.Send(containerops.SessionRecord{Kind: "output-eof"}); err != nil {
			return err
		}
	}
	// Docker output EOF can precede its final Inspect publication. A bounded
	// original-status observation waits for that publication, never a new start.
	observe, finish := context.WithTimeout(ctx, time.Second)
	defer finish()
	var status containerops.ExecStatus
	for {
		var readErr error
		status, readErr = r.containerExecStatusLocked(observe, session, intent)
		if readErr != nil {
			break
		}
		if status.Receipt.Phase == containerops.ExecFinished {
			break
		}
		select {
		case <-observe.Done():
			goto observed
		case <-time.After(50 * time.Millisecond):
		}
	}
observed:
	if status.Schema == 1 {
		_ = channel.Send(containerops.SessionRecord{Kind: "receipt", Receipt: &status.Receipt})
	}
	if err != nil || ctx.Err() != nil {
		if err == nil {
			err = context.Cause(ctx)
		}
		return channel.Send(containerops.SessionRecord{Kind: "error", Code: containerSessionError(err)})
	}
	return channel.Send(containerops.SessionRecord{Kind: "end"})
}
