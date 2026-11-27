// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/reconcile"
)

type checkerPreparationWork struct {
	use     [32]byte
	task    deployment.ObjectRef
	binding [32]byte
	done    chan struct{}
	stop    context.CancelFunc
	err     error
}

// Only one finite source/cache preparation runs at a time. The common module
// loop can still report compiler closures and revoke an original parent while
// this worker waits for source bytes or remote current cache observations.
func (r *Runtime) queueAppCheckers(ctx context.Context, v cluster.View, b deployment.Binding, task deployment.ObjectRef) error {
	if b.Needs().Lifecycle == nil {
		return nil
	}
	if ctx.Err() != nil || r.ctx.Err() != nil {
		return reconcile.ErrPending
	}
	u, ok := control.CheckerBindingUse(b)
	if !ok {
		return reconcile.ErrPending
	}
	r.checkerPreparationMu.Lock()
	defer r.checkerPreparationMu.Unlock()
	if work := r.checkerPreparation; work != nil {
		select {
		case <-work.done:
			r.checkerPreparation = nil
			work.stop()
			if work.use == u.Digest() && work.task == task && work.binding == b.Digest() {
				return work.err
			}
		default:
			return reconcile.ErrPending
		}
	}
	workctx, stop := context.WithCancel(r.ctx)
	work := &checkerPreparationWork{use: u.Digest(), task: task, binding: b.Digest(), done: make(chan struct{}), stop: stop}
	r.checkerPreparation = work
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer stop()
		err := r.prepareAppCheckers(workctx, v, b, task)
		r.checkerPreparationMu.Lock()
		work.err = err
		close(work.done)
		r.checkerPreparationMu.Unlock()
		r.wakeReport()
	}()
	return reconcile.ErrPending
}

func (r *Runtime) cancelStaleCheckerPreparation(v cluster.View) {
	r.checkerPreparationMu.Lock()
	defer r.checkerPreparationMu.Unlock()
	work := r.checkerPreparation
	if work == nil {
		return
	}
	select {
	case <-work.done:
		return
	default:
	}
	// A local read may cancel; every source/reserve/native permission still
	// comes from its own latest quorum edge. No local view issues new work.
	if _, err := r.controlPolicy.AppBindingPermit(v.State, r.Identity.Public, control.AppBindingRequest{Task: work.task, Digest: work.binding, At: time.Now().Unix()}); err != nil {
		work.stop()
	}
}
