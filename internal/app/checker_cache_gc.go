// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/hex"
	"errors"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
)

var errCheckerCacheFence = errors.New("current lifecycle cache collection fence unavailable")

type checkerCacheFence struct {
	Schema                     uint8
	Cluster, Owner             [32]byte
	Index, Epoch, RootRevision uint64
}

// A small latest-quorum fence avoids sending the whole source catalog over a
// bounded management response. Collection then uses the same local root, at
// least that committed index. A different root means retry, never stale GC.
func (r *Runtime) checkerCacheRetention(ctx context.Context) (checker.CacheRetention, error) {
	reply, err := r.appCall(ctx, "checker-cache-gc-fence", nil)
	if err != nil {
		return checker.CacheRetention{}, errors.Join(errCheckerCacheFence, err)
	}
	fence, err := schema.Decode[checkerCacheFence](reply.Data)
	if err != nil || reply.Local || fence.Schema != 1 || fence.Cluster != r.controlPolicy.Cluster || fence.Owner != r.commandIdentity().Public || fence.Index == 0 || fence.Epoch == 0 {
		return checker.CacheRetention{}, sfcp.ErrAdmission
	}
	view, err := r.Engine().Read(ctx, false)
	if err != nil {
		return checker.CacheRetention{}, err
	}
	if view.State.Index() < fence.Index || view.State.ModuleEpoch() != fence.Epoch || view.State.Object(control.LifecycleKey).Revision != fence.RootRevision {
		return checker.CacheRetention{}, errCheckerCacheFence
	}
	catalog, err := r.controlPolicy.Lifecycles(view.State)
	if err != nil {
		return checker.CacheRetention{}, err
	}
	rows, err := r.reports.ScanBounded(checkerObservationPrefix, maxCheckerObservationSlots, maxCheckerObservationTotal)
	if err != nil {
		return checker.CacheRetention{}, err
	}
	retention := checker.CacheRetention{Catalog: catalog}
	for _, raw := range rows {
		p, err := schema.Decode[checkerObservation](raw)
		if err != nil || p.validate(r.controlPolicy.Cluster, r.Identity.Public) != nil {
			return checker.CacheRetention{}, checker.ErrContract
		}
		if p.Checkpoint.Retire && p.Checkpoint.Active == nil && (p.Control == nil || p.Control.Terminal()) && p.remoteCallsClosed() {
			continue
		}
		request := p.Checkpoint.Definition.Request
		raw, err := hex.DecodeString(request.SourceDigest)
		if err != nil || len(raw) != 32 {
			return checker.CacheRetention{}, checker.ErrContract
		}
		var content [32]byte
		copy(content[:], raw)
		retention.Local = append(retention.Local, checker.CacheReference{Tenant: request.Tenant, Content: content})
	}
	return retention, nil
}

// Collection runs when the replicated lifecycle root this node holds changes
// (a script, use or build was added or removed), and otherwise only every
// checkerCacheIdle, which bounds how long content a finished run stopped
// using stays on disk. A failed or fenced attempt retries after
// checkerCacheRetry.
const (
	checkerCacheIdle  = 5 * time.Minute
	checkerCacheRetry = 10 * time.Second
)

type checkerCacheRoot struct{ Epoch, Revision uint64 }

// checkerCacheDue reports whether a collection should run now.
func checkerCacheDue(now, next time.Time, root, last checkerCacheRoot) bool {
	return next.IsZero() || !now.Before(next) || root != last
}

// Reuse the module loop; no new worker or idle compiler is introduced. Quorum
// loss disables reclamation and leaves every original byte/ref intact.
func (r *Runtime) collectCheckerCache() error {
	r.life.RLock()
	defer r.life.RUnlock()
	if r.closed || r.ctx.Err() != nil || r.checkerSources == nil {
		return nil
	}
	view, err := r.Engine().Read(r.ctx, false)
	if err != nil {
		return nil
	}
	root := checkerCacheRoot{Epoch: view.State.ModuleEpoch(), Revision: view.State.Object(control.LifecycleKey).Revision}
	now := time.Now()
	if !checkerCacheDue(now, r.checkerCacheNext, root, r.checkerCacheRoot) {
		return nil
	}
	r.checkerCacheNext, r.checkerCacheRoot = now.Add(checkerCacheRetry), root
	r.checkerRunMu.Lock()
	defer r.checkerRunMu.Unlock()
	ctx, cancel := context.WithTimeout(r.ctx, 5*time.Second)
	defer cancel()
	_, err = r.checkerSources.CollectCache(ctx, func(ctx context.Context) (checker.CacheRetention, error) {
		retention, e := r.checkerCacheRetention(ctx)
		return retention, e
	})
	if err == nil {
		r.checkerCacheNext = now.Add(checkerCacheIdle)
	}
	// A missing current fence is a conservative skip, not cache corruption or
	// a reason to stop unrelated container retirement.
	if errors.Is(err, errCheckerCacheFence) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil
	}
	return err
}
