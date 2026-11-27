// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/storage"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
)

// The local read can deny/cancel work. Only compilerQuery/CompilerOwner's
// current member/latest quorum grants can permit shared dispatch/native Start.
func (r *Runtime) compilerCurrent(v cluster.View, b checker.BuildIntent) error {
	_, err := r.controlPolicy.CheckerBuildPermit(v.State, r.commandIdentity().Public, control.CheckerBuildRequest{Schema: 1, Tenant: b.Tenant, ID: b.ID, Job: b.Digest(), MinimumIndex: v.State.Index(), At: time.Now().Unix()})
	return err
}

func (r *Runtime) compilerPreparation(ctx context.Context, job checker.BuildJob, p checker.TenantPolicy) (checker.CompilerPreparation, error) {
	b := job.Intent
	local, err := r.checkerCompiler.Preparation(b.Tenant, b.ID)
	if errors.Is(err, storage.ErrMissing) {
		// Dispatch attests the original builder already synced its local
		// journal. Missing bytes after dispatch are never new-job authority.
		if job.Phase != "reserved" {
			return checker.CompilerPreparation{}, err
		}
		if err = r.checkerCompiler.Accept(ctx, b, p); err != nil {
			return checker.CompilerPreparation{}, err
		}
		local, err = r.checkerCompiler.Preparation(b.Tenant, b.ID)
	}
	if err != nil {
		return checker.CompilerPreparation{}, err
	}
	if local.Intent.Digest() != b.Digest() {
		return checker.CompilerPreparation{}, checker.ErrCompilerOwner
	}
	if job.Phase == "dispatched" && !local.InputReady && !local.Cancelled && !local.Closed {
		return checker.CompilerPreparation{}, checker.ErrCompilerOwner
	}
	return local, nil
}

// A reserved miss can become a hit before dispatch. Only exact local bytes
// with committed ORIGINAL provenance can avoid the finite compiler. Missing,
// corruption and an output whose original job is not closed remain distinct.
func (r *Runtime) compilerInputsCached(ctx context.Context, book checker.Catalog, b checker.BuildIntent) (bool, error) {
	complete := true
	for _, input := range b.Inputs {
		fact, data, err := r.checkerSources.CompiledArtifact(ctx, b.Tenant, input.Recipe)
		clear(data)
		if err != nil {
			if errors.Is(err, storage.ErrMissing) && !errors.Is(err, checker.ErrSourceStore) {
				complete = false
				continue
			}
			return false, err
		}
		if fact.Build.Cluster != b.Cluster || fact.Build.Recipe.Source != input.Content {
			return false, checker.ErrSourceStore
		}
		if book.CompiledOrigin(fact.Build) != nil {
			return false, reconcile.ErrPending
		}
	}
	return complete, nil
}

func (r *Runtime) prepareCompilerSources(ctx context.Context, v cluster.View, book checker.Catalog, b checker.BuildIntent, p checker.TenantPolicy) error {
	u, ok := book.Use(b.Tenant, b.ID)
	if !ok || u.Kind != "build-job" || u.Parent != b.Digest() || u.Owner != r.Identity.Public {
		return checker.ErrReference
	}
	facts := make([]checker.SourceFact, 0, len(b.Inputs))
	for _, input := range b.Inputs {
		fact, _, err := book.SourceForUse(u, input.Content)
		if err != nil {
			return err
		}
		if err = r.receiveCheckerSource(ctx, u, fact, v.State.Index()); err != nil {
			return err
		}
		facts = append(facts, fact)
	}
	batch, inputs, err := r.checkerSources.PrepareBuild(ctx, b, p, facts)
	if err != nil {
		return err
	}
	return r.checkerCompiler.Stage(ctx, b, p, batch, inputs)
}

func (r *Runtime) dispatchCompiler(ctx context.Context, b checker.BuildIntent) error {
	work, err := r.compilerQuery(ctx, b, false, false)
	if err != nil {
		return err
	}
	if work.Phase == "dispatched" && work.Revision == 2 {
		return nil
	}
	if work.Phase != "reserved" || work.Revision != 1 {
		return checker.ErrCompilerOwner
	}
	report := control.CheckerBuildReport{Schema: 1, Cluster: r.controlPolicy.Cluster, Reporter: r.commandIdentity().Public, Tenant: b.Tenant, ID: b.ID, Action: "dispatch", Expected: work.Revision, Epoch: work.Epoch, RootRevision: work.RootRevision, Index: work.Index, At: time.Now().Unix()}
	report.Signature = ed25519.Sign(r.commandIdentity().Private, control.CheckerBuildReportBytes(report))
	raw, _ := json.Marshal(report)
	reply, err := r.appCall(ctx, "checker-build-report", raw)
	if err != nil {
		return err
	} // same accepted job is read before any next action
	if reply.Committed == nil || reply.Committed.Result.Code != state.Applied {
		return reconcile.ErrPending
	}
	return nil
}

// Cancellation cleans only the original native/journal under a fresh bounded
// cleanup context. It never extends the original build/Start deadline.
func (r *Runtime) cancelCompiler(b checker.BuildIntent) error {
	if r.ctx.Err() != nil {
		return r.ctx.Err()
	} // Runtime.Close owns Shutdown
	ctx, stop := context.WithTimeout(r.ctx, 30*time.Second)
	defer stop()
	if err := r.checkerCompiler.Cancel(b.Tenant, b.ID); err != nil {
		return err
	}
	return r.checkerCompiler.Step(ctx, b.Tenant, b.ID)
}

func (r *Runtime) consumeCompilerJob(ctx context.Context, b checker.BuildIntent) error {
	v, err := r.Engine().Read(ctx, false)
	if err != nil {
		return err
	}
	book, err := r.controlPolicy.Lifecycles(v.State)
	if err != nil {
		return err
	}
	job, ok := book.BuildJob(b.Tenant, b.ID)
	if !ok || job.Intent.Digest() != b.Digest() {
		// A retained local native must still stop even if its shared metadata
		// is missing; shared pins/closure cannot be inferred or resubmitted.
		return errors.Join(checker.ErrReference, r.cancelCompiler(b))
	}
	policy, ok := book.Policy(b.Tenant, b.Selection.PolicyRevision)
	if !ok {
		return checker.ErrReference
	}
	local, err := r.compilerPreparation(ctx, job, policy)
	if err != nil {
		return err
	}
	if local.Closed {
		return nil
	}
	if local.Cancelled || r.compilerCurrent(v, b) != nil {
		return r.cancelCompiler(b)
	}
	jobctx, stop := context.WithDeadline(ctx, time.UnixMilli(b.DeadlineUnixMilli))
	defer stop()
	if !local.NativeDispatched {
		cached, err := r.compilerInputsCached(jobctx, book, b)
		if err != nil {
			if jobctx.Err() != nil {
				return errors.Join(err, r.cancelCompiler(b))
			}
			return err
		}
		if cached {
			return r.cancelCompiler(b)
		}
	}
	if !local.InputReady {
		if err = r.prepareCompilerSources(jobctx, v, book, b, policy); err != nil {
			if jobctx.Err() != nil || errors.Is(err, checker.ErrSource) || errors.Is(err, checker.ErrContract) || errors.Is(err, checker.ErrReference) {
				return errors.Join(err, r.cancelCompiler(b))
			}
			return err
		}
	}
	if err = r.dispatchCompiler(jobctx, b); err == nil {
		err = r.checkerCompiler.Step(jobctx, b.Tenant, b.ID)
	}
	if jobctx.Err() != nil || errors.Is(err, checker.ErrSource) || errors.Is(err, checker.ErrContract) || errors.Is(err, checker.ErrReference) {
		return errors.Join(err, r.cancelCompiler(b))
	}
	return err
}

// Work comes only from existing shared jobs or retained original local jobs.
// This scheduler never allocates an ID, rebuilds a missing dispatched journal
// or starts a compiler while merely scanning policy/cache metadata.
func (r *Runtime) compilerCandidates(v cluster.View) ([]checker.BuildIntent, error) {
	book, err := r.controlPolicy.Lifecycles(v.State)
	if err != nil {
		return nil, err
	}
	pending, err := r.checkerCompiler.Pending()
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, b := range pending {
		seen[b.Tenant+"/"+b.ID] = true
	}
	for _, job := range book.BuildJobs() {
		b := job.Intent
		if b.Owner != r.Identity.Public || job.Phase == "closed" || seen[b.Tenant+"/"+b.ID] {
			continue
		}
		local, err := r.checkerCompiler.Preparation(b.Tenant, b.ID)
		if err == nil && local.Closed {
			continue
		}
		if err != nil && !errors.Is(err, storage.ErrMissing) {
			return nil, err
		}
		pending = append(pending, b)
	}
	sort.Slice(pending, func(i, j int) bool { return pending[i].Tenant+"/"+pending[i].ID < pending[j].Tenant+"/"+pending[j].ID })
	return pending, nil
}

// A sfcd-owned event consumer, not an idle compiler process/container. Only
// one finite native Step runs at a time; current state can interrupt it without
// blocking the common module loop behind source transfer or Docker Wait.
func (r *Runtime) compilerLoop() {
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	var done chan error
	var active checker.BuildIntent
	var stop context.CancelFunc
	var cursor string
	attempted := map[[32]byte]bool{}
	for {
		changed := r.Engine().Changes()
		view, err := r.Engine().Read(r.ctx, false)
		if err == nil && done != nil {
			if r.compilerCurrent(view, active) != nil {
				stop()
			}
		} else if err == nil {
			var jobs []checker.BuildIntent
			jobs, err = r.compilerCandidates(view)
			start := sort.Search(len(jobs), func(i int) bool { return jobs[i].Tenant+"/"+jobs[i].ID > cursor })
			for n := range jobs {
				b := jobs[(start+n)%len(jobs)]
				if attempted[b.Digest()] {
					continue
				}
				attempted[b.Digest()] = true
				cursor = b.Tenant + "/" + b.ID
				active = b.Clone()
				var ctx context.Context
				ctx, stop = context.WithCancel(r.ctx)
				done = make(chan error, 1)
				result := done
				go func(b checker.BuildIntent) { result <- r.consumeCompilerJob(ctx, b) }(active.Clone())
				break
			}
		}
		if err != nil {
			r.setCompilerError(err)
		}
		select {
		case <-r.ctx.Done():
			if stop != nil {
				stop()
			}
			if done != nil {
				<-done
			} // owner DB/engine stay open until child returns
			return
		case err := <-done:
			stop()
			stop = nil
			done = nil
			if err != nil {
				err = fmt.Errorf("lifecycle build %s/%s: %w", active.Tenant, active.ID, err)
			}
			r.setCompilerError(err)
		case <-tick.C:
			clear(attempted)
		case <-changed:
		}
	}
}

func (r *Runtime) setCompilerError(err error) {
	r.mu.Lock()
	r.compilerError = err
	r.mu.Unlock()
	r.wakeReport()
}
