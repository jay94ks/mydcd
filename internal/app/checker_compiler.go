// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/storage"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
)

// compilerAuthority is the actual member/latest quorum edge. Recovery cannot
// authorize new native work; the owner separately preserves its index floor.
func (r *Runtime) compilerAuthority(ctx context.Context, b checker.BuildIntent, recover bool) (checker.CompilerGrant, error) {
	p, err := r.compilerWork(ctx, b, recover)
	if err != nil {
		return checker.CompilerGrant{}, err
	}
	return checker.CompilerGrant{Schema: p.Schema, Job: p.Job, Manifest: p.Manifest, Policy: p.Policy, Owner: p.Owner, Phase: p.Phase, Revision: p.Revision, Index: p.Index, DeadlineUnixMilli: p.DeadlineUnixMilli, Recovery: p.Recovery}, nil
}

func (r *Runtime) compilerWork(ctx context.Context, b checker.BuildIntent, recover bool) (control.CheckerBuildPermit, error) {
	return r.compilerQuery(ctx, b, !recover, recover)
}

func (r *Runtime) compilerQuery(ctx context.Context, b checker.BuildIntent, start, recover bool) (control.CheckerBuildPermit, error) {
	if b.Cluster != r.controlPolicy.Cluster || b.Owner != r.Identity.Public || r.ctx.Err() != nil {
		return control.CheckerBuildPermit{}, sfcp.ErrAdmission
	}
	view, err := r.Engine().Read(ctx, false)
	if err != nil {
		return control.CheckerBuildPermit{}, err
	}
	q := control.CheckerBuildRequest{Schema: 1, Tenant: b.Tenant, ID: b.ID, Job: b.Digest(), MinimumIndex: view.State.Index(), At: time.Now().Unix(), Start: start, Recover: recover}
	raw, _ := json.Marshal(q)
	reply, err := r.appCall(ctx, "checker-build-permit", raw)
	if err != nil {
		return control.CheckerBuildPermit{}, err
	}
	p, err := schema.Decode[control.CheckerBuildPermit](reply.Data)
	if err != nil || reply.Local || p.Schema != 1 || p.Job != b.Digest() || p.Manifest != b.Manifest || p.Owner != b.Owner || p.DeadlineUnixMilli != b.DeadlineUnixMilli || p.Index < q.MinimumIndex || p.PolicyRevision != b.Selection.PolicyRevision || p.Epoch == 0 || p.RootRevision == 0 || p.Recovery != recover {
		return control.CheckerBuildPermit{}, sfcp.ErrAdmission
	}
	return p, nil
}

// The callback's native witness and output directory are checked against the
// original owner record in the SAME node DB before any build/cache fact signs.
func (r *Runtime) collectCompilerArtifacts(ctx context.Context, o checker.CompilerOutput) ([32]byte, error) {
	if r.checkerSources == nil {
		return [32]byte{}, checker.ErrSourceStore
	}
	return r.checkerSources.CollectCompiled(ctx, o)
}

// Publish only the original immutable native fact. A lost reply first queries
// the same job's current quorum state; a closed matching digest needs no submit.
// This is the existing convergent ModuleReport flow, never a new native job.
func (r *Runtime) publishCompilerClosure(ctx context.Context, b checker.BuildIntent, c checker.BuildClosure) error {
	if c.Job != b.Digest() || c.Owner != r.Identity.Public {
		return checker.ErrCompilerOwner
	}
	work, err := r.compilerWork(ctx, b, true)
	if err != nil {
		return err
	}
	if work.Phase == "closed" {
		if work.Closure == nil || *work.Closure != c.Digest() {
			return checker.ErrCompilerOwner
		}
		return nil
	}
	if c.Verify(b, work.Phase) != nil {
		return checker.ErrCompilerOwner
	}
	report := control.CheckerBuildReport{Schema: 1, Cluster: r.controlPolicy.Cluster, Reporter: r.commandIdentity().Public, Tenant: b.Tenant, ID: b.ID, Action: "close", Expected: work.Revision, Epoch: work.Epoch, RootRevision: work.RootRevision, Index: work.Index, At: time.Now().Unix(), Closure: &c}
	report.Signature = ed25519.Sign(r.commandIdentity().Private, control.CheckerBuildReportBytes(report))
	raw, _ := json.Marshal(report)
	reply, err := r.appCall(ctx, "checker-build-report", raw)
	if err != nil {
		return err
	}
	if reply.Committed == nil || reply.Committed.Result.Code != state.Applied {
		return reconcile.ErrPending
	}
	return nil
}

// Only metadata/ready closures run on the common module loop. Long compiler
// Start/Wait is driven by the finite job consumer, never this control loop.
func (r *Runtime) reconcileCompilerClosures(ctx context.Context, v cluster.View) error {
	if r.checkerCompiler == nil {
		return nil
	}
	book, err := r.controlPolicy.Lifecycles(v.State)
	if err != nil {
		return err
	}
	var result error
	for _, job := range book.BuildJobs() {
		if job.Intent.Owner != r.Identity.Public || job.Phase == "closed" {
			continue
		}
		c, err := r.checkerCompiler.Closure(job.Intent.Tenant, job.Intent.ID)
		if errors.Is(err, storage.ErrMissing) || errors.Is(err, reconcile.ErrPending) {
			continue
		}
		if err == nil {
			err = r.publishCompilerClosure(ctx, job.Intent, c)
		}
		result = errors.Join(result, err)
	}
	return result
}
