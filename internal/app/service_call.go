// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/servicecall"
	"github.com/jay94ks/seafield/internal/sfcp"
)

func (r *Runtime) openServiceCalls(c config.Node) error {
	r.serviceCallLimit = servicecall.Limiter{Concurrent: 32, PerMinute: 600, ScopedPerMinute: 120}
	r.cdProbeLimit = servicecall.Limiter{Concurrent: 4, PerMinute: 120, ScopedPerMinute: 10}
	r.serviceCAs = map[string]*x509.CertPool{}
	for _, entry := range c.ServiceCAs {
		if _, exists := r.serviceCAs[entry.Tenant]; exists {
			return servicecall.ErrInvalid
		}
		pem, err := installedGitFile(entry.CAFile, 1<<20, false)
		if err != nil {
			return err
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			return servicecall.ErrInvalid
		}
		r.serviceCAs[entry.Tenant] = roots
	}
	if r.workload != nil {
		return r.workload.RecoverServiceCalls(r.ctx)
	}
	return nil
}

func (r *Runtime) serviceCallPermit(ctx context.Context, read control.ServiceCallRead) error {
	read.Request.Body = nil
	raw, err := json.Marshal(read)
	if err != nil {
		return err
	}
	reply, err := r.appCall(ctx, "service-call-permit", raw)
	if err != nil {
		return err
	}
	index, err := schema.Decode[uint64](reply.Data)
	if err != nil || index == 0 || reply.Local || reply.RaftIndex == 0 || reply.CommandIndex < index {
		return sfcp.ErrAdmission
	}
	// The authenticated quorum permit can arrive before this native owner's
	// FSM publication. Consume that command ordinal locally, then recheck the
	// exact original target, epoch and current grant on the same durable view.
	// ReadAtLeast returns a Local view by design; that marker is not a denial.
	view, err := r.Engine().ReadAtLeast(ctx, index)
	if err != nil {
		return err
	}
	_, err = r.controlPolicy.ServiceCallPermit(view.State, r.Identity.Public, read, time.Now().Unix())
	return err
}

func (r *Runtime) callService(ctx context.Context, read control.ServiceCallRead) (out servicecall.Result, failure error) {
	if read.Target.Container.Owner != r.Identity.Public || !read.Target.Valid() || !read.Request.Valid() {
		return out, sfcp.ErrAdmission
	}
	parentCtx := ctx
	ctx, cancel := context.WithTimeout(ctx, read.Request.Duration())
	defer cancel()
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	if err := r.serviceCallPermit(ctx, read); err != nil {
		return out, err
	}
	r.life.RLock()
	defer r.life.RUnlock()
	if r.closed || r.workload == nil {
		return out, sfcp.ErrAdmission
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return out, err
	}
	target := read.Target.Container
	lease, err := r.workload.BorrowServiceCall(ctx, target.Instance, target.Generation, target.Revision, target.NativeID, hex.EncodeToString(nonce[:]), nonce)
	if lease.Pin != (reconcile.Lease{}) {
		defer func() { failure = errors.Join(failure, r.workload.ReturnReadProbe(lease)) }()
	}
	if err != nil || !lease.Target.Status.Running || !lease.Target.Status.ProcessReady || lease.Target.Status.HealthConfigured && lease.Target.Status.Health != "healthy" || target.StartedAt != "" && target.StartedAt != lease.Target.Status.StartedAt || read.Target.Address != lease.Target.IPv4 && read.Target.Address != lease.Target.IPv6 {
		return servicecall.Result{Code: servicecall.NoReadyTask}, nil
	}
	if err := r.serviceCallPermit(ctx, read); err != nil {
		return out, err
	}
	if err := r.workload.CheckReadProbe(ctx, lease); err != nil {
		return out, err
	}
	out, err = servicecall.Execute(ctx, read.Request, read.Target, r.serviceCAs[read.Tenant])
	if err != nil {
		return servicecall.Result{}, err
	}
	// A completed timeout remains a timeout result. Recheck current authority
	// with a separate bounded response budget, without reissuing the POST.
	finalCtx, finalCancel := context.WithTimeout(parentCtx, 3*time.Second)
	defer finalCancel()
	finalStop := context.AfterFunc(r.ctx, finalCancel)
	defer finalStop()
	if err := r.workload.CheckReadProbe(finalCtx, lease); err != nil {
		return servicecall.Result{}, err
	}
	if err := r.serviceCallPermit(finalCtx, read); err != nil {
		return servicecall.Result{}, err
	}
	return out, nil
}

func (r *Runtime) probeCD(ctx context.Context, read control.CDProbeRead) (out deployment.GitProbeResult, failure error) {
	parentCtx := ctx
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	current := func(ctx context.Context) error {
		view, err := r.currentView(ctx)
		if err != nil || view.Local {
			return sfcp.ErrAdmission
		}
		members, err := r.controlPolicy.Members(view.State)
		if err != nil || !members.WorkKey(r.Identity.Public) {
			return sfcp.ErrAdmission
		}
		for _, entry := range members.Entries {
			if entry.Peer.Key == hex.EncodeToString(r.Identity.Public[:]) {
				out.Node = entry.Peer.ID
				break
			}
		}
		if out.Node == "" {
			return sfcp.ErrAdmission
		}
		return r.controlPolicy.CDProbePermit(view.State, read, time.Now().Unix(), out.Node)
	}
	if err := current(ctx); err != nil {
		return out, err
	}
	release, ok := r.cdProbeLimit.Acquire(read.Session.User, time.Now().Unix())
	if !ok {
		out.Code = "rate-limited"
		return out, nil
	}
	defer release()
	r.life.RLock()
	defer r.life.RUnlock()
	if r.closed || r.gitFetcher == nil {
		return out, sfcp.ErrAdmission
	}
	var access deployment.GitAccess
	if read.Query.Credential != "" {
		entry, exists := r.gitCredentials[read.Tenant+"/"+read.Query.Credential]
		if !exists || entry.Tenant != read.Tenant || entry.Repository != read.Query.Repository {
			out.Code = "no-credential"
			return out, nil
		}
		var err error
		access, err = installedGitAccess(entry)
		if err != nil {
			out.Code = "no-credential"
			return out, nil
		}
		defer clear(access.Password)
		defer clear(access.Username)
	}
	result := r.gitFetcher.Probe(ctx, read.Tenant, read.Query, access)
	result.Node = out.Node
	finalCtx, finalCancel := context.WithTimeout(parentCtx, 3*time.Second)
	defer finalCancel()
	finalStop := context.AfterFunc(r.ctx, finalCancel)
	defer finalStop()
	if err := current(finalCtx); err != nil {
		return deployment.GitProbeResult{}, err
	}
	return result, nil
}
