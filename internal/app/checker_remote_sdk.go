// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"

	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
	contract "github.com/jay94ks/seafield/lifecycle/v1"
)

// Only app-scope targets may cross owners. Local calls keep the SAME
// ServiceProbe/SDK path and remote calls share its run ordinal and I/O join.
func (p *appCheckProbe) foreignCall(ctx context.Context, service string, call checker.ProbeCall) (checker.ProbeReply, bool, error) {
	if service == "" && len(p.request.Targets) == 1 {
		service = p.request.Targets[0].Service
	}
	for _, target := range p.request.Targets {
		if target.Service != service || target.Owner == p.localOwner {
			continue
		}
		if p.remote == nil || p.ServiceProbe == nil {
			return checker.ProbeReply{}, true, checker.ErrReference
		}
		reply, err := p.ServiceProbe.RemoteCall(ctx, call, p.remote)
		return reply, true, err
	}
	return checker.ProbeReply{}, false, nil
}

func (p *appCheckProbe) Connect(ctx context.Context, q contract.TCPProbe) (contract.TCPResult, error) {
	reply, remote, err := p.foreignCall(ctx, q.Service, checker.ProbeCall{Kind: "connect", TCP: &q})
	if !remote {
		return p.ServiceProbe.Connect(ctx, q)
	}
	if err != nil {
		return contract.TCPResult{}, err
	}
	if reply.TCP == nil {
		return contract.TCPResult{}, checker.ErrProbeRPC
	}
	return *reply.TCP, nil
}
func (p *appCheckProbe) Healthz(ctx context.Context, q contract.HTTPProbe) (contract.HTTPResult, error) {
	reply, remote, err := p.foreignCall(ctx, q.Service, checker.ProbeCall{Kind: "healthz", HTTP: &q})
	if !remote {
		return p.ServiceProbe.Healthz(ctx, q)
	}
	if err != nil {
		return contract.HTTPResult{}, err
	}
	if reply.HTTP == nil {
		return contract.HTTPResult{}, checker.ErrProbeRPC
	}
	return *reply.HTTP, nil
}
func (p *appCheckProbe) File(ctx context.Context, q contract.FileProbe) (contract.FileResult, error) {
	reply, remote, err := p.foreignCall(ctx, q.Service, checker.ProbeCall{Kind: "file", File: &q})
	if !remote {
		return p.ServiceProbe.File(ctx, q)
	}
	if err != nil {
		return contract.FileResult{}, err
	}
	if reply.File == nil {
		return contract.FileResult{}, checker.ErrProbeRPC
	}
	return *reply.File, nil
}
func (p *appCheckProbe) Exec(ctx context.Context, q contract.ExecProbe) (contract.ExecResult, error) {
	reply, remote, err := p.foreignCall(ctx, q.Service, checker.ProbeCall{Kind: "exec", Exec: &q})
	if !remote {
		return p.ServiceProbe.Exec(ctx, q)
	}
	if err != nil {
		return contract.ExecResult{}, err
	}
	if reply.Exec == nil {
		return contract.ExecResult{}, checker.ErrProbeRPC
	}
	return *reply.Exec, nil
}
