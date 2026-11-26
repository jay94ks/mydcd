// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"context"
	"encoding/json"
	"slices"
	"time"

	contract "github.com/jay94ks/mydcd/lifecycle/v1"
)

// GuardProbe shares the builtin validators with interpreted and compiled SDK
// calls. The node adapter must additionally check current authority, original
// Task/native generation and durable exec IDs at each real effect. This fixed
// accepted policy/request is not a substitute for that current-state permit.
func GuardProbe(ctx context.Context, request contract.Request, policy TenantPolicy, native contract.Probe) (contract.Probe, error) {
	if ctx == nil || native == nil || ValidateRequest(request) != nil || policy.Validate() != nil || !policy.Enabled || policy.Tenant != request.Tenant {
		return nil, ErrContract
	}
	return &guardedProbe{ctx: ctx, request: ownRequest(request), policy: policy.Clone(), native: native}, nil
}

type guardedProbe struct {
	ctx     context.Context
	request contract.Request
	policy  TenantPolicy
	native  contract.Probe
}

func (p *guardedProbe) stopped(ctx context.Context) bool {
	return ctx.Err() != nil || p.ctx.Err() != nil
}

func (p *guardedProbe) normalize(ctx context.Context, capability, builtin string, parameters any) (context.Context, context.CancelFunc, *Builtin, error) {
	if ctx == nil || p.ctx.Err() != nil || ctx.Err() != nil || !slices.Contains(p.policy.Execution.Capabilities, capability) {
		return nil, nil, nil, ErrContract
	}
	normalized, err := probeBuiltin(p.request, p.policy, capability, builtin, parameters)
	if err != nil {
		return nil, nil, nil, err
	}
	child, done, err := p.probeContext(ctx)
	return child, done, normalized, err
}

func (p *guardedProbe) probeContext(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if ctx == nil || p.ctx.Err() != nil || ctx.Err() != nil {
		return nil, nil, ErrContract
	}
	// The original run bounds every caller-supplied context, even Background.
	deadline := time.UnixMilli(p.request.DeadlineUnixMilli)
	if parent, ok := p.ctx.Deadline(); ok && parent.Before(deadline) {
		deadline = parent
	}
	child, cancel := context.WithDeadline(ctx, deadline)
	stop := context.AfterFunc(p.ctx, cancel)
	cleanup := func() { stop(); cancel() }
	if child.Err() != nil {
		cleanup()
		return nil, nil, ErrContract
	}
	return child, cleanup, nil
}

func normalizeTCP(request contract.Request, policy TenantPolicy, q contract.TCPProbe) (contract.TCPProbe, error) {
	if !slices.Contains(policy.Execution.Capabilities, "connect") || q.Port == 0 || q.ReadBytes < 0 || q.ReadBytes > policy.Execution.ProbeBytes || len(q.Request) > policy.Execution.ProbeBytes-q.ReadBytes {
		return contract.TCPProbe{}, ErrContract
	}
	if q.Service == "" && len(request.Targets) == 1 {
		q.Service = request.Targets[0].Service
	}
	for _, target := range request.Targets {
		if target.Service == q.Service {
			q.Request = slices.Clone(q.Request)
			return q, nil
		}
	}
	return contract.TCPProbe{}, ErrContract
}

func normalizeFile(request contract.Request, policy TenantPolicy, q contract.FileProbe) (contract.FileProbe, error) {
	b, err := probeBuiltin(request, policy, "file", "file", FileCondition{Service: q.Service, Path: q.Path, Kind: q.Kind, ContentDigest: q.ContentDigest})
	if err != nil {
		return contract.FileProbe{}, err
	}
	if q.MaxBytes < 0 || q.MaxBytes > policy.Execution.ProbeBytes || q.ContentDigest == "" && q.MaxBytes != 0 {
		return contract.FileProbe{}, ErrContract
	}
	if q.ContentDigest != "" && q.MaxBytes == 0 {
		q.MaxBytes = policy.Execution.ProbeBytes
	}
	q.Service, q.Path, q.Kind, q.ContentDigest = b.File.Service, b.File.Path, b.File.Kind, b.File.ContentDigest
	return q, nil
}

func (p *guardedProbe) Connect(ctx context.Context, q contract.TCPProbe) (contract.TCPResult, error) {
	q, err := normalizeTCP(p.request, p.policy, q)
	if err != nil {
		return contract.TCPResult{}, err
	}
	child, done, err := p.probeContext(ctx)
	if err != nil {
		return contract.TCPResult{}, err
	}
	defer done()
	r, err := p.native.Connect(child, q)
	if err != nil {
		return contract.TCPResult{}, err
	}
	if p.stopped(child) || r.Connected && len(r.Data) != q.ReadBytes || !r.Connected && len(r.Data) != 0 {
		return contract.TCPResult{}, ErrContract
	}
	r.Data = slices.Clone(r.Data)
	return r, nil
}

func probeBuiltin(request contract.Request, policy TenantPolicy, capability, builtin string, parameters any) (*Builtin, error) {
	if !slices.Contains(policy.Execution.Capabilities, capability) {
		return nil, ErrContract
	}
	raw, err := json.Marshal(parameters)
	if err != nil {
		return nil, ErrContract
	}
	services := make(map[string][]Check, len(request.Targets))
	for _, target := range request.Targets {
		services[target.Service] = nil
	}
	b, err := resolveBuiltin(Template{Builtin: builtin, Parameters: raw}, "", services)
	if err != nil {
		return nil, err
	}
	if b.Exec != nil && b.Exec.MaxBytes > policy.Execution.ProbeBytes || b.HTTP != nil && b.HTTP.MaxBytes > policy.Execution.ProbeBytes {
		return nil, ErrContract
	}
	return b, nil
}

// NormalizeProbeCall shares actual SDK/builtin validation before a daemon
// adapter journals or touches native resources. ID remains bound to the raw
// request/sequence; callers retain raw Digest separately from normalized input.
func NormalizeProbeCall(request contract.Request, policy TenantPolicy, c ProbeCall) (ProbeCall, error) {
	if ValidateRequest(request) != nil || policy.Validate() != nil || !policy.Enabled || policy.Tenant != request.Tenant || !c.valid(request, c.Sequence) || c.Kind == "hello" {
		return ProbeCall{}, ErrContract
	}
	if c.Kind == "connect" {
		q, err := normalizeTCP(request, policy, *c.TCP)
		if err != nil {
			return ProbeCall{}, err
		}
		c.TCP = &q
		return c, nil
	}
	if c.Kind == "file" {
		q, err := normalizeFile(request, policy, *c.File)
		if err != nil {
			return ProbeCall{}, err
		}
		c.File = &q
		return c, nil
	}
	var b *Builtin
	var err error
	switch c.Kind {
	case "healthz":
		b, err = probeBuiltin(request, policy, "healthz", "healthz", HTTPParameters(*c.HTTP))
	case "exec":
		b, err = probeBuiltin(request, policy, "exec", "cmd", ExecParameters(*c.Exec))
	case "dependency":
		b, err = probeBuiltin(request, policy, "dependency", "depends_on", DependencyCondition{Services: []string{c.Dependency.Service}, Condition: c.Dependency.Condition})
	default:
		return ProbeCall{}, ErrContract
	}
	if err != nil {
		return ProbeCall{}, err
	}
	c.HTTP, c.Exec, c.File, c.Dependency = nil, nil, nil, nil
	switch c.Kind {
	case "healthz":
		c.HTTP = b.HTTP
	case "exec":
		c.Exec = b.Exec
	case "dependency":
		c.Dependency = &contract.DependencyProbe{Service: b.Dependency.Services[0], Condition: b.Dependency.Condition}
	}
	return c, nil
}

func (p *guardedProbe) Healthz(ctx context.Context, q contract.HTTPProbe) (contract.HTTPResult, error) {
	child, done, b, err := p.normalize(ctx, "healthz", "healthz", HTTPParameters(q))
	if err != nil {
		return contract.HTTPResult{}, err
	}
	defer done()
	if b.HTTP.MaxBytes > p.policy.Execution.ProbeBytes {
		return contract.HTTPResult{}, ErrContract
	}
	r, err := p.native.Healthz(child, *b.HTTP)
	if err != nil {
		return contract.HTTPResult{}, err
	}
	if p.stopped(child) || r.StatusCode < 100 || r.StatusCode > 599 || r.Match != slices.Contains(b.HTTP.ExpectedStatus, r.StatusCode) {
		return contract.HTTPResult{}, ErrContract
	}
	return r, nil
}

func (p *guardedProbe) Exec(ctx context.Context, q contract.ExecProbe) (contract.ExecResult, error) {
	child, done, b, err := p.normalize(ctx, "exec", "cmd", ExecParameters(q))
	if err != nil {
		return contract.ExecResult{}, err
	}
	defer done()
	if b.Exec.MaxBytes > p.policy.Execution.ProbeBytes {
		return contract.ExecResult{}, ErrContract
	}
	r, err := p.native.Exec(child, *b.Exec)
	if err != nil {
		return contract.ExecResult{}, err
	}
	if p.stopped(child) || len(r.Stdout) > b.Exec.MaxBytes || r.ExitCode < 0 || r.ExitCode > 255 || !r.Exited && r.ExitCode != 0 {
		return contract.ExecResult{}, ErrContract
	}
	r.Stdout = slices.Clone(r.Stdout)
	return r, nil
}

func (p *guardedProbe) File(ctx context.Context, q contract.FileProbe) (contract.FileResult, error) {
	q, err := normalizeFile(p.request, p.policy, q)
	if err != nil {
		return contract.FileResult{}, err
	}
	child, done, err := p.probeContext(ctx)
	if err != nil {
		return contract.FileResult{}, err
	}
	defer done()
	r, err := p.native.File(child, q)
	if err != nil {
		return contract.FileResult{}, err
	}
	kindMatch := q.Kind == "any" || q.Kind == r.Kind
	if p.stopped(child) || r.Mode > 07777 || !r.Exists && (r.Match || r.Kind != "" || r.Mode != 0) || r.Exists && (r.Kind != "regular" && r.Kind != "directory" && r.Kind != "other" || r.Match && !kindMatch || q.ContentDigest == "" && r.Match != kindMatch) {
		return contract.FileResult{}, ErrContract
	}
	return r, nil
}

func (p *guardedProbe) Dependency(ctx context.Context, q contract.DependencyProbe) (contract.DependencyResult, error) {
	child, done, b, err := p.normalize(ctx, "dependency", "depends_on", DependencyCondition{Services: []string{q.Service}, Condition: q.Condition})
	if err != nil {
		return contract.DependencyResult{}, err
	}
	defer done()
	q = contract.DependencyProbe{Service: b.Dependency.Services[0], Condition: b.Dependency.Condition}
	r, err := p.native.Dependency(child, q)
	if err != nil {
		return contract.DependencyResult{}, err
	}
	if p.stopped(child) || !validStatus(r.Status) {
		return contract.DependencyResult{}, ErrContract
	}
	for _, target := range p.request.Targets {
		if target.Service == q.Service {
			if r.Generation != target.Generation || r.Revision != target.Revision {
				return contract.DependencyResult{}, ErrStale
			}
			return r, nil
		}
	}
	return contract.DependencyResult{}, ErrContract
}
