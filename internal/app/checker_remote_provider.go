// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/storage"
	"github.com/jay94ks/seafield/internal/workload"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
	contract "github.com/jay94ks/seafield/lifecycle/v1"
)

const checkerRemotePrefix = "checker/remote/"
const checkerRemoteRowBytes = 96 << 10
const checkerRemoteTotalBytes = 32 << 20
const checkerRemoteSlots = 1024

// One original provider call in the existing observations DB. Raw argv,
// request/response bytes and probe output are never stored in this row.
type checkerRemoteCall struct {
	Schema             uint8
	Consumer, Provider [32]byte
	Query              control.CheckerProbeRequest
	Header, Call       [32]byte
	Phase              string                     // prepared, dispatched, closed; closed also seals no-effect lookup
	Execution          *workload.ProbeExecReceipt `json:",omitempty"`
}

func (p checkerRemoteCall) key() string { return checkerRemotePrefix + hex.EncodeToString(p.Call[:]) }

func (p checkerRemoteCall) follows(old checkerRemoteCall) bool {
	if p.Header != old.Header || p.Call != old.Call || p.Consumer != old.Consumer || p.Provider != old.Provider {
		return false
	}
	if old.Execution != nil && (p.Execution == nil || !p.Execution.CanFollow(*old.Execution)) {
		return false
	}
	if old.Execution == nil && p.Execution != nil && p.Execution.Phase != workload.ProbeExecCreating {
		return false
	}
	switch old.Phase {
	case "prepared":
		return p.Phase == "dispatched" || p.Phase == "closed"
	case "dispatched":
		return p.Phase == "dispatched" || p.Phase == "closed"
	case "closed":
		return p.Phase == "closed" && (p.Execution == nil && old.Execution == nil || p.Execution != nil && old.Execution != nil && *p.Execution == *old.Execution)
	}
	return false
}

// Structural identity also permits original-key cleanup after the Task or
// its current authority was removed. It grants NO permission to execute.
func (p checkerRemoteCall) validate(cluster, provider [32]byte) error {
	q := p.Query
	if p.Schema != 1 || p.Provider != provider || provider == ([32]byte{}) || p.Consumer == ([32]byte{}) || q.Schema != 1 || q.At != 0 || q.Binding == ([32]byte{}) || q.PolicyRevision == 0 || q.Sequence == 0 || q.Sequence > checker.MaxProbeCalls || q.Payload == ([32]byte{}) || q.Run.Phase != checker.Dispatched || q.Run.Sequence == 0 || checker.ValidateRequest(q.Run.Request) != nil || q.Run.RequestDigest != checker.ProbeBinding(q.Run.Request) || q.Run.Request.Cluster != hex.EncodeToString(cluster[:]) || q.DeadlineUnixMilli <= 0 || q.DeadlineUnixMilli > q.Run.Request.DeadlineUnixMilli || p.Header != q.HeaderDigest() || p.Call != (checker.ProbeCall{Binding: checker.ProbeBinding(q.Run.Request), Sequence: q.Sequence}).ID() {
		return checker.ErrContract
	}
	if q.Kind != "connect" && q.Kind != "healthz" && q.Kind != "file" && q.Kind != "exec" {
		return checker.ErrContract
	}
	consumerBound, providerBound := false, false
	for _, target := range q.Run.Request.Targets {
		if target.TaskKey == q.Task.Key && target.Generation == q.Task.Generation && target.Revision == q.Task.Revision && target.Owner == hex.EncodeToString(p.Consumer[:]) {
			consumerBound = true
		}
		if target.Service == q.Service && target.Owner == hex.EncodeToString(provider[:]) {
			providerBound = true
		}
	}
	if !consumerBound || !providerBound || q.Task.Generation == 0 || q.Task.Revision < q.Task.Generation {
		return checker.ErrContract
	}
	if p.Phase != "prepared" && p.Phase != "dispatched" && p.Phase != "closed" {
		return checker.ErrContract
	}
	if p.Execution != nil {
		e := p.Execution
		if q.Kind != "exec" || e.Validate(q.Run.Request) != nil || e.Call != p.Call || e.Target.Service != q.Service || p.Phase == "prepared" || p.Phase == "closed" && !e.Terminal() {
			return checker.ErrContract
		}
	}
	return nil
}

// Caller holds checkerRemoteMu. Sync/reload after any ambiguous write keeps
// the old original record or its exact forward receipt; no effect is replayed.
func (r *Runtime) checkerRemoteIndex() error {
	if r.reports == nil || r.Identity == nil {
		return checker.ErrContract
	}
	if r.checkerRemoteReady {
		return nil
	}
	if err := r.reports.Sync(); err != nil {
		return err
	}
	rows, err := r.reports.ScanBounded(checkerRemotePrefix, checkerRemoteSlots, checkerRemoteTotalBytes)
	if err != nil {
		return err
	}
	for key := range r.checkerRemoteSizes {
		if _, ok := rows[key]; !ok {
			return checker.ErrContract
		}
	}
	sizes := make(map[string]int, len(rows))
	for key, raw := range rows {
		p, err := schema.Decode[checkerRemoteCall](raw)
		if err != nil || len(raw) > checkerRemoteRowBytes || p.validate(r.controlPolicy.Cluster, r.Identity.Public) != nil || key != p.key() {
			return checker.ErrContract
		}
		sizes[key] = len(key) + len(raw)
	}
	r.checkerRemoteSizes = sizes
	r.checkerRemoteReady = true
	return nil
}

func (r *Runtime) saveCheckerRemote(p checkerRemoteCall) error {
	if p.validate(r.controlPolicy.Cluster, r.Identity.Public) != nil || !r.checkerRemoteReady {
		return checker.ErrContract
	}
	raw, err := json.Marshal(p)
	key := p.key()
	if err != nil || len(raw) > checkerRemoteRowBytes {
		return checker.ErrContract
	}
	total := 0
	for _, size := range r.checkerRemoteSizes {
		total += size
	}
	old, exists := r.checkerRemoteSizes[key]
	if !exists && len(r.checkerRemoteSizes) >= checkerRemoteSlots || total-old+len(key)+len(raw) > checkerRemoteTotalBytes {
		return checker.ErrContract
	}
	if exists {
		before, err := r.reports.GetBounded(key, checkerRemoteRowBytes)
		if err != nil {
			r.checkerRemoteReady = false
			return err
		}
		previous, err := schema.Decode[checkerRemoteCall](before)
		if err != nil || previous.validate(r.controlPolicy.Cluster, r.Identity.Public) != nil || !p.follows(previous) {
			return checker.ErrContract
		}
	} else if p.Phase != "prepared" && p.Phase != "closed" {
		return checker.ErrContract
	}
	if err = r.reports.Write(map[string][]byte{key: raw}); err != nil {
		r.checkerRemoteReady = false
		return err
	}
	r.checkerRemoteSizes[key] = len(key) + len(raw)
	return nil
}

func (r *Runtime) saveCheckerRemoteExec(p *checkerRemoteCall, next workload.ProbeExecReceipt) error {
	if p == nil || p.Phase != "dispatched" || next.Validate(p.Query.Run.Request) != nil || next.Call != p.Call || next.Target.Service != p.Query.Service {
		return checker.ErrContract
	}
	if p.Execution == nil {
		if next.Phase != workload.ProbeExecCreating {
			return checker.ErrContract
		}
	} else if next.Phase == workload.ProbeExecCreating || !next.CanFollow(*p.Execution) {
		return checker.ErrContract
	}
	candidate := *p
	candidate.Execution = &next
	if err := r.saveCheckerRemote(candidate); err != nil {
		return err
	}
	*p = candidate
	return nil
}

// Both ends obtain their OWN current quorum read and wait for their local
// state to cover it. A forwarded permit is never a bearer execution token.
func (r *Runtime) checkerRemotePermit(ctx context.Context, q control.CheckerProbeRequest) (control.CheckerProbePermit, checker.TaskProgram, checker.TenantPolicy, error) {
	var empty control.CheckerProbePermit
	var program checker.TaskProgram
	var policy checker.TenantPolicy
	q.At = time.Now().UnixMilli()
	raw, _ := json.Marshal(q)
	var v cluster.View
	var data json.RawMessage
	var err error
	leader := r.Engine().IsLeader()
	if leader {
		// Use the SAME current quorum view and management reader as appCall.
		// The leader has no lagging replica to validate a second time.
		v, err = r.Engine().Read(ctx, true)
		if err == nil {
			data, err = r.readModule(ctx, "checker-probe-permit", r.commandIdentity().Actor(), raw, v)
		}
	} else {
		var reply cluster.ManagementReply
		reply, err = r.appCall(ctx, "checker-probe-permit", raw)
		data = reply.Data
	}
	if err != nil {
		return empty, program, policy, err
	}
	permit, err := schema.Decode[control.CheckerProbePermit](data)
	if err != nil || permit.Schema != 1 || permit.Index == 0 {
		return empty, program, policy, sfcp.ErrAdmission
	}
	if !leader {
		v, err = r.Engine().ReadAtLeast(ctx, permit.Index)
		if err != nil {
			return empty, program, policy, err
		}
	}
	if v.State.Index() < permit.Index {
		return empty, program, policy, checker.ErrPending
	}
	if !leader {
		local, err := r.controlPolicy.CheckerProbePermit(v.State, r.commandIdentity().Public, q)
		a, b := permit, local
		a.Index, b.Index = 0, 0
		if err != nil || a != b {
			return empty, program, policy, sfcp.ErrAdmission
		}
	}
	goal, err := schema.Decode[deployment.GoalCommand]([]byte(v.State.Object(q.Task.Key).Value))
	if err != nil {
		return empty, program, policy, err
	}
	service, err := schema.Decode[deployment.ComposeService](goal.Config)
	if err != nil || service.LifecycleProgram == nil || service.LifecycleProgram.Program != permit.Program {
		return empty, program, policy, sfcp.ErrAdmission
	}
	book, err := r.controlPolicy.Lifecycles(v.State)
	if err != nil {
		return empty, program, policy, err
	}
	policy, ok := book.Policy(q.Run.Request.Tenant, 0)
	if !ok || policy.Revision != permit.PolicyRevision {
		return empty, program, policy, sfcp.ErrAdmission
	}
	return permit, service.LifecycleProgram.Clone(), policy, nil
}

func (r *Runtime) serveCheckerProbes() error {
	return r.Mesh.OnCheckerProbe(func(ctx context.Context, s *sfcp.Session, wire sfcp.CheckerProbeRequest) (sfcp.CheckerProbeHandler, error) {
		q, err := schema.Decode[control.CheckerProbeRequest](wire.Metadata)
		if err != nil || wire.Digest != q.Payload {
			return sfcp.CheckerProbeHandler{}, sfcp.ErrAdmission
		}
		q.At = 0
		owner, p, err := r.checkerRemoteOriginal(q)
		if err != nil || !r.resourceCaller(ctx, [32]byte(s.Peer().Key), p.Consumer) || !r.acceptsResourceKey(ctx, p.Provider) {
			return sfcp.CheckerProbeHandler{}, sfcp.ErrAdmission
		}
		if wire.Action == "run" {
			if wire.ExpiresAt != q.DeadlineUnixMilli {
				return sfcp.CheckerProbeHandler{}, sfcp.ErrAdmission
			}
			permit, _, _, err := owner.checkerRemotePermit(ctx, q)
			if err != nil || permit.Consumer != p.Consumer || permit.Provider != p.Provider {
				return sfcp.CheckerProbeHandler{}, sfcp.ErrAdmission
			}
		}
		return sfcp.CheckerProbeHandler{Lifetime: owner.ctx, Execute: func(ctx context.Context, body []byte) (sfcp.CheckerProbeResult, error) {
			return owner.executeCheckerRemote(ctx, p, wire.Action, body)
		}}, nil
	})
}

// The provider serializes only native calls, independently of its own source
// checker flow. Two nodes inspecting each other never hold checkerRunMu here.
func (r *Runtime) executeCheckerRemote(ctx context.Context, original checkerRemoteCall, action string, body []byte) (sfcp.CheckerProbeResult, error) {
	if ctx == nil || r.Identity == nil || original.validate(r.controlPolicy.Cluster, r.Identity.Public) != nil {
		return sfcp.CheckerProbeResult{}, checker.ErrContract
	}
	if !r.life.TryRLock() {
		return sfcp.CheckerProbeResult{}, checker.ErrPending
	}
	defer r.life.RUnlock()
	if r.closed || r.ctx.Err() != nil || r.workload == nil {
		return sfcp.CheckerProbeResult{}, checker.ErrPending
	}
	r.checkerRemoteMu.Lock()
	defer r.checkerRemoteMu.Unlock()
	if err := ctx.Err(); err != nil {
		return sfcp.CheckerProbeResult{}, err
	}
	if err := r.checkerRemoteIndex(); err != nil {
		return sfcp.CheckerProbeResult{}, err
	}
	raw, err := r.reports.GetBounded(original.key(), checkerRemoteRowBytes)
	if err == nil {
		p, err := schema.Decode[checkerRemoteCall](raw)
		if err != nil || p.validate(r.controlPolicy.Cluster, r.Identity.Public) != nil || p.Header != original.Header || p.Consumer != original.Consumer {
			return sfcp.CheckerProbeResult{}, checker.ErrContract
		}
		// Even a duplicate run request can ONLY observe its original call.
		return r.recoverCheckerRemote(ctx, &p)
	}
	if !errors.Is(err, storage.ErrMissing) {
		return sfcp.CheckerProbeResult{}, err
	}
	if _, known := r.checkerRemoteSizes[original.key()]; known {
		return sfcp.CheckerProbeResult{}, checker.ErrContract
	}
	if action == "recover" {
		// A positive no-effect tombstone wins the race against a delayed run.
		// Missing alone never becomes closure while that run could still arrive.
		original.Phase = "closed"
		if err = r.saveCheckerRemote(original); err != nil {
			return sfcp.CheckerProbeResult{}, err
		}
		return sfcp.CheckerProbeResult{Closed: true}, nil
	}
	if action != "run" {
		return sfcp.CheckerProbeResult{}, sfcp.ErrAdmission
	}
	if sha256.Sum256(body) != original.Query.Payload {
		return sfcp.CheckerProbeResult{}, sfcp.ErrAdmission
	}
	call, err := schema.Decode[checker.ProbeCall](body)
	if err != nil {
		return sfcp.CheckerProbeResult{}, err
	}
	permit, program, policy, err := r.checkerRemotePermit(ctx, original.Query)
	if err != nil || permit.Consumer != original.Consumer || permit.Provider != original.Provider || !permit.Matches(original.Query, call) || len(r.Identity.Certificate.Certificate) == 0 {
		return sfcp.CheckerProbeResult{}, sfcp.ErrAdmission
	}
	boot := sha256.Sum256(r.Identity.Certificate.Certificate[0])
	if permit.Target.OwnerBoot != hex.EncodeToString(boot[:]) {
		return sfcp.CheckerProbeResult{}, sfcp.ErrAdmission
	}
	normal, err := program.ValidateAppProbeCall(original.Query.Run, original.Query.Stop, policy, call)
	if err != nil {
		return sfcp.CheckerProbeResult{}, err
	}
	if err = r.saveCheckerRemote(original); err != nil {
		return sfcp.CheckerProbeResult{}, err
	}
	original.Phase = "dispatched"
	if err = r.saveCheckerRemote(original); err != nil {
		return sfcp.CheckerProbeResult{}, err
	}
	authorize := func(ctx context.Context) error {
		latest, _, _, err := r.checkerRemotePermit(ctx, original.Query)
		before, after := permit, latest
		before.Index, after.Index = 0, 0
		if err != nil || before != after || !latest.Matches(original.Query, call) {
			return sfcp.ErrAdmission
		}
		return nil
	}
	lease, effectErr := r.workload.BorrowReadProbe(ctx, permit.Target.TaskKey, permit.Target.Generation, permit.Target.Revision, permit.Target.NativeID, original.Query.Run.Request.RunID, original.Call)
	reply := checker.ProbeReply{Schema: 1, Binding: call.Binding, Sequence: call.Sequence, Kind: call.Kind, Failed: true}
	if effectErr == nil && lease.Target.Status.StartedAt != permit.Target.StartedAt {
		effectErr = sfcp.ErrAdmission
	}
	if effectErr == nil {
		probe := checkerRemoteLease{manager: r.workload, request: original.Query.Run.Request, lease: lease, authorize: authorize, save: func(next workload.ProbeExecReceipt) error { return r.saveCheckerRemoteExec(&original, next) }}
		reply, effectErr = checker.DispatchProbe(ctx, normal, &probe)
	}
	// The synchronous SDK/connection operation above has returned. Only its
	// exact I/O pin may now be returned, even if native exec is still unknown.
	cleanup := r.workload.ReturnReadCall(context.Background(), original.Query.Run.Request, original.Query.Service, original.Call)
	if cleanup != nil {
		return sfcp.CheckerProbeResult{}, cleanup
	}
	if !r.checkerRemoteReady {
		return sfcp.CheckerProbeResult{}, checker.ErrPending
	}
	if original.Execution != nil && !original.Execution.Terminal() {
		return sfcp.CheckerProbeResult{Closed: false}, nil
	}
	if effectErr != nil {
		reply = checker.ProbeReply{Schema: 1, Binding: call.Binding, Sequence: call.Sequence, Kind: call.Kind, Failed: true}
	}
	original.Phase = "closed"
	if err = r.saveCheckerRemote(original); err != nil {
		return sfcp.CheckerProbeResult{}, err
	}
	if err = authorize(ctx); err != nil {
		return sfcp.CheckerProbeResult{Closed: true}, nil
	}
	data, err := json.Marshal(reply)
	return sfcp.CheckerProbeResult{Closed: true, Data: data}, err
}

func (r *Runtime) recoverCheckerRemote(ctx context.Context, p *checkerRemoteCall) (sfcp.CheckerProbeResult, error) {
	if p.Phase == "closed" {
		return sfcp.CheckerProbeResult{Closed: true}, nil
	}
	if err := r.workload.ReturnReadCall(ctx, p.Query.Run.Request, p.Query.Service, p.Call); err != nil {
		return sfcp.CheckerProbeResult{}, err
	}
	if p.Execution != nil && !p.Execution.Terminal() {
		err := r.workload.RecoverProbeExec(ctx, p.Query.Run.Request, *p.Execution, func(next workload.ProbeExecReceipt) error { return r.saveCheckerRemoteExec(p, next) })
		if errors.Is(err, workload.ErrProbeExecPending) {
			return sfcp.CheckerProbeResult{Closed: false}, nil
		}
		if err != nil {
			return sfcp.CheckerProbeResult{}, err
		}
	}
	p.Phase = "closed"
	if err := r.saveCheckerRemote(*p); err != nil {
		return sfcp.CheckerProbeResult{}, err
	}
	// Recovery proves closure only, never resurrects discarded private output.
	return sfcp.CheckerProbeResult{Closed: true}, nil
}

// Thin binding to the SAME native SDK adapters used by local ServiceProbe;
// no second probe algorithm or per-call sequence reset at the provider.
type checkerRemoteLease struct {
	manager   *workload.Manager
	request   contract.Request
	lease     workload.ReadProbeLease
	authorize func(context.Context) error
	save      func(workload.ProbeExecReceipt) error
}

func (p *checkerRemoteLease) Connect(ctx context.Context, q contract.TCPProbe) (contract.TCPResult, error) {
	return p.manager.ReadProbeTCP(ctx, p.lease, q, p.authorize)
}
func (p *checkerRemoteLease) Healthz(ctx context.Context, q contract.HTTPProbe) (contract.HTTPResult, error) {
	return p.manager.ReadProbeHTTP(ctx, p.lease, q, p.authorize)
}
func (p *checkerRemoteLease) File(ctx context.Context, q contract.FileProbe) (contract.FileResult, error) {
	return p.manager.ReadProbeFile(ctx, p.lease, q, p.authorize)
}
func (p *checkerRemoteLease) Exec(ctx context.Context, q contract.ExecProbe) (contract.ExecResult, error) {
	return p.manager.ExecuteProbeExec(ctx, p.request, p.lease, q, p.save, p.authorize)
}
func (p *checkerRemoteLease) Dependency(context.Context, contract.DependencyProbe) (contract.DependencyResult, error) {
	return contract.DependencyResult{}, checker.ErrContract
}
