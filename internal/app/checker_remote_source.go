// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/schema"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
)

var errCheckerRemotePending = errors.New("original remote checker call is not closed")

// Compact child metadata in the SAME original observation. Its Run/Request
// is stored once in Active/Last; no raw typed body or private response is kept.
type checkerRemoteReceipt struct {
	Schema                             uint8
	Binding, Provider, Payload, Header [32]byte
	PolicyRevision, Sequence           uint64
	Kind, Service                      string
	DeadlineUnixMilli                  int64
	Phase                              string   // sent or closed
	Response                           [32]byte `json:",omitempty"`
}

func (e checkerRemoteReceipt) query(p checkerObservation) (control.CheckerProbeRequest, error) {
	active := p.Checkpoint.Active
	if active == nil && p.Checkpoint.Last != nil {
		active = &p.Checkpoint.Last.Run
	}
	if active == nil || active.Phase != checker.Dispatched {
		return control.CheckerProbeRequest{}, checker.ErrContract
	}
	return control.CheckerProbeRequest{Schema: 1, Task: p.Task, Binding: e.Binding, Run: *active, Stop: p.Checkpoint.Definition.Stop, PolicyRevision: e.PolicyRevision, Sequence: e.Sequence, Kind: e.Kind, Service: e.Service, Payload: e.Payload, DeadlineUnixMilli: e.DeadlineUnixMilli}, nil
}

func (p checkerObservation) validateRemoteCalls(owner [32]byte) error {
	if len(p.RemoteCalls) == 0 {
		return nil
	}
	if p.Checkpoint.Definition.Scope != "" || len(p.RemoteCalls)+len(p.Executions) > checker.MaxProbeCalls {
		return checker.ErrContract
	}
	seen := map[[32]byte]bool{}
	for _, e := range p.Executions {
		seen[e.Call] = true
	}
	for _, e := range p.RemoteCalls {
		q, err := e.query(p)
		if err != nil {
			return err
		}
		call := (checker.ProbeCall{Binding: checker.ProbeBinding(q.Run.Request), Sequence: e.Sequence}).ID()
		if e.Schema != 1 || e.Binding == ([32]byte{}) || e.Payload == ([32]byte{}) || e.Provider == ([32]byte{}) || e.Provider == owner || e.PolicyRevision == 0 || e.Sequence == 0 || e.Sequence > checker.MaxProbeCalls || e.Header != q.HeaderDigest() || e.DeadlineUnixMilli <= 0 || e.DeadlineUnixMilli > q.Run.Request.DeadlineUnixMilli || seen[call] {
			return checker.ErrContract
		}
		seen[call] = true
		if e.Kind != "healthz" && e.Kind != "connect" && e.Kind != "exec" && e.Kind != "file" {
			return checker.ErrContract
		}
		bound := false
		for _, target := range q.Run.Request.Targets {
			if target.Service == e.Service && target.Owner == hex.EncodeToString(e.Provider[:]) {
				bound = true
			}
		}
		if !bound || e.Phase != "sent" && e.Phase != "closed" || e.Phase == "sent" && (e.Response != ([32]byte{}) || p.Checkpoint.Active == nil) || e.Phase == "closed" && e.Response == ([32]byte{}) {
			return checker.ErrContract
		}
	}
	return nil
}

// Caller shares the run's checkpoint mutex with local exec saves. Individual
// SDK calls may be concurrent; none may overwrite another call's whole row.
func (r *Runtime) saveCheckerRemoteReceipt(p *checkerObservation, next checkerRemoteReceipt) error {
	if p == nil || p.Checkpoint.Active == nil || p.Checkpoint.Active.Phase != checker.Dispatched {
		return checker.ErrContract
	}
	candidate := *p
	candidate.RemoteCalls = slices.Clone(p.RemoteCalls)
	index := -1
	for i, old := range candidate.RemoteCalls {
		if old.Sequence != next.Sequence {
			continue
		}
		before, after := old, next
		before.Phase, after.Phase = "", ""
		before.Response, after.Response = [32]byte{}, [32]byte{}
		if before != after || next.Phase != "closed" || old.Phase == "closed" && next.Response != old.Response {
			return checker.ErrContract
		}
		index = i
	}
	if index < 0 {
		if next.Phase != "sent" {
			return checker.ErrContract
		}
		candidate.RemoteCalls = append(candidate.RemoteCalls, next)
	} else {
		candidate.RemoteCalls[index] = next
	}
	if err := r.saveCheckerObservation(candidate); err != nil {
		return err
	}
	*p = candidate
	return nil
}

func (p checkerObservation) remoteCallsClosed() bool {
	for _, e := range p.RemoteCalls {
		if e.Phase != "closed" {
			return false
		}
	}
	return true
}

func (r *Runtime) sendCheckerRemote(ctx context.Context, b deployment.Binding, task deployment.ObjectRef, program checker.TaskProgram, policy checker.TenantPolicy, point *checkerObservation, call checker.ProbeCall, save func(checkerRemoteReceipt) error) (checker.ProbeReply, error) {
	if point == nil || point.Checkpoint.Active == nil || point.Task != task || save == nil {
		return checker.ProbeReply{}, checker.ErrContract
	}
	service, err := call.TargetService(point.Checkpoint.Active.Request)
	if err != nil {
		return checker.ProbeReply{}, err
	}
	q := control.CheckerProbeRequest{Schema: 1, Task: task, Binding: b.Digest(), Run: *point.Checkpoint.Active, Stop: point.Checkpoint.Definition.Stop, PolicyRevision: policy.Revision, Sequence: call.Sequence, Kind: call.Kind, Service: service, Payload: call.Digest(), DeadlineUnixMilli: call.DeadlineUnixMilli}
	permit, actual, _, err := r.checkerRemotePermit(ctx, q)
	if err != nil {
		return checker.ProbeReply{}, err
	}
	if permit.Consumer != r.Identity.Public || permit.Provider == r.Identity.Public || !permit.Matches(q, call) || checkerProgramHash(actual) != checkerProgramHash(program) {
		return checker.ProbeReply{}, mydcp.ErrAdmission
	}
	e := checkerRemoteReceipt{Schema: 1, Binding: q.Binding, Provider: permit.Provider, Payload: q.Payload, Header: q.HeaderDigest(), PolicyRevision: q.PolicyRevision, Sequence: q.Sequence, Kind: q.Kind, Service: q.Service, DeadlineUnixMilli: q.DeadlineUnixMilli, Phase: "sent"}
	if err = save(e); err != nil {
		return checker.ProbeReply{}, err
	}
	body, err := json.Marshal(call)
	if err != nil {
		return checker.ProbeReply{}, err
	}
	defer clear(body)
	result, err := r.callCheckerRemote(ctx, q, permit.Provider, "run", body, func(closed bool, data []byte) error {
		if !closed {
			return nil
		}
		e.Phase = "closed"
		e.Response = sha256.Sum256(data)
		return save(e)
	})
	defer clear(result.Data)
	if err != nil {
		return checker.ProbeReply{}, err
	}
	if !result.Closed {
		return checker.ProbeReply{}, errCheckerRemotePending
	}
	// An old/recovered closure has no replayable output. Never turn it into
	// a new probe or a successful typed result.
	if len(result.Data) == 0 {
		return checker.ProbeReply{}, checker.ErrProbeRPC
	}
	// Closure cleanup remains valid after revocation, but releasing private
	// bytes to the script still requires the source's own CURRENT authority.
	latest, _, _, err := r.checkerRemotePermit(ctx, q)
	before, after := permit, latest
	before.Index, after.Index = 0, 0
	if err != nil || before != after || !latest.Matches(q, call) {
		return checker.ProbeReply{}, mydcp.ErrAdmission
	}
	reply, err := schema.Decode[checker.ProbeReply](result.Data)
	if err != nil || reply.Validate(call) != nil {
		return checker.ProbeReply{}, checker.ErrProbeRPC
	}
	return reply, nil
}

// Exactly one stream attempt. Recovery grants no new effect and retains the
// original execution deadline in metadata; only its observation window is new.
func (r *Runtime) callCheckerRemote(ctx context.Context, q control.CheckerProbeRequest, provider [32]byte, action string, body []byte, store func(bool, []byte) error) (mydcp.CheckerProbeResult, error) {
	if ctx == nil || r.Mesh == nil || r.ctx == nil || store == nil {
		return mydcp.CheckerProbeResult{}, errCheckerRemotePending
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	deadline := time.UnixMilli(q.DeadlineUnixMilli)
	if action == "recover" {
		deadline = time.Now().Add(30 * time.Second)
	}
	if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
		deadline = end
	}
	ctx, done := context.WithDeadline(ctx, deadline)
	defer done()
	peer, ok := r.resourcePeerForKey(ctx, provider)
	if !ok || !peer.Member {
		return mydcp.CheckerProbeResult{}, mydcp.ErrAdmission
	}
	return r.callCheckerRemotePeer(ctx, q, peer, action, body, store)
}

// The wire adapter consumes an already selected current peer. It never changes
// the original Query/Call; authority and retained routing stay with the caller.
func (r *Runtime) callCheckerRemotePeer(ctx context.Context, q control.CheckerProbeRequest, peer mydcp.Peer, action string, body []byte, store func(bool, []byte) error) (mydcp.CheckerProbeResult, error) {
	if ctx == nil || r.Mesh == nil || store == nil || !peer.Member {
		return mydcp.CheckerProbeResult{}, mydcp.ErrAdmission
	}
	session, err := r.Mesh.Dial(ctx, peer)
	if err != nil {
		return mydcp.CheckerProbeResult{}, err
	}
	q.At = 0
	metadata, err := json.Marshal(q)
	if err != nil {
		return mydcp.CheckerProbeResult{}, err
	}
	// A run must use the exact per-call deadline; a shorter caller context
	// only cancels observation, it must not change the original wire header.
	expires := q.DeadlineUnixMilli
	if action == "recover" {
		deadline, ok := ctx.Deadline()
		if !ok {
			return mydcp.CheckerProbeResult{}, mydcp.ErrAdmission
		}
		expires = deadline.UnixMilli()
	}
	wire := mydcp.CheckerProbeRequest{Schema: 1, Action: action, Metadata: metadata, Digest: q.Payload, Bytes: uint32(len(body)), ExpiresAt: expires}
	return session.CallCheckerProbe(ctx, wire, body, func(_ context.Context, closed bool, data []byte) error { return store(closed, data) })
}

func (r *Runtime) recoverCheckerRemotes(ctx context.Context, p *checkerObservation) error {
	var pending error
	for _, e := range slices.Clone(p.RemoteCalls) {
		if e.Phase == "closed" {
			continue
		}
		q, err := e.query(*p)
		if err != nil || q.HeaderDigest() != e.Header {
			return checker.ErrContract
		}
		closed := false
		var storeErr error
		_, err = r.callCheckerRemote(ctx, q, e.Provider, "recover", nil, func(done bool, data []byte) error {
			if !done {
				return nil
			}
			if len(data) != 0 {
				storeErr = checker.ErrContract
				return storeErr
			}
			e.Phase = "closed"
			e.Response = sha256.Sum256(nil)
			if err := r.saveCheckerRemoteReceipt(p, e); err != nil {
				storeErr = err
				return err
			}
			closed = true
			return nil
		})
		if storeErr != nil {
			return storeErr
		}
		if err != nil || !closed {
			pending = errors.Join(pending, errCheckerRemotePending, err)
		}
	}
	return pending
}
