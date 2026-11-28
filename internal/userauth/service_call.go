// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/servicecall"
	"github.com/jay94ks/seafield/internal/sfcp"
)

type ServiceCallInput struct {
	Length int
	Digest [32]byte
}

func (i ServiceCallInput) Valid() bool {
	return i.Length >= 0 && i.Length <= servicecall.MaxBody && i.Digest != ([32]byte{})
}

// ServiceCallQuery is the header of one service call: the call without its
// body, and the body's length and digest. The body follows as input frames
// after "continue"; the reply's Data is the servicecall.Result.
type ServiceCallQuery struct {
	Tenant string
	Call   servicecall.Request
	Input  ServiceCallInput
}

func (q ServiceCallQuery) Valid() bool {
	return q.Tenant != "" && q.Call.Valid() && q.Call.Body == nil && q.Input.Valid()
}

var ServiceCallMethod = defineRoute(Method[ServiceCallQuery, servicecall.Result]{Name: "service-call"}, false)

// serviceCall is the request's decoded header when it is a typed service-call.
func (r Request) serviceCall() (ServiceCallQuery, bool) {
	rule, typed, ok := r.typedMethod()
	if !typed || !ok || r.Method != ServiceCallMethod.Name {
		return ServiceCallQuery{}, false
	}
	p, _ := rule.decode(r.Params)
	q, is := p.(ServiceCallQuery)
	return q, is
}

// callResult decodes a service-call reply's Data.
func callResult(reply Reply) (servicecall.Result, bool) {
	var r servicecall.Result
	return r, len(reply.Data) != 0 && lenient(reply.Data, &r) == nil && r.Valid()
}

type ServiceCallRelay struct {
	Target servicecall.Target
	Epoch  uint64
}

func (c Client) CallService(ctx context.Context, peer sfcp.Peer, session access.Session, tenant string, q servicecall.Request) (servicecall.Result, error) {
	if len(q.Body) > servicecall.MaxBody {
		return servicecall.Result{Code: servicecall.TooLarge}, nil
	}
	if c.Verify(session) != nil || tenant == "" || !q.Valid() || c.Self == nil || c.Self.Public != session.Key {
		return servicecall.Result{}, sfcp.ErrAdmission
	}
	body := q.Body
	q.Body = nil
	params, err := json.Marshal(ServiceCallQuery{Tenant: tenant, Call: q, Input: ServiceCallInput{len(body), sha256.Sum256(body)}})
	if err != nil {
		return servicecall.Result{}, err
	}
	raw, err := requestBody(Request{Method: ServiceCallMethod.Name, Params: params})
	if err != nil {
		return servicecall.Result{}, err
	}
	reply, err := c.serviceCallExchange(ctx, peer, body, 1, func(conn *sfcp.Session) (Envelope, error) {
		return Envelope{Body: raw, Session: &session, Signature: ed25519.Sign(c.Self.Private, access.RequestBytes(session, conn.PeerChallenge(), raw))}, nil
	})
	if err != nil {
		return servicecall.Result{}, err
	}
	result, ok := callResult(reply)
	if !ok {
		return servicecall.Result{}, sfcp.ErrFrame
	}
	return result, nil
}

func (c Client) serviceCallExchange(ctx context.Context, peer sfcp.Peer, body []byte, kind uint8, makeEnvelope func(*sfcp.Session) (Envelope, error)) (reply Reply, err error) {
	if c.Mesh == nil || c.Self == nil || c.Mesh.LocalKey() != sfcp.Identity(c.Self.Public) || len(body) > servicecall.MaxBody {
		return reply, sfcp.ErrAdmission
	}
	conn, stream, err := c.openUser(ctx, peer)
	if err != nil {
		return reply, err
	}
	defer stream.CancelRead(0)
	defer stream.Close()
	envelope, err := makeEnvelope(conn)
	if err != nil {
		return reply, err
	}
	header, err := json.Marshal(envelope)
	if err != nil {
		return reply, err
	}
	digest := sha256.Sum256(header)
	stop := context.AfterFunc(ctx, func() { stream.CancelRead(1); stream.CancelWrite(1) })
	defer stop()
	id := c.Mesh.NextRequest()
	frame := sfcp.Frame{Purpose: sfcp.User, Kind: kind, Request: id, Fields: []sfcp.Field{{Tag: 1, Required: true, Value: header}, {Tag: 2, Required: true, Value: digest[:]}}}
	if err = sfcp.WriteFrame(stream, frame); err != nil {
		return reply, err
	}
	read := func() (Reply, error) {
		var result Reply
		f, err := sfcp.ReadFrame(stream, 128<<10)
		if err != nil {
			return result, err
		}
		if f.Purpose != sfcp.User || f.Kind != 2 || f.Request != id || conn.Admit(f, sfcp.User, false) != nil || !bytes.Equal(f.Fields[1].Value, digest[:]) || lenient(f.Fields[0].Value, &result) != nil || result.Schema != 1 {
			return result, sfcp.ErrFrame
		}
		return result, nil
	}
	ready, err := read()
	if err != nil {
		return ready, err
	}
	if ready.Code != "continue" {
		_ = stream.Close()
		if streamEOF(stream) != nil {
			return ready, sfcp.ErrFrame
		}
		if _, ok := callResult(ready); ready.Code == "ok" && ok {
			return ready, nil
		}
		return ready, &Error{Code: ready.Code, Phase: sfcp.Completed}
	}
	if err = writeUserInput(stream, id, digest, body); err != nil {
		return reply, err
	}
	if err = stream.Close(); err != nil {
		return reply, err
	}
	reply, err = read()
	if err != nil {
		return reply, &Error{Code: "unknown", Phase: sfcp.Unknown, Cause: err}
	}
	if streamEOF(stream) != nil {
		return reply, &Error{Code: "unknown", Phase: sfcp.Unknown, Cause: sfcp.ErrFrame}
	}
	if reply.Code != "ok" {
		return reply, &Error{Code: reply.Code, Phase: sfcp.Completed}
	}
	return reply, nil
}

func (s Service) forwardServiceCall(ctx context.Context, peer sfcp.Peer, body []byte, envelope Envelope, binding userBinding, target *ServiceCallRelay) Reply {
	c := Client{Mesh: s.Mesh, Self: s.Self, Cluster: s.Policy.Cluster}
	reply, err := c.serviceCallExchange(ctx, peer, body, 3, func(conn *sfcp.Session) (Envelope, error) {
		copy := envelope
		copy.Relay = &Relay{Node: s.Self.Public, Target: [32]byte(peer.Key), Caller: binding.key, Challenge: binding.challenge, Connection: conn.PeerChallenge(), ServiceCall: target}
		copy.Relay.Signature = ed25519.Sign(s.Self.Private, RelayBytes(s.Policy.Cluster, copy))
		return copy, nil
	})
	if err != nil && reply.Code == "" {
		reply = Reply{Schema: 1, Code: "unknown"}
	}
	reply.RelayedBy = s.Self.Actor()
	return reply
}

func (s Service) streamServiceCall(ctx context.Context, conn *sfcp.Session, stream sfcp.Stream, frame sfcp.Frame, digest [32]byte, envelope Envelope, request Request, binding userBinding) error {
	call, ok := request.serviceCall()
	if envelope.Session == nil || !ok {
		return s.respond(stream, frame, digest, Reply{Schema: 1, Code: "invalid"})
	}
	var target *ServiceCallRelay
	if envelope.Relay != nil {
		target = envelope.Relay.ServiceCall
	}
	if target != nil && (!target.Target.Valid() || target.Target.Container.Owner != s.Self.Public || target.Target.Container.Tenant != call.Tenant || target.Target.Container.App != call.Call.App || target.Target.Container.Service != call.Call.Service || int(target.Target.Port) != call.Call.Port || target.Epoch == 0) {
		return s.respond(stream, frame, digest, Reply{Schema: 1, Code: "denied"})
	}
	ctx, cancel := context.WithTimeout(ctx, call.Call.Duration()+10*time.Second)
	defer cancel()
	current, view, allowed := s.planStreamView(ctx, binding, request, envelope, s.Engine.IsLeader())
	if allowed.Code != "ok" {
		return s.respond(stream, frame, digest, allowed)
	}
	if s.Engine.IsLeader() || target != nil {
		if s.ServiceCallLimiter == nil {
			return s.respond(stream, frame, digest, Reply{Schema: 1, Code: "unavailable"})
		}
		release, ok := s.ServiceCallLimiter.Acquire(call.Tenant, time.Now().Unix())
		if !ok {
			return s.respond(stream, frame, digest, dataReply("ok", servicecall.Result{Code: servicecall.RateLimited}))
		}
		defer release()
	}
	if err := s.respond(stream, frame, digest, Reply{Schema: 1, Code: "continue"}); err != nil {
		return err
	}
	var body []byte
	var err error
	if call.Input.Length == 0 {
		if call.Input.Digest != sha256.Sum256(nil) || streamEOF(stream) != nil {
			return sfcp.ErrFrame
		}
	} else {
		body, err = readUserInput(conn, stream, frame.Request, digest, call.Input.Length, call.Input.Digest, servicecall.MaxBody)
		if err != nil {
			return err
		}
	}
	defer clear(body)
	if !s.Engine.IsLeader() && target == nil {
		peer, ok := s.Engine.LeaderPeer()
		if !ok {
			return s.respond(stream, frame, digest, Reply{Schema: 1, Code: "unavailable"})
		}
		return s.respond(stream, frame, digest, current.forwardServiceCall(ctx, peer, body, envelope, binding, nil))
	}
	current, view, allowed = current.planStreamView(ctx, binding, request, envelope, s.Engine.IsLeader())
	if allowed.Code != "ok" {
		return s.respond(stream, frame, digest, allowed)
	}
	if target == nil {
		selected, err := current.Policy.ServiceCallTarget(view.State, *envelope.Session, time.Now().Unix(), call.Tenant, call.Call, s.Self.Public)
		if err != nil {
			return s.respond(stream, frame, digest, imageBuildError(err))
		}
		if !selected.Valid() {
			return s.respond(stream, frame, digest, dataReply("ok", servicecall.Result{Code: servicecall.NoReadyTask}))
		}
		target = &ServiceCallRelay{Target: selected, Epoch: view.State.ModuleEpoch()}
		if selected.Container.Owner != s.Self.Public {
			peer, ok := s.Mesh.Peer(sfcp.Identity(selected.Container.Owner))
			if !ok || !peer.Member || peer.ID != selected.Container.Node {
				return s.respond(stream, frame, digest, Reply{Schema: 1, Code: "unavailable"})
			}
			return s.respond(stream, frame, digest, current.forwardServiceCall(ctx, peer, body, envelope, binding, target))
		}
	}
	if current.ServiceCaller == nil {
		return s.respond(stream, frame, digest, Reply{Schema: 1, Code: "unavailable"})
	}
	q := call.Call
	q.Body = body
	out, err := current.ServiceCaller(ctx, control.ServiceCallRead{Session: *envelope.Session, Tenant: call.Tenant, Request: q, Target: target.Target, Epoch: target.Epoch})
	if err != nil {
		return s.respond(stream, frame, digest, imageBuildError(err))
	}
	if !out.Valid() {
		return sfcp.ErrFrame
	}
	return s.respond(stream, frame, digest, dataReply("ok", out))
}
