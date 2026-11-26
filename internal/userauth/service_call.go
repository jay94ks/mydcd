// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/servicecall"
)

type ServiceCallInput struct {
	Length int
	Digest [32]byte
}

func (i ServiceCallInput) Valid() bool {
	return i.Length >= 0 && i.Length <= servicecall.MaxBody && i.Digest != ([32]byte{})
}

type ServiceCallRelay struct {
	Target servicecall.Target
	Epoch  uint64
}

func (c Client) CallService(ctx context.Context, peer mydcp.Peer, session access.Session, tenant string, q servicecall.Request) (servicecall.Result, error) {
	if len(q.Body) > servicecall.MaxBody {
		return servicecall.Result{Code: servicecall.TooLarge}, nil
	}
	if c.Verify(session) != nil || tenant == "" || !q.Valid() || c.Self == nil || c.Self.Public != session.Key {
		return servicecall.Result{}, mydcp.ErrAdmission
	}
	body := q.Body
	q.Body = nil
	raw, err := requestBody(Request{Method: "service-call", Tenant: tenant, ServiceCall: &q, ServiceInput: &ServiceCallInput{len(body), sha256.Sum256(body)}})
	if err != nil {
		return servicecall.Result{}, err
	}
	reply, err := c.serviceCallExchange(ctx, peer, body, 1, func(conn *mydcp.Session) (Envelope, error) {
		return Envelope{Body: raw, Session: &session, Signature: ed25519.Sign(c.Self.Private, access.RequestBytes(session, conn.PeerChallenge(), raw))}, nil
	})
	if err != nil {
		return servicecall.Result{}, err
	}
	if reply.ServiceCall == nil || !reply.ServiceCall.Valid() {
		return servicecall.Result{}, mydcp.ErrFrame
	}
	return *reply.ServiceCall, nil
}

func (c Client) serviceCallExchange(ctx context.Context, peer mydcp.Peer, body []byte, kind uint8, makeEnvelope func(*mydcp.Session) (Envelope, error)) (reply Reply, err error) {
	if c.Mesh == nil || c.Self == nil || c.Mesh.LocalKey() != mydcp.Identity(c.Self.Public) || len(body) > servicecall.MaxBody {
		return reply, mydcp.ErrAdmission
	}
	conn, err := c.Mesh.Dial(ctx, peer)
	if err != nil {
		return reply, err
	}
	envelope, err := makeEnvelope(conn)
	if err != nil {
		return reply, err
	}
	header, err := json.Marshal(envelope)
	if err != nil {
		return reply, err
	}
	digest := sha256.Sum256(header)
	stream, err := conn.OpenManagement(ctx)
	if err != nil {
		return reply, err
	}
	defer stream.CancelRead(0)
	defer stream.Close()
	stop := context.AfterFunc(ctx, func() { stream.CancelRead(1); stream.CancelWrite(1) })
	defer stop()
	id := c.Mesh.NextRequest()
	frame := mydcp.Frame{Purpose: mydcp.User, Kind: kind, Request: id, Fields: []mydcp.Field{{Tag: 1, Required: true, Value: header}, {Tag: 2, Required: true, Value: digest[:]}}}
	if err = mydcp.WriteFrame(stream, frame); err != nil {
		return reply, err
	}
	read := func() (Reply, error) {
		var result Reply
		f, err := mydcp.ReadFrame(stream, 128<<10)
		if err != nil {
			return result, err
		}
		if f.Purpose != mydcp.User || f.Kind != 2 || f.Request != id || conn.Admit(f, mydcp.User, false) != nil || !bytes.Equal(f.Fields[1].Value, digest[:]) || strict(f.Fields[0].Value, &result) != nil || result.Schema != 1 {
			return result, mydcp.ErrFrame
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
			return ready, mydcp.ErrFrame
		}
		if ready.Code == "ok" && ready.ServiceCall != nil && ready.ServiceCall.Valid() {
			return ready, nil
		}
		return ready, &Error{Code: ready.Code, Phase: mydcp.Completed}
	}
	if err = writeUserInput(stream, id, digest, body); err != nil {
		return reply, err
	}
	if err = stream.Close(); err != nil {
		return reply, err
	}
	reply, err = read()
	if err != nil {
		return reply, &Error{Code: "unknown", Phase: mydcp.Unknown, Cause: err}
	}
	if streamEOF(stream) != nil {
		return reply, &Error{Code: "unknown", Phase: mydcp.Unknown, Cause: mydcp.ErrFrame}
	}
	if reply.Code != "ok" {
		return reply, &Error{Code: reply.Code, Phase: mydcp.Completed}
	}
	return reply, nil
}

func (s Service) forwardServiceCall(ctx context.Context, peer mydcp.Peer, body []byte, envelope Envelope, binding userBinding, target *ServiceCallRelay) Reply {
	c := Client{Mesh: s.Mesh, Self: s.Self, Cluster: s.Policy.Cluster}
	reply, err := c.serviceCallExchange(ctx, peer, body, 3, func(conn *mydcp.Session) (Envelope, error) {
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

func (s Service) streamServiceCall(ctx context.Context, conn *mydcp.Session, stream mydcp.Stream, frame mydcp.Frame, digest [32]byte, envelope Envelope, request Request, binding userBinding) error {
	if envelope.Session == nil || request.ServiceCall == nil || request.ServiceInput == nil || !request.ServiceInput.Valid() || request.ServiceCall.Body != nil {
		return s.respond(stream, frame, digest, Reply{Schema: 1, Code: "invalid"})
	}
	var target *ServiceCallRelay
	if envelope.Relay != nil {
		target = envelope.Relay.ServiceCall
	}
	if target != nil && (!target.Target.Valid() || target.Target.Container.Owner != s.Self.Public || target.Target.Container.Tenant != request.Tenant || target.Target.Container.App != request.ServiceCall.App || target.Target.Container.Service != request.ServiceCall.Service || int(target.Target.Port) != request.ServiceCall.Port || target.Epoch == 0) {
		return s.respond(stream, frame, digest, Reply{Schema: 1, Code: "denied"})
	}
	ctx, cancel := context.WithTimeout(ctx, request.ServiceCall.Duration()+10*time.Second)
	defer cancel()
	current, view, allowed := s.planStreamView(ctx, binding, request, envelope, s.Engine.IsLeader())
	if allowed.Code != "ok" {
		return s.respond(stream, frame, digest, allowed)
	}
	if s.Engine.IsLeader() || target != nil {
		if s.ServiceCallLimiter == nil {
			return s.respond(stream, frame, digest, Reply{Schema: 1, Code: "unavailable"})
		}
		release, ok := s.ServiceCallLimiter.Acquire(request.Tenant, time.Now().Unix())
		if !ok {
			return s.respond(stream, frame, digest, Reply{Schema: 1, Code: "ok", ServiceCall: &servicecall.Result{Code: servicecall.RateLimited}})
		}
		defer release()
	}
	if err := s.respond(stream, frame, digest, Reply{Schema: 1, Code: "continue"}); err != nil {
		return err
	}
	var body []byte
	var err error
	if request.ServiceInput.Length == 0 {
		if request.ServiceInput.Digest != sha256.Sum256(nil) || streamEOF(stream) != nil {
			return mydcp.ErrFrame
		}
	} else {
		body, err = readUserInput(conn, stream, frame.Request, digest, request.ServiceInput.Length, request.ServiceInput.Digest, servicecall.MaxBody)
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
		selected, err := current.Policy.ServiceCallTarget(view.State, *envelope.Session, time.Now().Unix(), request.Tenant, *request.ServiceCall, s.Self.Public)
		if err != nil {
			return s.respond(stream, frame, digest, imageBuildError(err))
		}
		if !selected.Valid() {
			return s.respond(stream, frame, digest, Reply{Schema: 1, Code: "ok", ServiceCall: &servicecall.Result{Code: servicecall.NoReadyTask}})
		}
		target = &ServiceCallRelay{Target: selected, Epoch: view.State.ModuleEpoch()}
		if selected.Container.Owner != s.Self.Public {
			peer, ok := s.Mesh.Peer(mydcp.Identity(selected.Container.Owner))
			if !ok || !peer.Member || peer.ID != selected.Container.Node {
				return s.respond(stream, frame, digest, Reply{Schema: 1, Code: "unavailable"})
			}
			return s.respond(stream, frame, digest, current.forwardServiceCall(ctx, peer, body, envelope, binding, target))
		}
	}
	if current.ServiceCaller == nil {
		return s.respond(stream, frame, digest, Reply{Schema: 1, Code: "unavailable"})
	}
	q := *request.ServiceCall
	q.Body = body
	out, err := current.ServiceCaller(ctx, control.ServiceCallRead{Session: *envelope.Session, Tenant: request.Tenant, Request: q, Target: target.Target, Epoch: target.Epoch})
	if err != nil {
		return s.respond(stream, frame, digest, imageBuildError(err))
	}
	if !out.Valid() {
		return mydcp.ErrFrame
	}
	return s.respond(stream, frame, digest, Reply{Schema: 1, Code: "ok", ServiceCall: &out})
}
