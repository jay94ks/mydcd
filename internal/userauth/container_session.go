// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
)

type ContainerSessionRequest struct {
	Schema    uint8
	Method    string
	Tenant    string
	Selection containerops.Selection
	Spec      *containerops.SessionSpec   `json:",omitempty"`
	Intent    *containerops.SessionIntent `json:",omitempty"`
	Nonce     [32]byte
}

type ContainerSessionReply struct {
	Schema    uint8
	Code      string
	Supported bool
	Target    *containerops.Target     `json:",omitempty"`
	Status    *containerops.ExecStatus `json:",omitempty"`
}

func (r ContainerSessionReply) valid() bool {
	if r.Schema != 1 {
		return false
	}
	switch r.Code {
	case "ready":
		return r.Supported && r.Target != nil && r.Target.Valid() && r.Status == nil
	case "ok":
		return r.Supported && !(r.Target != nil && r.Status != nil)
	case "denied", "unavailable", "target-changed", "unsupported", "conflict":
		return !r.Supported && r.Target == nil && r.Status == nil
	}
	return false
}

func (q ContainerSessionRequest) valid() bool {
	if q.Schema != 1 || q.Nonce == ([32]byte{}) {
		return false
	}
	switch q.Method {
	case "capabilities":
		return q.Tenant == "" && q.Selection == (containerops.Selection{}) && q.Spec == nil && q.Intent == nil
	case "resolve":
		return q.Tenant != "" && q.Selection.Valid() && q.Spec != nil && q.Spec.Validate() == nil && q.Intent == nil && (q.Spec.Query == nil || q.Spec.Query.Selection == q.Selection)
	case "open", "status":
		return q.Selection == (containerops.Selection{}) && q.Spec == nil && q.Intent != nil && q.Intent.Validate() == nil && q.Tenant == q.Intent.Target.Tenant && (q.Method != "status" || q.Intent.Spec.Kind == "exec")
	}
	return false
}

func containerSessionReply(stream sfcp.Stream, frame sfcp.Frame, digest [32]byte, reply ContainerSessionReply) error {
	reply.Schema = 1
	if !reply.valid() {
		return sfcp.ErrFrame
	}
	raw, err := json.Marshal(reply)
	if err != nil {
		return err
	}
	return sfcp.WriteFrame(stream, sfcp.Frame{Purpose: sfcp.ContainerSession, Kind: 2, Request: frame.Request, Fields: []sfcp.Field{{Tag: 1, Required: true, Value: raw}, {Tag: 2, Required: true, Value: digest[:]}}})
}

func (s Service) handleContainerSession(ctx context.Context, conn *sfcp.Session, stream sfcp.Stream, frame sfcp.Frame) error {
	ctx, cancelLifetime := context.WithCancel(ctx)
	defer cancelLifetime()
	if s.ContainerLifetime != nil {
		stop := context.AfterFunc(s.ContainerLifetime, cancelLifetime)
		defer stop()
	}
	if frame.Kind != 1 && frame.Kind != 3 {
		return sfcp.ErrFrame
	}
	digest := sha256.Sum256(frame.Fields[0].Value)
	if !bytes.Equal(digest[:], frame.Fields[1].Value) {
		return sfcp.ErrFrame
	}
	envelope, err := schema.Decode[Envelope](frame.Fields[0].Value)
	if err != nil {
		return sfcp.ErrFrame
	}
	defer clear(frame.Fields[0].Value)
	defer clear(envelope.Body)
	q, err := schema.Decode[ContainerSessionRequest](envelope.Body)
	respond := func(code string) error {
		return containerSessionReply(stream, frame, digest, ContainerSessionReply{Code: code})
	}
	if err != nil || !q.valid() || envelope.Session == nil {
		return respond("denied")
	}
	binding, err := s.binding(conn, frame.Kind, envelope)
	if err != nil || binding.key != envelope.Session.Key {
		return respond("denied")
	}
	admit, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	v, err := s.Engine.Read(admit, false)
	if err != nil || s.Enabled != nil && !s.Enabled(v.State) {
		return respond("unavailable")
	}
	policy, err := s.Policy.Current(v.State)
	if err != nil {
		return respond("unsupported")
	}
	catalog, err := policy.Catalog(v.State)
	method := "container-session-open"
	if q.Method == "status" {
		method = "container-exec-status"
	}
	if err != nil || catalog.VerifySession(*envelope.Session, policy.Cluster, policy.Issuer(envelope.Session.Issuer), time.Now().Unix()) != nil || !s.nodeRequestAllowed(v.State, catalog, Request{Method: method, Tenant: q.Tenant}, envelope) {
		return respond("denied")
	}
	if s.ContainerPlanner == nil || s.ContainerRunner == nil || s.ContainerExecObserver == nil {
		return respond("unsupported")
	}
	if q.Method != "open" {
		if streamEOF(stream) != nil {
			return sfcp.ErrFrame
		}
		if q.Method == "capabilities" {
			return containerSessionReply(stream, frame, digest, ContainerSessionReply{Code: "ok", Supported: true})
		}
		if q.Method == "resolve" {
			target, err := s.ContainerPlanner(admit, control.ContainerSessionPlan{Session: *envelope.Session, Tenant: q.Tenant, Selection: q.Selection, Spec: *q.Spec})
			if err != nil {
				return respond("denied")
			}
			return containerSessionReply(stream, frame, digest, ContainerSessionReply{Code: "ok", Supported: true, Target: &target})
		}
		if q.Intent.User != envelope.Session.User {
			return respond("denied")
		}
		owner, err := s.resourceOwner(v.State, q.Intent.Target.Node, q.Intent.Target.Owner)
		if err != nil {
			return respond("denied")
		}
		if owner != s.Self.Public {
			return s.forwardContainerSession(ctx, conn, stream, frame, digest, envelope, binding, q)
		}
		status, err := s.ContainerExecObserver(admit, *envelope.Session, *q.Intent)
		if err != nil {
			return respond("unavailable")
		}
		return containerSessionReply(stream, frame, digest, ContainerSessionReply{Code: "ok", Supported: true, Status: &status})
	}
	i := *q.Intent
	now := time.Now().Unix()
	if i.User != envelope.Session.User || i.Session != access.ExactSessionDigest(*envelope.Session) || i.Verify(envelope.Session.Key) != nil || i.At > now || now-i.At > 30 {
		return respond("denied")
	}
	selection, err := policy.ContainerSessionSelection(v.State, i.Target)
	if err != nil {
		return respond("target-changed")
	}
	resolvedSpec := i.Spec
	if i.Spec.Query != nil {
		query := *i.Spec.Query
		query.Selection = selection
		resolvedSpec.Query = &query
	}
	current, err := s.ContainerPlanner(admit, control.ContainerSessionPlan{Session: *envelope.Session, Tenant: q.Tenant, Selection: selection, Spec: resolvedSpec})
	if err != nil || !current.Matches(i.Target) {
		return respond("target-changed")
	}
	owner, err := s.resourceOwner(v.State, i.Target.Node, i.Target.Owner)
	if err != nil {
		return respond("denied")
	}
	if owner != s.Self.Public {
		return s.forwardContainerSession(ctx, conn, stream, frame, digest, envelope, binding, q)
	}
	if err = containerSessionReply(stream, frame, digest, ContainerSessionReply{Code: "ready", Supported: true, Target: &current}); err != nil {
		return err
	}
	channel, err := newContainerChannel(ctx, conn, stream, frame.Request, i, envelope.Session.ExpiresAt, false)
	if err != nil {
		return err
	}
	defer channel.releaseContext()
	return s.ContainerRunner(channel.Context(), *envelope.Session, i, channel)
}

func (c Client) containerSessionExchange(ctx context.Context, peer sfcp.Peer, request ContainerSessionRequest, kind uint8, setup time.Duration, makeEnvelope func(*sfcp.Session, []byte) (Envelope, error)) (*ContainerChannel, ContainerSessionReply, error) {
	var reply ContainerSessionReply
	if !request.valid() || c.Mesh == nil || c.Self == nil || c.Self.Public != [32]byte(c.Mesh.LocalKey()) {
		return nil, reply, sfcp.ErrAdmission
	}
	if setup <= 0 || setup > time.Minute {
		return nil, reply, sfcp.ErrAdmission
	}
	admit, finish := context.WithTimeout(ctx, setup)
	defer finish()
	conn, err := c.Mesh.Dial(admit, peer)
	if err != nil {
		return nil, reply, &Error{Code: "transport", Phase: sfcp.NotSent, Cause: err, stage: "container-dial"}
	}
	body, err := json.Marshal(request)
	if err != nil {
		return nil, reply, err
	}
	defer clear(body)
	envelope, err := makeEnvelope(conn, body)
	if err != nil {
		return nil, reply, err
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		return nil, reply, err
	}
	defer clear(raw)
	digest := sha256.Sum256(raw)
	stream, err := conn.OpenContainerStream(admit)
	if err != nil {
		return nil, reply, &Error{Code: "transport", Phase: sfcp.NotSent, Cause: err, stage: "container-open"}
	}
	keep := false
	defer func() {
		if !keep {
			stream.CancelRead(0)
			stream.CancelWrite(0)
		}
	}()
	stop := context.AfterFunc(admit, func() { stream.CancelRead(1); stream.CancelWrite(1) })
	defer stop()
	deadline, _ := admit.Deadline()
	_ = stream.SetDeadline(deadline)
	id := c.Mesh.NextRequest()
	frame := sfcp.Frame{Purpose: sfcp.ContainerSession, Kind: kind, Request: id, Fields: []sfcp.Field{{Tag: 1, Required: true, Value: raw}, {Tag: 2, Required: true, Value: digest[:]}}}
	if _, err = sfcp.Encode(frame); err != nil {
		return nil, reply, err
	}
	if err = sfcp.WriteFrame(stream, frame); err != nil {
		return nil, reply, &Error{Code: "transport", Phase: sfcp.Unknown, Cause: err, stage: "container-send"}
	}
	if request.Method != "open" {
		if err = stream.Close(); err != nil {
			return nil, reply, err
		}
	}
	response, err := sfcp.ReadFrame(stream, 128<<10)
	if err != nil {
		return nil, reply, &Error{Code: "transport", Phase: sfcp.Unknown, Cause: err, stage: "container-accept"}
	}
	if response.Purpose != sfcp.ContainerSession || response.Kind != 2 || response.Request != id || conn.Admit(response, sfcp.ContainerSession, false) != nil || !bytes.Equal(response.Fields[1].Value, digest[:]) {
		return nil, reply, sfcp.ErrFrame
	}
	reply, err = schema.Decode[ContainerSessionReply](response.Fields[0].Value)
	if err != nil || !reply.valid() {
		return nil, reply, sfcp.ErrFrame
	}
	if request.Method == "open" && reply.Code == "ok" {
		return nil, reply, sfcp.ErrFrame
	}
	if request.Method != "open" || reply.Code != "ready" {
		if err = streamEOF(stream); err != nil {
			return nil, reply, err
		}
		if reply.Code != "ok" {
			return nil, reply, &Error{Code: reply.Code, Phase: sfcp.Completed}
		}
		return nil, reply, nil
	}
	if !reply.Supported || reply.Target == nil || !reply.Target.Matches(request.Intent.Target) {
		return nil, reply, sfcp.ErrFrame
	}
	channel, err := newContainerChannel(ctx, conn, stream, id, *request.Intent, envelope.Session.ExpiresAt, true)
	if err != nil {
		return nil, reply, err
	}
	keep = true
	return channel, reply, nil
}

func (c Client) callContainerSession(ctx context.Context, peer sfcp.Peer, session access.Session, q ContainerSessionRequest, setup time.Duration) (*ContainerChannel, ContainerSessionReply, error) {
	if c.Verify(session) != nil {
		return nil, ContainerSessionReply{}, sfcp.ErrAdmission
	}
	q.Schema = 1
	if _, err := rand.Read(q.Nonce[:]); err != nil {
		return nil, ContainerSessionReply{}, err
	}
	return c.containerSessionExchange(ctx, peer, q, 1, setup, func(conn *sfcp.Session, body []byte) (Envelope, error) {
		return Envelope{Body: body, Session: &session, Signature: ed25519.Sign(c.Self.Private, access.RequestBytes(session, conn.PeerChallenge(), body))}, nil
	})
}

func (c Client) ResolveContainerSession(ctx context.Context, peer sfcp.Peer, session access.Session, tenant string, selection containerops.Selection, spec containerops.SessionSpec) (containerops.Target, error) {
	_, reply, err := c.callContainerSession(ctx, peer, session, ContainerSessionRequest{Method: "resolve", Tenant: tenant, Selection: selection, Spec: &spec}, 10*time.Second)
	if err != nil {
		return containerops.Target{}, err
	}
	if !reply.Supported || reply.Target == nil || !reply.Target.Valid() || reply.Target.Cluster != c.Cluster || reply.Target.Tenant != tenant || (selection.Standalone == "" && (reply.Target.Standalone != "" || reply.Target.App != selection.App) || selection.Standalone != "" && reply.Target.Standalone != selection.Standalone) || selection.Service != "" && reply.Target.Service != selection.Service || selection.Instance != "" && selection.Instance != reply.Target.Instance || reply.Target.NativeID == "" || reply.Target.StartedAt == "" {
		return containerops.Target{}, sfcp.ErrFrame
	}
	return *reply.Target, nil
}
func (c Client) OpenContainerSession(ctx context.Context, peer sfcp.Peer, session access.Session, intent containerops.SessionIntent, setup time.Duration) (*ContainerChannel, error) {
	channel, _, err := c.callContainerSession(ctx, peer, session, ContainerSessionRequest{Method: "open", Tenant: intent.Target.Tenant, Intent: &intent}, setup)
	return channel, err
}
func (c Client) ContainerExecStatus(ctx context.Context, peer sfcp.Peer, session access.Session, intent containerops.SessionIntent) (containerops.ExecStatus, error) {
	_, reply, err := c.callContainerSession(ctx, peer, session, ContainerSessionRequest{Method: "status", Tenant: intent.Target.Tenant, Intent: &intent}, 10*time.Second)
	if err != nil {
		return containerops.ExecStatus{}, err
	}
	if reply.Status == nil || reply.Status.Schema != 1 || reply.Status.Request != intent.Request || reply.Status.Target != intent.Target || reply.Status.Receipt.Intent != intent.Digest() || reply.Status.Receipt.Validate() != nil {
		return containerops.ExecStatus{}, sfcp.ErrFrame
	}
	return *reply.Status, nil
}
