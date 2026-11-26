// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"crypto/ed25519"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/credentials"
	"github.com/jay94ks/mydcd/internal/mydcp"
)

// Private input stays on the explicitly pinned owner connection. The normal
// follower relay never sees a password, generated token, or provider material.
func (s Service) handleInitialCredential(ctx context.Context, conn *mydcp.Session, stream mydcp.Stream, frame mydcp.Frame, digest [32]byte, envelope Envelope, request Request, binding userBinding) error {
	reply := Reply{Schema: 1, Code: "denied"}
	defer func() { clear(reply.InitialCredentialToken) }()
	if frame.Kind != 1 || envelope.Relay != nil || envelope.Session == nil || s.Credentials == nil || s.Self == nil || request.InitialCredential == nil {
		return s.respond(stream, frame, digest, reply)
	}
	r := *request.InitialCredential
	session := *envelope.Session
	if r.Owner != s.Self.Public || session.Key != binding.key || access.VerifyRequest(session, binding.challenge, envelope.Body, envelope.Signature) != nil {
		return s.respond(stream, frame, digest, reply)
	}
	view, err := s.authenticationView(ctx)
	if err != nil {
		reply.Code = "unavailable"
		return s.respond(stream, frame, digest, reply)
	}
	if s.Enabled != nil && !s.Enabled(view.State) || s.Policy.InitialCredentialAllowed(view.State, session, time.Now().Unix(), r) != nil {
		return s.respond(stream, frame, digest, reply)
	}
	var issued credentials.InitialIssued
	defer issued.Destroy()
	if request.Method == "initial-credential-stage" {
		source, sourceErr := conn.CredentialSource()
		if sourceErr != nil {
			return s.respond(stream, frame, digest, reply)
		}
		issued, err = s.Credentials.PrepareInitial(ctx, r, request.Secret, source, time.Now())
	} else {
		err = s.Credentials.ObserveInitial(ctx, r)
	}
	if err != nil {
		reply.Code = "credential-write-unknown"
		return s.respond(stream, frame, digest, reply)
	}
	// Provider work may overlap role/user/owner changes. Publication needs a
	// fresh quorum view and still performs its own exact target-user CAS.
	view, err = s.authenticationView(ctx)
	if err != nil {
		reply.Code = "unavailable"
		return s.respond(stream, frame, digest, reply)
	}
	if s.Enabled != nil && !s.Enabled(view.State) || s.Policy.InitialCredentialAllowed(view.State, session, time.Now().Unix(), r) != nil {
		reply.Code = "conflict"
		return s.respond(stream, frame, digest, reply)
	}
	fact, err := credentials.SignInitialFact(r, s.Self.Private)
	if err != nil {
		return s.respond(stream, frame, digest, reply)
	}
	reply.Code, reply.InitialCredentialFact = "ok", &fact
	if request.Method == "initial-credential-stage" {
		reply.InitialCredentialToken = issued.Token
	}
	return s.respond(stream, frame, digest, reply)
}

// StageInitialCredential is one explicit dispatch. The caller first persists
// PUBLIC InitialRequest; after any uncertain error it uses Observe, never
// repeats Stage. A returned token must remain in memory until the separately
// signed issue-initial-credential action succeeds, then be shown once/cleared.
func (c Client) StageInitialCredential(ctx context.Context, owner mydcp.Peer, session access.Session, request credentials.InitialRequest, password []byte) (Reply, error) {
	return c.initialCredentialExchange(ctx, owner, session, request, password, false)
}
func (c Client) ObserveInitialCredential(ctx context.Context, owner mydcp.Peer, session access.Session, request credentials.InitialRequest) (Reply, error) {
	return c.initialCredentialExchange(ctx, owner, session, request, nil, true)
}
func (c Client) initialCredentialExchange(ctx context.Context, owner mydcp.Peer, session access.Session, request credentials.InitialRequest, password []byte, observe bool) (Reply, error) {
	if c.Verify(session) != nil || !request.Valid() || request.Cluster != c.Cluster || request.Owner != [32]byte(owner.Key) || observe && password != nil {
		return Reply{}, mydcp.ErrAdmission
	}
	if !observe && (request.Method == access.Password && (len(password) == 0 || len(password) > 1024) || request.Method == access.Token && len(password) != 0) {
		return Reply{}, mydcp.ErrAdmission
	}
	method := "initial-credential-stage"
	if observe {
		method = "initial-credential-observe"
	}
	body, err := requestBody(Request{Method: method, InitialCredential: &request, Secret: password})
	if err != nil {
		return Reply{}, err
	}
	defer clear(body)
	reply, _, err := c.exchange(ctx, owner, func(conn *mydcp.Session) (Envelope, error) {
		return Envelope{Body: body, Session: &session, Signature: ed25519.Sign(c.Self.Private, access.RequestBytes(session, conn.PeerChallenge(), body))}, nil
	}, false)
	if err != nil {
		clear(reply.InitialCredentialToken)
		return Reply{}, err
	}
	fact := reply.InitialCredentialFact
	if fact == nil || !fact.Verify() || fact.Request != request || observe && len(reply.InitialCredentialToken) != 0 || request.Method == access.Password && len(reply.InitialCredentialToken) != 0 || request.Method == access.Token && !observe && len(reply.InitialCredentialToken) != 43 {
		clear(reply.InitialCredentialToken)
		return Reply{}, mydcp.ErrFrame
	}
	return reply, nil
}
