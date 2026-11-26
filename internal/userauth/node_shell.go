// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/schema"
)

// NodeShellStream is the existing native owner's original-ID SSH session. The
// transport never supplies replacement user/PTY parameters to the effect.
type NodeShellStream interface {
	io.ReadWriteCloser
	Resize(cols, rows uint16) error
	CloseWrite() error
	Wait() (control.NodeShellEnd, error)
	Metadata() control.NodeShellSession
}
type NodeShellRequest struct {
	Schema    uint8
	SessionID string
	Nonce     [32]byte
}
type NodeShellReply struct {
	Schema  uint8
	Code    string
	Session *control.NodeShellSession `json:",omitempty"`
}

func (q NodeShellRequest) valid() bool {
	return q.Schema == 1 && q.SessionID != "" && len(q.SessionID) <= 256 && q.Nonce != ([32]byte{})
}
func (r NodeShellReply) valid() bool {
	if r.Schema != 1 {
		return false
	}
	if r.Code == "ready" {
		return r.Session != nil && r.Session.SessionID != "" && r.Session.Account == access.NodeShellAccount && r.Session.State == "opened" && r.Session.OpenedAt > 0 && r.Session.End == nil
	}
	switch r.Code {
	case "forbidden", "node-shell-disabled", "node-shell-not-ready", "limit", "node-unreachable", "unavailable":
		return r.Session == nil
	}
	return false
}
func nodeShellResponse(stream mydcp.Stream, f mydcp.Frame, digest [32]byte, reply NodeShellReply) error {
	reply.Schema = 1
	if !reply.valid() {
		return mydcp.ErrFrame
	}
	raw, err := json.Marshal(reply)
	if err != nil {
		return err
	}
	return mydcp.WriteFrame(stream, mydcp.Frame{Purpose: mydcp.NodeShell, Kind: 2, Request: f.Request, Fields: []mydcp.Field{{1, true, raw}, {2, true, digest[:]}}})
}
func (s Service) handleNodeShell(ctx context.Context, conn *mydcp.Session, stream mydcp.Stream, frame mydcp.Frame) error {
	if frame.Kind != 1 && frame.Kind != 3 {
		return mydcp.ErrFrame
	}
	digest := sha256.Sum256(frame.Fields[0].Value)
	if !bytes.Equal(digest[:], frame.Fields[1].Value) {
		return mydcp.ErrFrame
	}
	envelope, err := schema.Decode[Envelope](frame.Fields[0].Value)
	defer clear(frame.Fields[0].Value)
	if err != nil {
		return mydcp.ErrFrame
	}
	defer clear(envelope.Body)
	respond := func(code string) error { return nodeShellResponse(stream, frame, digest, NodeShellReply{Code: code}) }
	q, err := schema.Decode[NodeShellRequest](envelope.Body)
	if err != nil || !q.valid() || envelope.Session == nil {
		return respond("forbidden")
	}
	binding, err := s.binding(conn, frame.Kind, envelope)
	if err != nil || binding.key != envelope.Session.Key || envelope.Relay != nil && envelope.Relay.ServiceCall != nil {
		return respond("forbidden")
	}
	admit, finish := context.WithTimeout(ctx, 10*time.Second)
	defer finish()
	view, err := s.authenticationView(admit)
	if err != nil || s.Enabled != nil && !s.Enabled(view.State) {
		return respond("unavailable")
	}
	policy, err := s.Policy.Current(view.State)
	if err != nil {
		return respond("forbidden")
	}
	catalog, err := policy.Catalog(view.State)
	if err != nil || !s.nodeRequestAllowed(view.State, catalog, Request{Method: "node-shell-open"}, envelope) {
		return respond("forbidden")
	}
	book, err := policy.NodeShells(view.State)
	if err != nil {
		return respond("unavailable")
	}
	record, ok := book.Record(q.SessionID)
	now := time.Now().Unix()
	if !ok || record.Session.User != envelope.Session.User || catalog.OperationAllowed(*envelope.Session, "open-node-shell") != nil || catalog.AuthorizeNodeShell(*envelope.Session, policy.Cluster, policy.Issuer(envelope.Session.Issuer), now, record.Session.Node, book.Policy) != nil {
		return respond("forbidden")
	}
	owner, err := s.resourceOwner(view.State, record.Session.Node, record.Owner)
	if err != nil {
		return respond("node-unreachable")
	}
	if owner != s.Self.Public {
		return s.forwardNodeShell(ctx, conn, stream, frame, digest, envelope, binding, q, owner)
	}
	if _, err = policy.NodeShellPermit(view.State, s.Self.Public, q.SessionID, now); err != nil {
		return respond(control.NodeShellErrorCode(err))
	}
	if s.NodeShellOpen == nil {
		return respond("node-shell-not-ready")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if s.NodeShellLifetime != nil {
		stop := context.AfterFunc(s.NodeShellLifetime, cancel)
		defer stop()
	}
	native, err := s.NodeShellOpen(ctx, q.SessionID)
	if err != nil {
		code := "unavailable"
		if errors.Is(err, access.ErrDenied) {
			code = "forbidden"
		} else if errors.Is(err, control.ErrNodeShellNotReady) {
			code = "node-shell-not-ready"
		}
		return respond(code)
	}
	defer native.Close()
	metadata := native.Metadata()
	if metadata.SessionID != q.SessionID || metadata.User != record.Session.User || metadata.Node != record.Session.Node || metadata.Username != record.Session.Username || metadata.Account != record.Session.Account || metadata.Sudo != record.Session.Sudo {
		return respond("unavailable")
	}
	if err = nodeShellResponse(stream, frame, digest, NodeShellReply{Code: "ready", Session: &metadata}); err != nil {
		return err
	}
	channel, err := newNodeShellChannel(ctx, conn, stream, frame.Request, sha256.Sum256(envelope.Body), envelope.Session.ExpiresAt, false)
	if err != nil {
		return err
	}
	defer channel.releaseContext()
	return serveNodeShell(channel, native)
}
func serveNodeShell(channel *NodeShellChannel, native NodeShellStream) error {
	input := make(chan error, 1)
	go func() {
		for {
			r, err := channel.Receive()
			if err != nil {
				_ = native.Close()
				input <- err
				return
			}
			switch r.Kind {
			case "stdin":
				var n int
				n, err = native.Write(r.Data)
				if err == nil && n != len(r.Data) {
					err = io.ErrShortWrite
				}
				clear(r.Data)
			case "resize":
				err = native.Resize(r.Cols, r.Rows)
			case "half-close":
				err = native.CloseWrite()
			case "ping":
				err = channel.Send(mydcp.NodeShellRecord{Kind: "ping"})
			}
			if err != nil {
				_ = native.Close()
				input <- err
				return
			}
		}
	}()
	defer func() { _ = native.Close(); channel.StopReceive(); <-input }()
	buffer := make([]byte, mydcp.NodeShellChunkBytes)
	defer clear(buffer)
	for {
		n, err := native.Read(buffer)
		if n > 0 {
			if e := channel.Send(mydcp.NodeShellRecord{Kind: "stdout", Data: buffer[:n]}); e != nil {
				return e
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				return err
			}
			break
		}
	}
	end, err := native.Wait()
	if err != nil {
		return err
	}
	wire := mydcp.NodeShellEnd{Code: end.Code, Reason: end.Reason}
	if end.ClosedBy != nil {
		wire.ClosedBy = &mydcp.NodeShellActor{User: end.ClosedBy.User, Username: end.ClosedBy.Username}
	}
	return channel.Send(mydcp.NodeShellRecord{Kind: "end", End: &wire})
}
func (c Client) nodeShellExchange(ctx context.Context, peer mydcp.Peer, q NodeShellRequest, expires int64, kind uint8, makeEnvelope func(*mydcp.Session, []byte) (Envelope, error)) (*NodeShellChannel, NodeShellReply, error) {
	var reply NodeShellReply
	if !q.valid() || c.Mesh == nil || c.Self == nil || c.Self.Public != [32]byte(c.Mesh.LocalKey()) {
		return nil, reply, mydcp.ErrAdmission
	}
	setup, finish := context.WithTimeout(ctx, 10*time.Second)
	defer finish()
	conn, err := c.Mesh.Dial(setup, peer)
	if err != nil {
		return nil, reply, &Error{Code: "transport", Phase: mydcp.NotSent, Cause: err}
	}
	body, err := json.Marshal(q)
	if err != nil {
		return nil, reply, err
	}
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
	stream, err := conn.OpenNodeShellStream(setup)
	if err != nil {
		return nil, reply, &Error{Code: "transport", Phase: mydcp.NotSent, Cause: err}
	}
	keep := false
	defer func() {
		if !keep {
			stream.CancelRead(0)
			stream.CancelWrite(0)
		}
	}()
	stop := context.AfterFunc(setup, func() { stream.CancelRead(1); stream.CancelWrite(1) })
	defer stop()
	deadline, _ := setup.Deadline()
	_ = stream.SetDeadline(deadline)
	id := c.Mesh.NextRequest()
	f := mydcp.Frame{Purpose: mydcp.NodeShell, Kind: kind, Request: id, Fields: []mydcp.Field{{1, true, raw}, {2, true, digest[:]}}}
	if err = mydcp.WriteFrame(stream, f); err != nil {
		return nil, reply, &Error{Code: "transport", Phase: mydcp.Unknown, Cause: err}
	}
	response, err := mydcp.ReadFrame(stream, 128<<10)
	if err != nil {
		return nil, reply, &Error{Code: "transport", Phase: mydcp.Unknown, Cause: err}
	}
	if response.Purpose != mydcp.NodeShell || response.Kind != 2 || response.Request != id || conn.Admit(response, mydcp.NodeShell, false) != nil || !bytes.Equal(response.Fields[1].Value, digest[:]) {
		return nil, reply, mydcp.ErrFrame
	}
	reply, err = schema.Decode[NodeShellReply](response.Fields[0].Value)
	if err != nil || !reply.valid() {
		return nil, reply, mydcp.ErrFrame
	}
	if reply.Code != "ready" {
		if streamEOF(stream) != nil {
			return nil, reply, mydcp.ErrFrame
		}
		return nil, reply, &Error{Code: reply.Code, Phase: mydcp.Completed}
	}
	if reply.Session.SessionID != q.SessionID {
		return nil, reply, mydcp.ErrFrame
	}
	channel, err := newNodeShellChannel(ctx, conn, stream, id, sha256.Sum256(body), expires, true)
	if err != nil {
		return nil, reply, err
	}
	keep = true
	return channel, reply, nil
}
func (c Client) OpenNodeShell(ctx context.Context, peer mydcp.Peer, session access.Session, originalID string) (*NodeShellChannel, control.NodeShellSession, error) {
	if c.Verify(session) != nil {
		return nil, control.NodeShellSession{}, mydcp.ErrAdmission
	}
	q := NodeShellRequest{Schema: 1, SessionID: originalID}
	if _, err := rand.Read(q.Nonce[:]); err != nil {
		return nil, control.NodeShellSession{}, err
	}
	channel, reply, err := c.nodeShellExchange(ctx, peer, q, session.ExpiresAt, 1, func(conn *mydcp.Session, body []byte) (Envelope, error) {
		return Envelope{Body: body, Session: &session, Signature: ed25519.Sign(c.Self.Private, access.RequestBytes(session, conn.PeerChallenge(), body))}, nil
	})
	if err != nil {
		return nil, control.NodeShellSession{}, err
	}
	if reply.Session.User != session.User {
		_ = channel.Close()
		return nil, control.NodeShellSession{}, mydcp.ErrFrame
	}
	return channel, *reply.Session, nil
}
func (s Service) forwardNodeShell(ctx context.Context, conn *mydcp.Session, stream mydcp.Stream, frame mydcp.Frame, digest [32]byte, envelope Envelope, binding userBinding, q NodeShellRequest, owner [32]byte) error {
	peer, ok := s.Mesh.Peer(mydcp.Identity(owner))
	if !ok || !peer.Member || peer.Key == mydcp.Identity(s.Self.Public) {
		return nodeShellResponse(stream, frame, digest, NodeShellReply{Code: "node-unreachable"})
	}
	c := Client{Mesh: s.Mesh, Self: s.Self, Cluster: s.Policy.Cluster}
	remote, reply, err := c.nodeShellExchange(ctx, peer, q, envelope.Session.ExpiresAt, 3, func(conn *mydcp.Session, body []byte) (Envelope, error) {
		if !bytes.Equal(body, envelope.Body) {
			return Envelope{}, mydcp.ErrFrame
		}
		copy := envelope
		copy.Relay = &Relay{Node: s.Self.Public, Target: [32]byte(peer.Key), Caller: binding.key, Challenge: binding.challenge, Connection: conn.PeerChallenge()}
		copy.Relay.Signature = ed25519.Sign(s.Self.Private, RelayBytes(s.Policy.Cluster, copy))
		return copy, nil
	})
	if err != nil {
		code := "unavailable"
		var e *Error
		if errors.As(err, &e) && e.Phase == mydcp.Completed {
			code = e.Code
		}
		return nodeShellResponse(stream, frame, digest, NodeShellReply{Code: code})
	}
	defer remote.Close()
	if err = nodeShellResponse(stream, frame, digest, reply); err != nil {
		return err
	}
	local, err := newNodeShellChannel(ctx, conn, stream, frame.Request, sha256.Sum256(envelope.Body), envelope.Session.ExpiresAt, false)
	if err != nil {
		return err
	}
	defer local.releaseContext()
	done := make(chan error, 2)
	pump := func(from, to *NodeShellChannel) {
		for {
			r, e := from.Receive()
			if e != nil {
				done <- e
				return
			}
			e = to.Send(r)
			clear(r.Data)
			if e != nil || r.Kind == "end" {
				done <- e
				return
			}
		}
	}
	go pump(local, remote)
	go pump(remote, local)
	first := <-done
	local.StopReceive()
	_ = remote.Close()
	<-done
	return first
}
