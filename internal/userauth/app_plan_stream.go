// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"io"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/sfcp"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
)

// AppPlanInput describes read-only bytes on this one authenticated stream.
// It is not an upload ID, a durable candidate, or a deployment operation.
type AppPlanInput struct {
	Length int
	Digest [32]byte
}

func (m AppPlanInput) valid() bool {
	return m.validSources(false)
}

func (m AppPlanInput) validSources(envelope bool) bool {
	limit := deployment.ArtifactMaxBytes
	if envelope {
		limit = appSourceInputMaxBytes
	}
	return m.Length > 0 && m.Length <= limit && m.Digest != ([32]byte{})
}

// StreamAppPlan transfers a complete input and one frozen result. No candidate
// is published until all ordered frames, the digest, and stream EOF validate.
func (c Client) StreamAppPlan(ctx context.Context, target sfcp.Peer, session access.Session, tenant string, q control.AppPlanRequest) ([]byte, error) {
	if c.Verify(session) != nil || q.SourceEnvelope || q.Part != 0 || len(q.Document) == 0 || len(q.Document) > deployment.ArtifactMaxBytes {
		return nil, sfcp.ErrAdmission
	}
	document := q.Document
	if len(q.CheckerSources) != 0 {
		if q.PrepareSources || q.Move != nil {
			return nil, sfcp.ErrAdmission
		}
		var err error
		document, err = encodeAppSourceInput(document, q.CheckerSources, c.Cluster, tenant)
		if err != nil {
			return nil, err
		}
		defer clear(document)
		q.CheckerSources, q.SourceEnvelope = nil, true
	}
	q.Document = nil
	body, err := requestBody(Request{Method: "app-plan-stream", Tenant: tenant, AppPlan: &q, AppInput: &AppPlanInput{len(document), sha256.Sum256(document)}})
	if err != nil {
		return nil, err
	}
	raw, _, err := c.planExchange(ctx, target, document, 1, func(conn *sfcp.Session) (Envelope, error) {
		return Envelope{Body: body, Session: &session, Signature: ed25519.Sign(c.Self.Private, access.RequestBytes(session, conn.PeerChallenge(), body))}, nil
	})
	return raw, err
}

func (c Client) planExchange(ctx context.Context, target sfcp.Peer, document []byte, kind uint8, makeEnvelope func(*sfcp.Session) (Envelope, error)) ([]byte, Reply, error) {
	if c.Mesh == nil || c.Self == nil || c.Self.Public != [32]byte(c.Mesh.LocalKey()) {
		return nil, Reply{}, sfcp.ErrAdmission
	}
	conn, err := c.Mesh.Dial(ctx, target)
	if err != nil {
		return nil, Reply{}, err
	}
	envelope, err := makeEnvelope(conn)
	if err != nil {
		return nil, Reply{}, err
	}
	header, err := json.Marshal(envelope)
	if err != nil {
		return nil, Reply{}, err
	}
	digest := sha256.Sum256(header)
	stream, err := conn.OpenManagement(ctx)
	if err != nil {
		return nil, Reply{}, err
	}
	defer stream.CancelRead(0)
	defer stream.Close()
	stop := context.AfterFunc(ctx, func() { stream.CancelRead(1); stream.CancelWrite(1) })
	defer stop()
	id := c.Mesh.NextRequest()
	frame := sfcp.Frame{Purpose: sfcp.User, Kind: kind, Request: id, Fields: []sfcp.Field{{Tag: 1, Required: true, Value: header}, {Tag: 2, Required: true, Value: digest[:]}}}
	if err = sfcp.WriteFrame(stream, frame); err != nil {
		return nil, Reply{}, err
	}
	readReply := func() (Reply, error) {
		f, err := sfcp.ReadFrame(stream, 128<<10)
		var reply Reply
		if err != nil {
			return reply, err
		}
		if f.Purpose != sfcp.User || f.Kind != 2 || f.Request != id || conn.Admit(f, sfcp.User, false) != nil || !bytes.Equal(f.Fields[1].Value, digest[:]) || strict(f.Fields[0].Value, &reply) != nil || reply.Schema != 1 {
			return reply, sfcp.ErrFrame
		}
		return reply, nil
	}
	ready, err := readReply()
	if err != nil {
		return nil, ready, err
	}
	if ready.Code != "continue" {
		return nil, ready, &Error{Code: ready.Code, Phase: sfcp.Completed}
	}
	if ready.AppPlan != nil {
		return nil, ready, sfcp.ErrFrame
	}
	if err = writeUserInput(stream, id, digest, document); err != nil {
		return nil, ready, err
	}
	if err = stream.Close(); err != nil {
		return nil, ready, err
	}
	var artifact []byte
	var first Reply
	var expected [32]byte
	length := 0
	for index := 0; ; index++ {
		reply, err := readReply()
		if err != nil {
			return nil, reply, err
		}
		if reply.Code != "ok" {
			return nil, reply, &Error{Code: reply.Code, Phase: sfcp.Completed, Cause: appPlanInputCause(reply)}
		}
		part := reply.AppPlan
		if part == nil || part.Part != index || part.Length < 1 || part.Length > deployment.ArtifactMaxBytes || part.Digest == ([32]byte{}) || len(part.Data) != min(deployment.ArtifactPartBytes, part.Length-len(artifact)) {
			return nil, reply, sfcp.ErrFrame
		}
		if index == 0 {
			first, length, expected = reply, part.Length, part.Digest
		} else if part.Length != length || part.Digest != expected || reply.Node != first.Node || reply.RelayedBy != first.RelayedBy {
			return nil, reply, sfcp.ErrFrame
		}
		artifact = append(artifact, part.Data...)
		if len(artifact) == length {
			break
		}
	}
	if sha256.Sum256(artifact) != expected || streamEOF(stream) != nil {
		return nil, first, sfcp.ErrFrame
	}
	return artifact, first, nil
}

func writeUserInput(w io.Writer, id uint64, header [32]byte, document []byte) error {
	for offset := 0; offset < len(document); offset += deployment.ArtifactPartBytes {
		var encoded [8]byte
		binary.LittleEndian.PutUint64(encoded[:], uint64(offset))
		frame := sfcp.Frame{Purpose: sfcp.User, Kind: 4, Request: id, Fields: []sfcp.Field{{Tag: 1, Required: true, Value: encoded[:]}, {Tag: 2, Required: true, Value: document[offset:min(len(document), offset+deployment.ArtifactPartBytes)]}, {Tag: 3, Required: true, Value: header[:]}}}
		if err := sfcp.WriteFrame(w, frame); err != nil {
			return err
		}
	}
	return nil
}

func streamEOF(r io.Reader) error {
	var extra [1]byte
	n, err := r.Read(extra[:])
	if n != 0 || err != io.EOF {
		return sfcp.ErrFrame
	}
	return nil
}

func readUserInput(conn *sfcp.Session, stream sfcp.Stream, id uint64, header [32]byte, length int, expected [32]byte, limit int) ([]byte, error) {
	// Each authenticated consumer supplies its own smaller bound: app 4 MiB,
	// root source 256 KiB, module ZIP 64 MiB. Do not impose the app limit on
	// another consumer or enlarge the app's admission because it shares frames.
	if length < 1 || length > limit || limit < 1 || limit > max(deployment.ArtifactMaxBytes, checker.MaxModuleBytes) || expected == ([32]byte{}) {
		return nil, sfcp.ErrBudget
	}
	document := make([]byte, length)
	for offset := 0; offset < len(document); offset += deployment.ArtifactPartBytes {
		f, err := sfcp.ReadFrame(stream, deployment.ArtifactPartBytes+64)
		if err != nil {
			return nil, err
		}
		if f.Purpose != sfcp.User || f.Kind != 4 || f.Request != id || conn.Admit(f, sfcp.User, false) != nil || binary.LittleEndian.Uint64(f.Fields[0].Value) != uint64(offset) || !bytes.Equal(f.Fields[2].Value, header[:]) || len(f.Fields[1].Value) != min(deployment.ArtifactPartBytes, len(document)-offset) {
			return nil, sfcp.ErrFrame
		}
		copy(document[offset:], f.Fields[1].Value)
	}
	if sha256.Sum256(document) != expected || streamEOF(stream) != nil {
		return nil, sfcp.ErrFrame
	}
	return document, nil
}

func (s Service) planStreamView(ctx context.Context, binding userBinding, request Request, envelope Envelope, latest bool) (Service, cluster.View, Reply) {
	view, err := s.Engine.Read(ctx, latest)
	if err == nil {
		s.Policy, err = s.Policy.Current(view.State)
	}
	if err != nil {
		return s, view, Reply{Schema: 1, Code: "unavailable"}
	}
	c, err := s.Policy.Catalog(view.State)
	if err != nil || request.Operation != nil || request.Enrollment != nil {
		return s, view, Reply{Schema: 1, Code: "denied"}
	}
	if !s.nodeRequestAllowed(view.State, c, request, envelope) {
		return s, view, Reply{Schema: 1, Code: "denied"}
	}
	if envelope.Relay != nil {
		members, err := s.Policy.Members(view.State)
		if err != nil || !members.MemberKey(envelope.Relay.Node) {
			return s, view, Reply{Schema: 1, Code: "denied"}
		}
	}
	return s, view, s.execute(c, binding, request, envelope)
}

func (s Service) streamAppPlan(ctx context.Context, conn *sfcp.Session, stream sfcp.Stream, frame sfcp.Frame, digest [32]byte, envelope Envelope, request Request, binding userBinding) error {
	if envelope.Session == nil || !request.AppInput.validSources(request.AppPlan.SourceEnvelope) || request.AppPlan.Document != nil || request.AppPlan.Part != 0 || request.AppPlan.SourceEnvelope && (len(request.AppPlan.CheckerSources) != 0 || request.AppPlan.PrepareSources || request.AppPlan.Move != nil) {
		return s.respond(stream, frame, digest, Reply{Schema: 1, Code: "invalid"})
	}
	current, _, admission := s.planStreamView(ctx, binding, request, envelope, s.Engine.IsLeader())
	if admission.Code != "ok" {
		return s.respond(stream, frame, digest, admission)
	}
	if frame.Kind == 3 && !s.Engine.IsLeader() {
		return s.respond(stream, frame, digest, Reply{Schema: 1, Code: "not-leader"})
	}
	if err := s.respond(stream, frame, digest, Reply{Schema: 1, Code: "continue"}); err != nil {
		return err
	}
	limit := deployment.ArtifactMaxBytes
	if request.AppPlan.SourceEnvelope {
		limit = appSourceInputMaxBytes
	}
	document, err := readUserInput(conn, stream, frame.Request, digest, request.AppInput.Length, request.AppInput.Digest, limit)
	if err != nil {
		return err
	}
	defer clear(document)
	var artifact []byte
	var reply Reply
	if !s.Engine.IsLeader() {
		if frame.Kind != 1 {
			return s.respond(stream, frame, digest, Reply{Schema: 1, Code: "not-leader"})
		}
		artifact, reply, err = current.forwardAppPlan(ctx, envelope, binding, document)
	} else {
		current, view, allowed := s.planStreamView(ctx, binding, request, envelope, true)
		if allowed.Code != "ok" {
			return s.respond(stream, frame, digest, allowed)
		}
		if request.AppPlan.SourceEnvelope {
			decoded, facts, err := decodeAppSourceInput(document, current.Policy.Cluster, request.Tenant)
			if err != nil {
				return s.respond(stream, frame, digest, Reply{Schema: 1, Code: "invalid"})
			}
			defer clear(decoded)
			request.AppPlan.Document, request.AppPlan.CheckerSources, request.AppPlan.SourceEnvelope = decoded, facts, false
		} else {
			request.AppPlan.Document = document
		}
		artifact, err = current.appPlanArtifact(ctx, view, *envelope.Session, request.Tenant, *request.AppPlan)
		reply = Reply{Schema: 1, Code: "ok"}
	}
	if err != nil {
		if reply.Code == "ok" || reply.Code == "" {
			reply = appPlanErrorReply(err)
		}
		return s.respond(stream, frame, digest, reply)
	}
	if len(artifact) == 0 || len(artifact) > deployment.ArtifactMaxBytes {
		return sfcp.ErrBudget
	}
	planDigest := sha256.Sum256(artifact)
	for index, offset := 0, 0; offset < len(artifact); index, offset = index+1, offset+deployment.ArtifactPartBytes {
		reply.AppPlan = &control.AppPlanPart{Digest: planDigest, Length: len(artifact), Part: index, Data: artifact[offset:min(len(artifact), offset+deployment.ArtifactPartBytes)]}
		if err := s.respond(stream, frame, digest, reply); err != nil {
			return err
		}
	}
	return nil
}

func (s Service) forwardAppPlan(ctx context.Context, envelope Envelope, binding userBinding, document []byte) ([]byte, Reply, error) {
	peer, ok := s.Engine.LeaderPeer()
	if !ok || [32]byte(peer.Key) == s.Self.Public {
		return nil, Reply{Schema: 1, Code: "unavailable"}, sfcp.ErrAdmission
	}
	c := Client{Mesh: s.Mesh, Self: s.Self, Cluster: s.Policy.Cluster}
	artifact, reply, err := c.planExchange(ctx, peer, document, 3, func(conn *sfcp.Session) (Envelope, error) {
		copy := envelope
		copy.Relay = &Relay{Node: s.Self.Public, Target: [32]byte(peer.Key), Caller: binding.key, Challenge: binding.challenge, Connection: conn.PeerChallenge()}
		copy.Relay.Signature = ed25519.Sign(s.Self.Private, RelayBytes(s.Policy.Cluster, copy))
		return copy, nil
	})
	if err != nil && reply.Code == "" {
		reply = Reply{Schema: 1, Code: "unavailable"}
	}
	reply.RelayedBy = s.Self.Actor()
	return artifact, reply, err
}
