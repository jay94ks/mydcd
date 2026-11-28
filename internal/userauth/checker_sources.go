// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/storage"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
)

// SourceArtifacts is the node store boundary. Permit is checked before bounded
// input allocation; every transfer is bound to the client's original upload ID
// and rechecks authority before storage.
type SourceArtifacts interface {
	Permit(context.Context, access.Session, checker.SourceDescriptor, bool) error
	BeginPublication(context.Context, access.Session, checker.SourceDescriptor, [32]byte, bool) (func(), error)
	StagePublication(context.Context, access.Session, checker.SourceDescriptor, [32]byte, []byte) (checker.SourceFact, error)
	RecoverPublication(context.Context, access.Session, checker.SourceDescriptor, [32]byte) (checker.SourceFact, error)
	StagePublicationModule(context.Context, access.Session, checker.SourceDescriptor, [32]byte, checker.ModuleArchive) (checker.ModuleFact, error)
	RecoverPublicationModule(context.Context, access.Session, checker.SourceDescriptor, [32]byte, checker.ModulePin) (checker.ModuleFact, error)
	ValidatePublication(context.Context, access.Session, checker.SourceDescriptor, [32]byte, []byte) (*checker.SourceFact, []checker.SourceDiagnostic, error)
}

// WithCheckerUpload scopes only source/module transfers to the immutable CLI
// intent signature. It neither changes the login nor creates a new operation.
func (c Client) WithCheckerUpload(i CheckerScriptIntent) Client {
	id := checkerUploadID(i)
	c.checkerUpload = &id
	return c
}

func (s Service) streamCheckerSource(ctx context.Context, conn *sfcp.Session, stream sfcp.Stream, frame sfcp.Frame, header [32]byte, envelope Envelope, request Request, binding userBinding) error {
	denied := func(code string) error { return s.respond(stream, frame, header, Reply{Schema: 1, Code: code}) }
	q, ok := request.checkerStage()
	if frame.Kind != 1 || envelope.Relay != nil || envelope.Session == nil || envelope.Session.Key != binding.key || access.VerifyRequest(*envelope.Session, binding.challenge, envelope.Body, envelope.Signature) != nil || !ok || !request.checkerArtifactRequest() {
		return denied("denied")
	}
	module := moduleMethod(request.Method)
	d := q.Source.Clone()
	recover := recoverMethod(request.Method)
	if s.CheckerSources == nil {
		return denied("unavailable")
	}
	if err := s.CheckerSources.Permit(ctx, *envelope.Session, d, recover); err != nil {
		return denied("denied")
	}
	upload := q.Upload
	done, err := s.CheckerSources.BeginPublication(ctx, *envelope.Session, d, upload, recover)
	if err != nil {
		return denied(checkerArtifactFailure(err))
	}
	defer done()
	var data []byte
	if recover {
		if err := streamEOF(stream); err != nil {
			return err
		}
	} else {
		if err := denied("continue"); err != nil {
			return err
		}
		length, digest, limit := d.Length, d.Digest, checker.MaxScriptBytes
		if module {
			length, digest, limit = q.Module.Length, q.Module.Digest, checker.MaxModuleBytes
		}
		data, err = readUserInput(conn, stream, frame.Request, header, int(length), digest, limit)
		if err != nil {
			return err
		}
		defer clear(data)
	}
	var reply Reply
	if module {
		pin := *q.Module
		var fact checker.ModuleFact
		if recover {
			fact, err = s.CheckerSources.RecoverPublicationModule(ctx, *envelope.Session, d, upload, pin)
		} else {
			fact, err = s.CheckerSources.StagePublicationModule(ctx, *envelope.Session, d, upload, checker.ModuleArchive{Pin: pin, ZIP: data})
		}
		if err != nil {
			return denied(checkerArtifactFailure(err))
		}
		if fact.Verify() != nil || fact.Cluster != s.Policy.Cluster || fact.Owner != s.Self.Public || fact.Tenant != d.Tenant || fact.Module != pin {
			return denied("invalid")
		}
		reply = dataReply("ok", fact)
	} else {
		var fact checker.SourceFact
		if recover {
			fact, err = s.CheckerSources.RecoverPublication(ctx, *envelope.Session, d, upload)
		} else {
			fact, err = s.CheckerSources.StagePublication(ctx, *envelope.Session, d, upload, data)
		}
		if err != nil {
			return denied(checkerArtifactFailure(err))
		}
		if fact.Verify() != nil || fact.Cluster != s.Policy.Cluster || fact.Owner != s.Self.Public || fact.Tenant != d.Tenant || fact.ContentDigest() != d.ContentDigest() {
			return denied("invalid")
		}
		reply = dataReply("ok", fact)
	}
	return s.respond(stream, frame, header, reply)
}

func checkerArtifactFailure(err error) string {
	switch {
	case errors.Is(err, checker.ErrSourceUncertain):
		return "unknown"
	case errors.Is(err, control.ErrLifecycleSourceMissing):
		return "missing"
	case errors.Is(err, storage.ErrMissing) && !errors.Is(err, checker.ErrSourceStore):
		return "missing"
	case errors.Is(err, access.ErrDenied), errors.Is(err, sfcp.ErrAdmission):
		return "denied"
	case errors.Is(err, checker.ErrReference), errors.Is(err, checker.ErrSourceStore), errors.Is(err, checker.ErrSource):
		return "invalid"
	default:
		return "unavailable"
	}
}

func (c Client) sourceReply(target sfcp.Peer, d checker.SourceDescriptor, reply Reply) (checker.SourceFact, error) {
	var fact checker.SourceFact
	f := &fact
	if reply.Code != "ok" || len(reply.Data) == 0 || strict(reply.Data, f) != nil || reply.Node != hex.EncodeToString(target.Key[:]) || f.Verify() != nil || f.Owner != [32]byte(target.Key) || f.Cluster != c.Cluster || f.Tenant != d.Tenant || f.ContentDigest() != d.ContentDigest() || c.checkerUpload == nil || f.Upload == nil || *f.Upload != *c.checkerUpload {
		return checker.SourceFact{}, sfcp.ErrAdmission
	}
	return f.Clone(), nil
}

// checkerRequest is a checker-* request for d under this client's upload ID.
func (c Client) checkerRequest(method string, d checker.SourceDescriptor, pin *checker.ModulePin) (Request, error) {
	if c.checkerUpload == nil {
		return Request{}, sfcp.ErrAdmission
	}
	q := CheckerStageQuery{Tenant: d.Tenant, Source: d.Clone(), Module: pin, Upload: *c.checkerUpload}
	if !q.validFor(method) {
		return Request{}, sfcp.ErrAdmission
	}
	return stageRequest(method, q)
}

// StageCheckerSource does not redirect or auto-resubmit. A transport failure
// after sending preserves this descriptor; RecoverCheckerSource sends no bytes.
func (c Client) StageCheckerSource(ctx context.Context, target sfcp.Peer, session access.Session, d checker.SourceDescriptor, data []byte) (checker.SourceFact, error) {
	if c.Verify(session) != nil || d.Validate() != nil || uint64(len(data)) != d.Length || sha256.Sum256(data) != d.Digest {
		return checker.SourceFact{}, sfcp.ErrAdmission
	}
	request, err := c.checkerRequest(CheckerSourceStageMethod.Name, d, nil)
	if err != nil {
		return checker.SourceFact{}, err
	}
	reply, err := c.stageCheckerArtifact(ctx, target, session, request, data)
	if err != nil {
		return checker.SourceFact{}, err
	}
	return c.sourceReply(target, d, reply)
}

// stageCheckerArtifact shares the original bounded source upload framing and
// request lifetime with module ZIPs. It never redirects or retries an upload.
func (c Client) stageCheckerArtifact(ctx context.Context, target sfcp.Peer, session access.Session, request Request, data []byte) (Reply, error) {
	if c.Verify(session) != nil || c.Mesh == nil || c.Self == nil || c.Self.Public != [32]byte(c.Mesh.LocalKey()) {
		return Reply{}, sfcp.ErrAdmission
	}
	return c.stageCheckerExchange(ctx, target, data, 1, func(conn *sfcp.Session) (Envelope, error) {
		body, err := requestBody(request)
		if err != nil {
			return Envelope{}, err
		}
		return Envelope{Body: body, Session: &session, Signature: ed25519.Sign(c.Self.Private, access.RequestBytes(session, conn.PeerChallenge(), body))}, nil
	})
}
func (c Client) stageCheckerExchange(ctx context.Context, target sfcp.Peer, data []byte, kind uint8, makeEnvelope func(*sfcp.Session) (Envelope, error)) (Reply, error) {
	if c.Mesh == nil || c.Self == nil || c.Self.Public != [32]byte(c.Mesh.LocalKey()) {
		return Reply{}, sfcp.ErrAdmission
	}
	data = bytes.Clone(data)
	defer clear(data)
	conn, stream, err := c.openUser(ctx, target)
	if err != nil {
		return Reply{}, err
	}
	defer stream.CancelRead(0)
	defer stream.Close()
	envelope, err := makeEnvelope(conn)
	if err != nil {
		return Reply{}, err
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		return Reply{}, err
	}
	header := sha256.Sum256(raw)
	stop := context.AfterFunc(ctx, func() { stream.CancelRead(1); stream.CancelWrite(1) })
	defer stop()
	id := c.Mesh.NextRequest()
	requestID := strconv.FormatUint(id, 10)
	lifetime, _ := sfcp.NewRequest(requestID, header)
	lifetime, _ = lifetime.BeginSend()
	var prepared Reply
	unknown := func(err error) (Reply, error) {
		return prepared, &Error{Code: "transport", Phase: lifetime.Abandon().Phase(), Cause: err}
	}
	if err = sfcp.WriteFrame(stream, sfcp.Frame{Purpose: sfcp.User, Kind: kind, Request: id, Fields: []sfcp.Field{{Tag: 1, Required: true, Value: raw}, {Tag: 2, Required: true, Value: header[:]}}}); err != nil {
		return unknown(err)
	}
	read := func() (Reply, error) {
		f, err := sfcp.ReadFrame(stream, 128<<10)
		var reply Reply
		if err != nil {
			return reply, err
		}
		if f.Purpose != sfcp.User || f.Kind != 2 || f.Request != id || conn.Admit(f, sfcp.User, false) != nil || !bytes.Equal(f.Fields[1].Value, header[:]) || lenient(f.Fields[0].Value, &reply) != nil || reply.Schema != 1 {
			return reply, sfcp.ErrFrame
		}
		return reply, nil
	}
	ready, err := read()
	if err != nil {
		return unknown(err)
	}
	if len(ready.Data) != 0 {
		prepared = Reply{Schema: 1, Data: ready.Data}
	}
	if ready.Code != "continue" {
		// A Unix request is bidirectional: even an initial rejection needs
		// our send EOF before the server can close its response. Waiting for
		// the peer EOF first deadlocks both halves until the request expires.
		if err := stream.Close(); err != nil {
			return unknown(err)
		}
		if streamEOF(stream) != nil {
			return unknown(sfcp.ErrFrame)
		}
		if ready.Code == "unknown" || ready.Code == "unavailable" {
			return prepared, &Error{Code: ready.Code, Phase: lifetime.Abandon().Phase()}
		}
		lifetime, _ = lifetime.Reply(requestID, header)
		return prepared, &Error{Code: ready.Code, Phase: lifetime.Phase()}
	}
	if ready.Node != hex.EncodeToString(target.Key[:]) {
		return unknown(sfcp.ErrFrame)
	}
	if err = writeUserInput(stream, id, header, data); err != nil {
		return unknown(err)
	}
	if err = stream.Close(); err != nil {
		return unknown(err)
	}
	reply, err := read()
	if err != nil || streamEOF(stream) != nil {
		return unknown(errors.Join(sfcp.ErrFrame, err))
	}
	if reply.Code != "ok" {
		phase := lifetime.Abandon().Phase()
		if reply.Code == "unknown" || reply.Code == "unavailable" {
			return prepared, &Error{Code: reply.Code, Phase: phase}
		}
		lifetime, _ = lifetime.Reply(requestID, header)
		return prepared, &Error{Code: reply.Code, Phase: lifetime.Phase()}
	}
	lifetime, _ = lifetime.Reply(requestID, header)
	return reply, nil
}

func (c Client) RecoverCheckerSource(ctx context.Context, target sfcp.Peer, session access.Session, d checker.SourceDescriptor) (checker.SourceFact, error) {
	if c.Verify(session) != nil || d.Validate() != nil {
		return checker.SourceFact{}, sfcp.ErrAdmission
	}
	request, err := c.checkerRequest(CheckerSourceRecoverMethod.Name, d, nil)
	if err != nil {
		return checker.SourceFact{}, err
	}
	body, err := requestBody(request)
	if err != nil {
		return checker.SourceFact{}, err
	}
	reply, _, err := c.exchange(ctx, target, func(conn *sfcp.Session) (Envelope, error) {
		return Envelope{Body: body, Session: &session, Signature: ed25519.Sign(c.Self.Private, access.RequestBytes(session, conn.PeerChallenge(), body))}, nil
	}, false)
	if err != nil {
		return checker.SourceFact{}, err
	}
	return c.sourceReply(target, d, reply)
}
