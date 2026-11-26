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

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/storage"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
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

func (s Service) streamCheckerSource(ctx context.Context, conn *mydcp.Session, stream mydcp.Stream, frame mydcp.Frame, header [32]byte, envelope Envelope, request Request, binding userBinding) error {
	denied := func(code string) error { return s.respond(stream, frame, header, Reply{Schema: 1, Code: code}) }
	module := request.Method == "checker-module-stage" || request.Method == "checker-module-recover"
	if frame.Kind != 1 || envelope.Relay != nil || envelope.Session == nil || envelope.Session.Key != binding.key || access.VerifyRequest(*envelope.Session, binding.challenge, envelope.Body, envelope.Signature) != nil || request.Operation != nil || request.Enrollment != nil || request.Username != "" || request.UserKey != ([32]byte{}) || request.Ticket != nil || request.Proof != nil || request.After != "" || request.Node != "" || request.CheckerUpload == nil || request.CheckerSource == nil || request.CheckerSource.Validate() != nil || request.Tenant != request.CheckerSource.Tenant || (request.CheckerModule != nil) != module || module && !moduleInput(*request.CheckerSource, *request.CheckerModule) {
		return denied("denied")
	}
	d := request.CheckerSource.Clone()
	recover := request.Method == "checker-source-recover" || request.Method == "checker-module-recover"
	if s.CheckerSources == nil {
		return denied("unavailable")
	}
	if err := s.CheckerSources.Permit(ctx, *envelope.Session, d, recover); err != nil {
		return denied("denied")
	}
	upload := *request.CheckerUpload
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
			length, digest, limit = request.CheckerModule.Length, request.CheckerModule.Digest, checker.MaxModuleBytes
		}
		data, err = readUserInput(conn, stream, frame.Request, header, int(length), digest, limit)
		if err != nil {
			return err
		}
		defer clear(data)
	}
	reply := Reply{Schema: 1, Code: "ok", Tenant: d.Tenant}
	if module {
		pin := *request.CheckerModule
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
		reply.CheckerModule = &fact
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
		reply.CheckerSource = &fact
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
	case errors.Is(err, access.ErrDenied), errors.Is(err, mydcp.ErrAdmission):
		return "denied"
	case errors.Is(err, checker.ErrReference), errors.Is(err, checker.ErrSourceStore), errors.Is(err, checker.ErrSource):
		return "invalid"
	default:
		return "unavailable"
	}
}

func (c Client) sourceReply(target mydcp.Peer, d checker.SourceDescriptor, reply Reply) (checker.SourceFact, error) {
	f := reply.CheckerSource
	if reply.Code != "ok" || reply.CheckerModule != nil || reply.Tenant != d.Tenant || reply.Node != hex.EncodeToString(target.Key[:]) || f == nil || f.Verify() != nil || f.Owner != [32]byte(target.Key) || f.Cluster != c.Cluster || f.Tenant != d.Tenant || f.ContentDigest() != d.ContentDigest() || c.checkerUpload == nil || f.Upload == nil || *f.Upload != *c.checkerUpload {
		return checker.SourceFact{}, mydcp.ErrAdmission
	}
	return f.Clone(), nil
}

// StageCheckerSource does not redirect or auto-resubmit. A transport failure
// after sending preserves this descriptor; RecoverCheckerSource sends no bytes.
func (c Client) StageCheckerSource(ctx context.Context, target mydcp.Peer, session access.Session, d checker.SourceDescriptor, data []byte) (checker.SourceFact, error) {
	if c.Verify(session) != nil || d.Validate() != nil || uint64(len(data)) != d.Length || sha256.Sum256(data) != d.Digest {
		return checker.SourceFact{}, mydcp.ErrAdmission
	}
	d = d.Clone()
	reply, err := c.stageCheckerArtifact(ctx, target, session, Request{CheckerUpload: c.checkerUpload, Method: "checker-source-stage", Tenant: d.Tenant, CheckerSource: &d}, data)
	if err != nil {
		return checker.SourceFact{}, err
	}
	return c.sourceReply(target, d, reply)
}

// stageCheckerArtifact shares the original bounded source upload framing and
// request lifetime with module ZIPs. It never redirects or retries an upload.
func (c Client) stageCheckerArtifact(ctx context.Context, target mydcp.Peer, session access.Session, request Request, data []byte) (Reply, error) {
	if c.Verify(session) != nil || c.Mesh == nil || c.Self == nil || c.Self.Public != [32]byte(c.Mesh.LocalKey()) {
		return Reply{}, mydcp.ErrAdmission
	}
	return c.stageCheckerExchange(ctx, target, data, 1, func(conn *mydcp.Session) (Envelope, error) {
		body, err := requestBody(request)
		if err != nil {
			return Envelope{}, err
		}
		return Envelope{Body: body, Session: &session, Signature: ed25519.Sign(c.Self.Private, access.RequestBytes(session, conn.PeerChallenge(), body))}, nil
	})
}
func (c Client) stageCheckerExchange(ctx context.Context, target mydcp.Peer, data []byte, kind uint8, makeEnvelope func(*mydcp.Session) (Envelope, error)) (Reply, error) {
	if c.Mesh == nil || c.Self == nil || c.Self.Public != [32]byte(c.Mesh.LocalKey()) {
		return Reply{}, mydcp.ErrAdmission
	}
	data = bytes.Clone(data)
	defer clear(data)
	conn, err := c.Mesh.Dial(ctx, target)
	if err != nil {
		return Reply{}, &Error{Code: "transport", Phase: mydcp.NotSent, Cause: err}
	}
	envelope, err := makeEnvelope(conn)
	if err != nil {
		return Reply{}, err
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		return Reply{}, err
	}
	header := sha256.Sum256(raw)
	stream, err := conn.OpenManagement(ctx)
	if err != nil {
		return Reply{}, &Error{Code: "transport", Phase: mydcp.NotSent, Cause: err}
	}
	defer stream.CancelRead(0)
	defer stream.Close()
	stop := context.AfterFunc(ctx, func() { stream.CancelRead(1); stream.CancelWrite(1) })
	defer stop()
	id := c.Mesh.NextRequest()
	requestID := strconv.FormatUint(id, 10)
	lifetime, _ := mydcp.NewRequest(requestID, header)
	lifetime, _ = lifetime.BeginSend()
	var prepared Reply
	unknown := func(err error) (Reply, error) {
		return prepared, &Error{Code: "transport", Phase: lifetime.Abandon().Phase(), Cause: err}
	}
	if err = mydcp.WriteFrame(stream, mydcp.Frame{Purpose: mydcp.User, Kind: kind, Request: id, Fields: []mydcp.Field{{Tag: 1, Required: true, Value: raw}, {Tag: 2, Required: true, Value: header[:]}}}); err != nil {
		return unknown(err)
	}
	read := func() (Reply, error) {
		f, err := mydcp.ReadFrame(stream, 128<<10)
		var reply Reply
		if err != nil {
			return reply, err
		}
		if f.Purpose != mydcp.User || f.Kind != 2 || f.Request != id || conn.Admit(f, mydcp.User, false) != nil || !bytes.Equal(f.Fields[1].Value, header[:]) || strict(f.Fields[0].Value, &reply) != nil || reply.Schema != 1 {
			return reply, mydcp.ErrFrame
		}
		return reply, nil
	}
	ready, err := read()
	if err != nil {
		return unknown(err)
	}
	if ready.LifecycleStage != nil {
		prepared = Reply{Schema: 1, LifecycleStage: ready.LifecycleStage}
	}
	if ready.Code != "continue" {
		// A Unix request is bidirectional: even an initial rejection needs
		// our send EOF before the server can close its response. Waiting for
		// the peer EOF first deadlocks both halves until the request expires.
		if err := stream.Close(); err != nil {
			return unknown(err)
		}
		if streamEOF(stream) != nil {
			return unknown(mydcp.ErrFrame)
		}
		if ready.Code == "unknown" || ready.Code == "unavailable" {
			return prepared, &Error{Code: ready.Code, Phase: lifetime.Abandon().Phase()}
		}
		lifetime, _ = lifetime.Reply(requestID, header)
		return prepared, &Error{Code: ready.Code, Phase: lifetime.Phase()}
	}
	if ready.Node != hex.EncodeToString(target.Key[:]) || (ready.CheckerSource != nil || ready.CheckerModule != nil) {
		return unknown(mydcp.ErrFrame)
	}
	if err = writeUserInput(stream, id, header, data); err != nil {
		return unknown(err)
	}
	if err = stream.Close(); err != nil {
		return unknown(err)
	}
	reply, err := read()
	if err != nil || streamEOF(stream) != nil {
		return unknown(errors.Join(mydcp.ErrFrame, err))
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

func (c Client) RecoverCheckerSource(ctx context.Context, target mydcp.Peer, session access.Session, d checker.SourceDescriptor) (checker.SourceFact, error) {
	if c.Verify(session) != nil || d.Validate() != nil {
		return checker.SourceFact{}, mydcp.ErrAdmission
	}
	d = d.Clone()
	body, err := requestBody(Request{CheckerUpload: c.checkerUpload, Method: "checker-source-recover", Tenant: d.Tenant, CheckerSource: &d})
	if err != nil {
		return checker.SourceFact{}, err
	}
	reply, _, err := c.exchange(ctx, target, func(conn *mydcp.Session) (Envelope, error) {
		return Envelope{Body: body, Session: &session, Signature: ed25519.Sign(c.Self.Private, access.RequestBytes(session, conn.PeerChallenge(), body))}, nil
	}, false)
	if err != nil {
		return checker.SourceFact{}, err
	}
	return c.sourceReply(target, d, reply)
}
