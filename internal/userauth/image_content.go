// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/registryclient"
	"github.com/jay94ks/mydcd/internal/schema"
)

const imageContentChunk = 24 << 10
const imageContentWindow = 8 << 20
const imageContentSeconds = 900

type ImageContentRequest struct {
	Schema    uint8
	Tenant    string
	Query     registryclient.ContentQuery
	ExpiresAt int64
	Nonce     [32]byte
}

func (q ImageContentRequest) valid(now int64) bool {
	return q.Schema == 1 && q.Tenant != "" && len(q.Tenant) <= 63 && q.Query.Valid() && q.Nonce != ([32]byte{}) && q.ExpiresAt > now && q.ExpiresAt-now <= imageContentSeconds
}

type ImageContentReply struct {
	Schema uint8
	Code   string
	Info   *registryclient.ContentInfo `json:",omitempty"`
}

func (r ImageContentReply) valid(q registryclient.ContentQuery) bool {
	if r.Schema != 1 {
		return false
	}
	if r.Code == "ready" || r.Code == "ok" {
		return r.Info != nil && r.Info.Valid(q)
	}
	switch r.Code {
	case "denied", "unavailable", "unsupported", "invalid", "target-changed":
		return r.Info == nil
	}
	return false
}

// Body owns the actual native/HTTP reader and original source I/O hold.
// Authorize rechecks the current user, source/run and trust, not a cached role.
type ImageContentSource struct {
	Lifetime  context.Context
	Info      registryclient.ContentInfo
	Body      io.ReadCloser
	Authorize func(context.Context) error
}

func imageContentReply(stream mydcp.Stream, frame mydcp.Frame, header [32]byte, r ImageContentReply) error {
	r.Schema = 1
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return mydcp.WriteFrame(stream, mydcp.Frame{Purpose: mydcp.ImageContent, Kind: 2, Request: frame.Request, Fields: []mydcp.Field{{Tag: 1, Required: true, Value: raw}, {Tag: 2, Required: true, Value: header[:]}}})
}
func contentDeadline(stream mydcp.Stream, ctx context.Context) error {
	deadline := time.Now().Add(60 * time.Second)
	if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
		deadline = end
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return stream.SetDeadline(deadline)
}
func writeImageContent(stream mydcp.Stream, id uint64, header [32]byte, offset uint64, data []byte) error {
	if len(data) == 0 || len(data) > imageContentChunk {
		return mydcp.ErrFrame
	}
	var raw [8]byte
	binary.LittleEndian.PutUint64(raw[:], offset)
	return mydcp.WriteFrame(stream, mydcp.Frame{Purpose: mydcp.ImageContent, Kind: 4, Request: id, Fields: []mydcp.Field{{Tag: 1, Required: true, Value: raw[:]}, {Tag: 2, Required: true, Value: data}, {Tag: 3, Required: true, Value: header[:]}}})
}

func (s Service) handleImageContent(base context.Context, conn *mydcp.Session, stream mydcp.Stream, frame mydcp.Frame) error {
	if frame.Kind == 5 {
		return s.handleImageBuildBaseContent(base, conn, stream, frame)
	}
	if frame.Kind != 1 && frame.Kind != 3 {
		return mydcp.ErrFrame
	}
	header := sha256.Sum256(frame.Fields[0].Value)
	if !bytes.Equal(header[:], frame.Fields[1].Value) {
		return mydcp.ErrFrame
	}
	envelope, err := schema.Decode[Envelope](frame.Fields[0].Value)
	if err != nil {
		return mydcp.ErrFrame
	}
	defer clear(frame.Fields[0].Value)
	defer clear(envelope.Body)
	// Like finite User RPCs, consume the original request EOF even on denial.
	if err = streamEOF(stream); err != nil {
		return err
	}
	respond := func(code string) error {
		return imageContentReply(stream, frame, header, ImageContentReply{Code: code})
	}
	q, err := schema.Decode[ImageContentRequest](envelope.Body)
	if err != nil || !q.valid(time.Now().Unix()) || envelope.Session == nil || q.ExpiresAt > envelope.Session.ExpiresAt {
		return respond("denied")
	}
	binding, err := s.binding(conn, frame.Kind, envelope)
	if err != nil || binding.key != envelope.Session.Key {
		return respond("denied")
	}
	admit, done := context.WithTimeout(base, 5*time.Second)
	defer done()
	view, err := s.Engine.Read(admit, true)
	if err != nil || view.Local || s.Enabled != nil && !s.Enabled(view.State) {
		return respond("unavailable")
	}
	policy, err := s.Policy.Current(view.State)
	if err != nil {
		return respond("unsupported")
	}
	catalog, err := policy.Catalog(view.State)
	if err != nil || !s.nodeRequestAllowed(view.State, catalog, Request{Method: "image-content", Tenant: q.Tenant}, envelope) {
		return respond("denied")
	}
	read, err := policy.PlanImageContent(view.State, *envelope.Session, time.Now().Unix(), q.Tenant, q.Query, s.Self.Public)
	if err != nil || read.Resolve.Target.Code != "" {
		return respond("denied")
	}
	ctx, cancel := context.WithDeadline(base, time.Unix(q.ExpiresAt, 0))
	defer cancel()
	stop := context.AfterFunc(ctx, func() { stream.CancelRead(1); stream.CancelWrite(1) })
	defer stop()
	if err = contentDeadline(stream, ctx); err != nil {
		return err
	}
	if read.Resolve.Target.Owner != s.Self.Public {
		if envelope.Relay != nil {
			return respond("target-changed")
		}
		return s.forwardImageContent(ctx, stream, frame, header, envelope, binding, q, read.Resolve.Target.Owner)
	}
	if s.ImageContent == nil {
		return respond("unsupported")
	}
	source, err := s.ImageContent(ctx, read)
	if source.Body != nil {
		defer source.Body.Close()
	}
	if err != nil || source.Body == nil || source.Authorize == nil || !source.Info.Valid(q.Query) {
		return respond("unavailable")
	}
	if source.Lifetime != nil {
		stopLifetime := context.AfterFunc(source.Lifetime, cancel)
		defer stopLifetime()
	}
	check := source.Authorize
	source.Authorize = func(call context.Context) error {
		if err := check(call); err != nil {
			return err
		}
		return conn.Admit(frame, mydcp.ImageContent, false)
	}
	return sendImageContent(ctx, stream, frame, header, source)
}

// sendImageContent is shared by the actual authenticated handler and transport
// fault fixtures. It owns no alternate selection/authentication algorithm.
func sendImageContent(ctx context.Context, stream mydcp.Stream, frame mydcp.Frame, header [32]byte, source ImageContentSource) error {
	respond := func(code string) error {
		return imageContentReply(stream, frame, header, ImageContentReply{Code: code})
	}
	err := consumeImageContent(ctx, source, func() error {
		return imageContentReply(stream, frame, header, ImageContentReply{Code: "ready", Info: &source.Info})
	}, func(offset int64, data []byte) error {
		if err := contentDeadline(stream, ctx); err != nil {
			return err
		}
		return writeImageContent(stream, frame.Request, header, uint64(offset), data)
	})
	if err != nil {
		var failed *Error
		if errors.As(err, &failed) && failed.Phase == mydcp.Completed {
			return respond(failed.Code)
		}
		return err
	}
	if err := contentDeadline(stream, ctx); err != nil {
		return err
	}
	return imageContentReply(stream, frame, header, ImageContentReply{Code: "ok", Info: &source.Info})
}

// ReadImageContentSource is the local owner path. It uses the same tentative
// bytes, digest/length, current authorization and real body Close as the wire
// sender, without creating a loopback transport or a second verification core.
func ReadImageContentSource(ctx context.Context, query registryclient.ContentQuery, source ImageContentSource, to io.Writer) (info registryclient.ContentInfo, failure error) {
	if source.Body != nil {
		defer func() { failure = errors.Join(failure, source.Body.Close()) }()
	}
	if to == nil || source.Body == nil || source.Authorize == nil || !source.Info.Valid(query) {
		return info, mydcp.ErrAdmission
	}
	if source.Lifetime != nil {
		call, cancel := context.WithCancel(ctx)
		stop := context.AfterFunc(source.Lifetime, cancel)
		defer stop()
		defer cancel()
		ctx = call
	}
	err := consumeImageContent(ctx, source, func() error { return nil }, func(_ int64, data []byte) error {
		n, err := to.Write(data)
		if err == nil && n != len(data) {
			err = io.ErrShortWrite
		}
		return err
	})
	return source.Info, err
}

func consumeImageContent(ctx context.Context, source ImageContentSource, begin func() error, write func(int64, []byte) error) error {
	failed := func(code string) error { return &Error{Code: code, Phase: mydcp.Completed} }
	closeBody := context.AfterFunc(ctx, func() { _ = source.Body.Close() })
	defer closeBody()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := source.Authorize(ctx); err != nil {
		return failed("denied")
	}
	if err := begin(); err != nil {
		return err
	}
	hash := sha256.New()
	buffer := make([]byte, imageContentChunk)
	defer clear(buffer)
	var offset, checked int64
	last := time.Now()
	for offset < source.Info.Bytes {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := io.ReadFull(source.Body, buffer[:min(int64(len(buffer)), source.Info.Bytes-offset)])
		if err != nil {
			return failed("unavailable")
		}
		if offset-checked >= imageContentWindow || time.Since(last) >= time.Second {
			if err = source.Authorize(ctx); err != nil {
				return failed("denied")
			}
			checked, last = offset, time.Now()
		}
		_, _ = hash.Write(buffer[:n])
		if err = write(offset, buffer[:n]); err != nil {
			return err
		}
		offset += int64(n)
	}
	var extra [1]byte
	n, err := source.Body.Read(extra[:])
	if n != 0 || err != io.EOF || "sha256:"+hex.EncodeToString(hash.Sum(nil)) != source.Info.Digest {
		return failed("invalid")
	}
	if err = source.Body.Close(); err != nil {
		return failed("unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err = source.Authorize(ctx); err != nil {
		return failed("denied")
	}
	return nil
}

// ReadImageContent performs one immutable read. Bytes are tentative until this
// returns success; consumers must not publish a cache/file after a partial read.
func (c Client) ReadImageContent(ctx context.Context, peer mydcp.Peer, session access.Session, tenant string, q registryclient.ContentQuery, to io.Writer) (registryclient.ContentInfo, error) {
	if c.Verify(session) != nil || to == nil || !q.Valid() {
		return registryclient.ContentInfo{}, mydcp.ErrAdmission
	}
	request := ImageContentRequest{Schema: 1, Tenant: tenant, Query: q, ExpiresAt: min(time.Now().Unix()+imageContentSeconds, session.ExpiresAt)}
	if _, err := rand.Read(request.Nonce[:]); err != nil {
		return registryclient.ContentInfo{}, err
	}
	return c.imageContentExchange(ctx, peer, request, 1, func(conn *mydcp.Session, body []byte) (Envelope, error) {
		return Envelope{Body: body, Session: &session, Signature: ed25519.Sign(c.Self.Private, access.RequestBytes(session, conn.PeerChallenge(), body))}, nil
	}, nil, to)
}

func (c Client) imageContentExchange(base context.Context, peer mydcp.Peer, q ImageContentRequest, kind uint8, makeEnvelope func(*mydcp.Session, []byte) (Envelope, error), begin func(registryclient.ContentInfo) error, to io.Writer) (registryclient.ContentInfo, error) {
	if !q.valid(time.Now().Unix()) {
		return registryclient.ContentInfo{}, mydcp.ErrAdmission
	}
	return c.imageContentTransfer(base, peer, q, q.Query, q.ExpiresAt, kind, makeEnvelope, begin, to)
}

// Both user reads and accepted-build owner reads use the same framing,
// tentative-byte, length/digest and final EOF checks. Their grants differ.
func (c Client) imageContentTransfer(base context.Context, peer mydcp.Peer, request any, query registryclient.ContentQuery, expiresAt int64, kind uint8, makeEnvelope func(*mydcp.Session, []byte) (Envelope, error), begin func(registryclient.ContentInfo) error, to io.Writer) (registryclient.ContentInfo, error) {
	var info registryclient.ContentInfo
	if c.Mesh == nil || c.Self == nil || c.Self.Public != [32]byte(c.Mesh.LocalKey()) || !query.Valid() || expiresAt <= time.Now().Unix() || to == nil {
		return info, mydcp.ErrAdmission
	}
	ctx, cancel := context.WithDeadline(base, time.Unix(expiresAt, 0))
	defer cancel()
	setup, done := context.WithTimeout(ctx, 5*time.Second)
	defer done()
	conn, err := c.Mesh.Dial(setup, peer)
	if err != nil {
		return info, &Error{Code: "transport", Phase: mydcp.NotSent, Cause: err}
	}
	body, err := json.Marshal(request)
	if err != nil {
		return info, err
	}
	defer clear(body)
	envelope, err := makeEnvelope(conn, body)
	if err != nil {
		return info, err
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		return info, err
	}
	defer clear(raw)
	header := sha256.Sum256(raw)
	stream, err := conn.OpenImageContentStream(setup)
	if err != nil {
		return info, err
	}
	defer stream.CancelRead(0)
	defer stream.Close()
	stop := context.AfterFunc(ctx, func() { stream.CancelRead(1); stream.CancelWrite(1) })
	defer stop()
	id := c.Mesh.NextRequest()
	if err = contentDeadline(stream, ctx); err != nil {
		return info, err
	}
	if err = mydcp.WriteFrame(stream, mydcp.Frame{Purpose: mydcp.ImageContent, Kind: kind, Request: id, Fields: []mydcp.Field{{Tag: 1, Required: true, Value: raw}, {Tag: 2, Required: true, Value: header[:]}}}); err != nil {
		return info, err
	}
	if err = stream.Close(); err != nil {
		return info, err
	}
	var offset int64
	hash := sha256.New()
	ready := false
	for {
		if err = contentDeadline(stream, ctx); err != nil {
			return info, err
		}
		frame, err := mydcp.ReadFrame(stream, 128<<10)
		if err != nil {
			return info, err
		}
		if frame.Purpose != mydcp.ImageContent || frame.Request != id || conn.Admit(frame, mydcp.ImageContent, false) != nil {
			return info, mydcp.ErrFrame
		}
		if frame.Kind == 4 {
			data := frame.Fields[1].Value
			if !ready || !bytes.Equal(frame.Fields[2].Value, header[:]) || binary.LittleEndian.Uint64(frame.Fields[0].Value) != uint64(offset) || len(data) == 0 || len(data) > imageContentChunk || int64(len(data)) > info.Bytes-offset {
				clear(data)
				return info, mydcp.ErrFrame
			}
			_, _ = hash.Write(data)
			n, err := to.Write(data)
			clear(data)
			if err != nil {
				return info, err
			}
			if n != len(frame.Fields[1].Value) {
				return info, io.ErrShortWrite
			}
			offset += int64(n)
			continue
		}
		if frame.Kind != 2 || !bytes.Equal(frame.Fields[1].Value, header[:]) {
			return info, mydcp.ErrFrame
		}
		reply, err := schema.Decode[ImageContentReply](frame.Fields[0].Value)
		clear(frame.Fields[0].Value)
		if err != nil || !reply.valid(query) {
			return info, mydcp.ErrFrame
		}
		if !ready && reply.Code == "ready" {
			info = *reply.Info
			ready = true
			if begin != nil {
				if err = begin(info); err != nil {
					return info, err
				}
			}
			continue
		}
		if ready && reply.Code == "ready" {
			return info, mydcp.ErrFrame
		}
		if reply.Code != "ok" {
			if streamEOF(stream) != nil {
				return info, mydcp.ErrFrame
			}
			return info, &Error{Code: reply.Code, Phase: mydcp.Completed}
		}
		if !ready || *reply.Info != info || offset != info.Bytes || "sha256:"+hex.EncodeToString(hash.Sum(nil)) != info.Digest || streamEOF(stream) != nil {
			return info, mydcp.ErrFrame
		}
		return info, nil
	}
}

type imageContentRelayWriter struct {
	ctx     context.Context
	stream  mydcp.Stream
	request uint64
	header  [32]byte
	offset  uint64
}

func (w *imageContentRelayWriter) Write(data []byte) (int, error) {
	if err := contentDeadline(w.stream, w.ctx); err != nil {
		return 0, err
	}
	if err := writeImageContent(w.stream, w.request, w.header, w.offset, data); err != nil {
		return 0, err
	}
	w.offset += uint64(len(data))
	return len(data), nil
}
func (s Service) forwardImageContent(ctx context.Context, stream mydcp.Stream, frame mydcp.Frame, header [32]byte, envelope Envelope, binding userBinding, q ImageContentRequest, owner [32]byte) error {
	peer, ok := s.Mesh.Peer(mydcp.Identity(owner))
	if !ok || !peer.Member {
		return imageContentReply(stream, frame, header, ImageContentReply{Code: "unavailable"})
	}
	c := Client{Mesh: s.Mesh, Self: s.Self, Cluster: s.Policy.Cluster}
	writer := &imageContentRelayWriter{ctx: ctx, stream: stream, request: frame.Request, header: header}
	info, err := c.imageContentExchange(ctx, peer, q, 3, func(conn *mydcp.Session, body []byte) (Envelope, error) {
		if !bytes.Equal(body, envelope.Body) {
			return Envelope{}, mydcp.ErrFrame
		}
		copy := envelope
		copy.Relay = &Relay{Node: s.Self.Public, Target: owner, Caller: binding.key, Challenge: binding.challenge, Connection: conn.PeerChallenge()}
		copy.Relay.Signature = ed25519.Sign(s.Self.Private, RelayBytes(s.Policy.Cluster, copy))
		return copy, nil
	}, func(info registryclient.ContentInfo) error {
		return imageContentReply(stream, frame, header, ImageContentReply{Code: "ready", Info: &info})
	}, writer)
	if err != nil {
		code := "unavailable"
		var failure *Error
		if errors.As(err, &failure) && failure.Phase == mydcp.Completed {
			code = failure.Code
		}
		return imageContentReply(stream, frame, header, ImageContentReply{Code: code})
	}
	return imageContentReply(stream, frame, header, ImageContentReply{Code: "ok", Info: &info})
}
