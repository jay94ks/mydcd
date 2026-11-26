// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

// Public metadata only. Bytes flow on purpose18 and never enter UserOperation.
type VolumeFileRequest struct {
	Recover   bool `json:",omitempty"`
	Schema    uint8
	ID        string
	ExpiresAt int64
	Nonce     [32]byte
}
type VolumeFileReply struct {
	Schema   uint8
	ID, Code string
	Result   *volumes.FileResult `json:",omitempty"`
	Entries  []volumes.FileEntry `json:",omitempty"`
	Next     string              `json:",omitempty"`
}
type VolumeFileIO struct {
	Recover bool
	Epoch   uint64
	Source  io.Reader
	Write   func([]byte) error
}
type VolumeFileRunner func(context.Context, access.Session, control.VolumeFileJob, VolumeFileIO) (VolumeFileReply, error)

// volumeFileView consumes the existing authenticated quorum barrier before
// selecting or consuming an original file operation. An owner can be a Raft
// follower; its ReadAtLeast view is local after consuming that exact prefix.
func (s Service) volumeFileView(ctx context.Context, envelope Envelope, id string, epoch uint64, original *control.VolumeFileJob) (cluster.View, control.VolumeFileJob, error) {
	view, err := s.authenticationView(ctx)
	if err != nil {
		return view, control.VolumeFileJob{}, err
	}
	job, err := s.volumeFileAt(view, envelope, id, epoch, original)
	return view, job, err
}

func (s Service) volumeFileAt(view cluster.View, envelope Envelope, id string, epoch uint64, original *control.VolumeFileJob) (control.VolumeFileJob, error) {
	if envelope.Session == nil || view.RaftIndex == 0 || epoch != 0 && view.State.ModuleEpoch() != epoch || s.Enabled != nil && !s.Enabled(view.State) || envelope.Relay != nil && envelope.Relay.ServiceCall != nil {
		return control.VolumeFileJob{}, mydcp.ErrAdmission
	}
	policy, err := s.Policy.Current(view.State)
	if err != nil {
		return control.VolumeFileJob{}, err
	}
	s.Policy = policy
	book, err := policy.Volumes(view.State)
	if err != nil {
		return control.VolumeFileJob{}, err
	}
	job, ok := book.VolumeFile(id)
	if !ok {
		return control.VolumeFileJob{}, mydcp.ErrAdmission
	}
	catalog, err := policy.Catalog(view.State)
	if err != nil || !s.nodeRequestAllowed(view.State, catalog, Request{Method: "submit", Operation: &job.Origin}, envelope) {
		return control.VolumeFileJob{}, mydcp.ErrAdmission
	}
	// The relay supplies connection proof, never a replacement user/session.
	// Passing the recorded owner here also permits an ingress to select it;
	// only that exact owner may enter the native runner below.
	currentOwner, err := s.resourceOwner(view.State, job.Native.Owner.Node, job.Native.Owner.Key)
	if err != nil {
		return control.VolumeFileJob{}, err
	}
	job, err = policy.VolumeFileWork(view.State, currentOwner, *envelope.Session, id, time.Now().Unix())
	if err != nil {
		return control.VolumeFileJob{}, err
	}
	if original != nil && (job.ID != original.ID || job.Method != original.Method || job.Request != original.Request || job.Consumer != original.Consumer || volumes.NativeBindingDigest(job.Native) != volumes.NativeBindingDigest(original.Native)) {
		return control.VolumeFileJob{}, mydcp.ErrAdmission
	}
	return job, nil
}

func writeVolumeFileReply(stream mydcp.Stream, id uint64, header [32]byte, r VolumeFileReply) error {
	r.Schema = 1
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return mydcp.WriteFrame(stream, mydcp.Frame{Purpose: mydcp.VolumeFile, Kind: 2, Request: id, Fields: []mydcp.Field{{Tag: 1, Required: true, Value: raw}, {Tag: 2, Required: true, Value: header[:]}}})
}
func volumeFileChunk(stream mydcp.Stream, id uint64, header [32]byte, offset uint64, data []byte) error {
	if len(data) == 0 || len(data) > 24<<10 {
		return mydcp.ErrFrame
	}
	var off [8]byte
	binary.LittleEndian.PutUint64(off[:], offset)
	return mydcp.WriteFrame(stream, mydcp.Frame{Purpose: mydcp.VolumeFile, Kind: 4, Request: id, Fields: []mydcp.Field{{Tag: 1, Required: true, Value: off[:]}, {Tag: 2, Required: true, Value: data}, {Tag: 3, Required: true, Value: header[:]}}})
}

// The reader exposes EOF only after EXACT payload length and stream EOF. The
// native atomic put consequently cannot publish a truncated/overlong request.
type volumeFileReader struct {
	stream       mydcp.Stream
	id           uint64
	header       [32]byte
	size, offset int64
	pending      []byte
	done         bool
	authorize    func() error
}

func (r *volumeFileReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if err := r.authorize(); err != nil {
		return 0, err
	}
	if len(r.pending) > 0 {
		n := copy(p, r.pending)
		clear(r.pending[:n])
		r.pending = r.pending[n:]
		return n, nil
	}
	if r.done {
		return 0, io.EOF
	}
	if r.offset == r.size {
		if err := streamEOF(r.stream); err != nil {
			return 0, err
		}
		r.done = true
		return 0, io.EOF
	}
	f, err := mydcp.ReadFrame(r.stream, 128<<10)
	if err != nil {
		return 0, err
	}
	if f.Purpose != mydcp.VolumeFile || f.Kind != 4 || f.Request != r.id || binary.LittleEndian.Uint64(f.Fields[0].Value) != uint64(r.offset) || !bytes.Equal(f.Fields[2].Value, r.header[:]) || len(f.Fields[1].Value) == 0 || len(f.Fields[1].Value) > 24<<10 || int64(len(f.Fields[1].Value)) > r.size-r.offset {
		return 0, mydcp.ErrFrame
	}
	if err := r.authorize(); err != nil {
		clear(f.Fields[1].Value)
		return 0, err
	}
	r.offset += int64(len(f.Fields[1].Value))
	r.pending = f.Fields[1].Value
	return r.Read(p)
}
func (q VolumeFileRequest) valid(now int64) bool {
	return q.Schema == 1 && q.ID != "" && len(q.ID) < 64 && q.Nonce != ([32]byte{}) && q.ExpiresAt > now && q.ExpiresAt-now <= 900
}

func (s Service) handleVolumeFile(base context.Context, conn *mydcp.Session, stream mydcp.Stream, frame mydcp.Frame) error {
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
	defer clear(envelope.Body)
	q, err := schema.Decode[VolumeFileRequest](envelope.Body)
	reply := func(code string) error {
		return writeVolumeFileReply(stream, frame.Request, header, VolumeFileReply{ID: q.ID, Code: code})
	}
	if err != nil || !q.valid(time.Now().Unix()) || envelope.Session == nil || q.ExpiresAt > envelope.Session.ExpiresAt {
		return reply("denied")
	}
	binding, err := s.binding(conn, frame.Kind, envelope)
	if err != nil || binding.key != envelope.Session.Key {
		return reply("denied")
	}
	ctx, cancel := context.WithDeadline(base, time.Unix(q.ExpiresAt, 0))
	defer cancel()
	stop := context.AfterFunc(ctx, func() { stream.CancelRead(1); stream.CancelWrite(1) })
	defer stop()
	view, job, err := s.volumeFileView(ctx, envelope, q.ID, 0, nil)
	if err != nil {
		return reply("denied")
	}
	epoch := view.State.ModuleEpoch()
	currentOwner, err := s.resourceOwner(view.State, job.Native.Owner.Node, job.Native.Owner.Key)
	if err != nil {
		return reply("denied")
	}
	authorize := func() error {
		if err := conn.Admit(frame, mydcp.VolumeFile, false); err != nil {
			return err
		}
		if _, err := s.binding(conn, frame.Kind, envelope); err != nil {
			return err
		}
		fresh, current, err := s.volumeFileView(ctx, envelope, q.ID, epoch, &job)
		if err != nil || current.Native.Owner != job.Native.Owner {
			return mydcp.ErrAdmission
		}
		owner, err := s.resourceOwner(fresh.State, current.Native.Owner.Node, current.Native.Owner.Key)
		if err != nil || owner != currentOwner {
			return mydcp.ErrAdmission
		}
		return nil
	}
	if err = authorize(); err != nil {
		return reply("denied")
	}
	// A relay attests only the original user's proof and this one connection.
	// It cannot replace the user's credential or accepted operation.
	if currentOwner != s.Self.Public {
		if envelope.Relay != nil {
			return reply("target-changed")
		}
		return s.forwardVolumeFile(ctx, conn, stream, frame, header, envelope, binding, q, job, currentOwner, authorize)
	}
	if s.VolumeFiles == nil {
		return reply("unavailable")
	}
	if job.Method != "volume-file-put" || q.Recover {
		if err = streamEOF(stream); err != nil {
			return err
		}
	}
	if err = reply("ready"); err != nil {
		return err
	}
	reader := &volumeFileReader{stream: stream, id: frame.Request, header: header, size: job.Request.Size, authorize: authorize}
	defer clear(reader.pending)
	var offset uint64
	ioBoundary := VolumeFileIO{Recover: q.Recover, Epoch: epoch, Source: reader, Write: func(data []byte) error {
		if err := authorize(); err != nil {
			return err
		}
		if err := volumeFileChunk(stream, frame.Request, header, offset, data); err != nil {
			return err
		}
		offset += uint64(len(data))
		return nil
	}}
	if err = authorize(); err != nil {
		return reply("denied")
	}
	r, err := s.VolumeFiles(ctx, *envelope.Session, job, ioBoundary)
	if err != nil {
		return reply("unknown")
	}
	if job.Method == "volume-file-put" && !q.Recover && !reader.done {
		if _, err := io.Copy(io.Discard, reader); err != nil {
			return err
		}
		if !reader.done {
			return mydcp.ErrFrame
		}
	}
	// The original native runner has completed/retained its own I/O settlement
	// before this response gate. Authority loss here suppresses the result and
	// never substitutes a new operation or discards a possibly published write.
	if err = authorize(); err != nil {
		return reply("denied")
	}
	r.ID = q.ID
	return writeVolumeFileReply(stream, frame.Request, header, r)
}

func (s Service) forwardVolumeFile(ctx context.Context, incoming *mydcp.Session, stream mydcp.Stream, frame mydcp.Frame, header [32]byte, envelope Envelope, binding userBinding, q VolumeFileRequest, job control.VolumeFileJob, currentOwner [32]byte, authorize func() error) error {
	peer, ok := s.Mesh.Peer(mydcp.Identity(currentOwner))
	if !ok || !peer.Member || peer.ID != job.Native.Owner.Node {
		return writeVolumeFileReply(stream, frame.Request, header, VolumeFileReply{ID: q.ID, Code: "unavailable"})
	}
	c := Client{Mesh: s.Mesh, Self: s.Self, Cluster: s.Policy.Cluster}
	// The same bounded decoder validates both sides; relay changes only the
	// connection/header proof and re-chunks bytes at their original offsets.
	var source io.Reader
	if job.Method == "volume-file-put" && !q.Recover {
		r := &volumeFileReader{stream: stream, id: frame.Request, header: header, size: job.Request.Size, authorize: authorize}
		defer clear(r.pending)
		source = r
	} else if err := streamEOF(stream); err != nil {
		return err
	}
	if err := writeVolumeFileReply(stream, frame.Request, header, VolumeFileReply{ID: q.ID, Code: "ready"}); err != nil {
		return err
	}
	var offset uint64
	r, err := c.volumeFileExchange(ctx, peer, q, job, source, volumeFileWriterFunc(func(b []byte) (int, error) {
		if err := authorize(); err != nil {
			return 0, err
		}
		e := volumeFileChunk(stream, frame.Request, header, offset, b)
		if e != nil {
			return 0, e
		}
		offset += uint64(len(b))
		return len(b), nil
	}), 3, func(conn *mydcp.Session, body []byte) (Envelope, error) {
		copy := envelope
		copy.Relay = &Relay{Node: s.Self.Public, Target: currentOwner, Caller: binding.key, Challenge: binding.challenge, Connection: conn.PeerChallenge()}
		copy.Relay.Signature = ed25519.Sign(s.Self.Private, RelayBytes(s.Policy.Cluster, copy))
		return copy, nil
	})
	if err != nil {
		var completed *Error
		if !errors.As(err, &completed) || completed.Phase != mydcp.Completed {
			return err
		}
	}
	if err := authorize(); err != nil {
		return writeVolumeFileReply(stream, frame.Request, header, VolumeFileReply{ID: q.ID, Code: "denied"})
	}
	return writeVolumeFileReply(stream, frame.Request, header, r)
}

type volumeFileWriterFunc func([]byte) (int, error)

func (f volumeFileWriterFunc) Write(b []byte) (int, error) { return f(b) }

func (c Client) VolumeFile(ctx context.Context, peer mydcp.Peer, session access.Session, job control.VolumeFileJob, source io.Reader, to io.Writer) (VolumeFileReply, error) {
	if c.Verify(session) != nil || job.Origin.Session.User != session.User {
		return VolumeFileReply{}, mydcp.ErrAdmission
	}
	q := VolumeFileRequest{Recover: job.Method == "volume-file-put" && source == nil, Schema: 1, ID: job.ID, ExpiresAt: min(session.ExpiresAt, time.Now().Add(15*time.Minute).Unix())}
	if _, err := rand.Read(q.Nonce[:]); err != nil {
		return VolumeFileReply{}, err
	}
	return c.volumeFileExchange(ctx, peer, q, job, source, to, 1, func(conn *mydcp.Session, body []byte) (Envelope, error) {
		return Envelope{Session: &session, Body: body, Signature: ed25519.Sign(c.Self.Private, access.RequestBytes(session, conn.PeerChallenge(), body))}, nil
	})
}
func (c Client) volumeFileExchange(base context.Context, peer mydcp.Peer, q VolumeFileRequest, job control.VolumeFileJob, source io.Reader, to io.Writer, kind uint8, envelopeFor func(*mydcp.Session, []byte) (Envelope, error)) (VolumeFileReply, error) {
	if !q.valid(time.Now().Unix()) || q.ID != job.ID || job.Request.Scope.Cluster != c.Cluster || !job.Request.Valid(job.Method) {
		return VolumeFileReply{}, mydcp.ErrAdmission
	}
	ctx, cancel := context.WithDeadline(base, time.Unix(q.ExpiresAt, 0))
	defer cancel()
	conn, err := c.Mesh.Dial(ctx, peer)
	if err != nil {
		return VolumeFileReply{}, err
	}
	body, _ := json.Marshal(q)
	envelope, err := envelopeFor(conn, body)
	if err != nil {
		return VolumeFileReply{}, err
	}
	raw, _ := json.Marshal(envelope)
	header := sha256.Sum256(raw)
	stream, err := conn.OpenVolumeFileStream(ctx)
	if err != nil {
		return VolumeFileReply{}, err
	}
	defer stream.Close()
	defer stream.CancelRead(0)
	stop := context.AfterFunc(ctx, func() { stream.CancelRead(1); stream.CancelWrite(1) })
	defer stop()
	id := c.Mesh.NextRequest()
	if err = mydcp.WriteFrame(stream, mydcp.Frame{Purpose: mydcp.VolumeFile, Kind: kind, Request: id, Fields: []mydcp.Field{{Tag: 1, Required: true, Value: raw}, {Tag: 2, Required: true, Value: header[:]}}}); err != nil {
		return VolumeFileReply{}, err
	}
	if job.Method != "volume-file-put" || q.Recover {
		if err = stream.Close(); err != nil {
			return VolumeFileReply{}, err
		}
	}
	readReply := func() (VolumeFileReply, error) {
		f, e := mydcp.ReadFrame(stream, 128<<10)
		if e != nil {
			return VolumeFileReply{}, e
		}
		if f.Purpose != mydcp.VolumeFile || f.Kind != 2 || f.Request != id || conn.Admit(f, mydcp.VolumeFile, false) != nil || !bytes.Equal(f.Fields[1].Value, header[:]) {
			return VolumeFileReply{}, mydcp.ErrFrame
		}
		r, e := schema.Decode[VolumeFileReply](f.Fields[0].Value)
		if e != nil || r.Schema != 1 || r.ID != q.ID {
			return VolumeFileReply{}, mydcp.ErrFrame
		}
		return r, nil
	}
	r, err := readReply()
	if err != nil {
		return r, err
	}
	if r.Code != "ready" {
		if err = stream.Close(); err != nil {
			return r, err
		}
		if err = streamEOF(stream); err != nil {
			return r, err
		}
		return r, &Error{Code: r.Code, Phase: mydcp.Completed}
	}
	if job.Method == "volume-file-put" && !q.Recover {
		if source == nil {
			return r, mydcp.ErrFrame
		}
		buf := make([]byte, 24<<10)
		defer clear(buf)
		var offset int64
		for offset < job.Request.Size {
			n, e := io.ReadFull(source, buf[:min(int64(len(buf)), job.Request.Size-offset)])
			if e != nil {
				return r, e
			}
			if e = volumeFileChunk(stream, id, header, uint64(offset), buf[:n]); e != nil {
				return r, e
			}
			offset += int64(n)
		}
		var extra [1]byte
		if n, e := source.Read(extra[:]); n != 0 || !errors.Is(e, io.EOF) {
			return r, mydcp.ErrFrame
		}
		if err = stream.Close(); err != nil {
			return r, err
		}
	}
	if job.Method == "volume-file-get" {
		if to == nil {
			return r, mydcp.ErrFrame
		}
		h := sha256.New()
		var offset int64
		for {
			f, e := mydcp.ReadFrame(stream, 128<<10)
			if e != nil {
				return r, e
			}
			if f.Purpose != mydcp.VolumeFile || f.Request != id || conn.Admit(f, mydcp.VolumeFile, false) != nil {
				return r, mydcp.ErrFrame
			}
			if f.Kind == 2 {
				if !bytes.Equal(f.Fields[1].Value, header[:]) {
					return r, mydcp.ErrFrame
				}
				r, e = schema.Decode[VolumeFileReply](f.Fields[0].Value)
				if e != nil || r.Schema != 1 || r.ID != q.ID {
					return r, mydcp.ErrFrame
				}
				if r.Code != "ok" || r.Result == nil || r.Result.Size != offset || !bytes.Equal(r.Result.Digest[:], h.Sum(nil)) {
					return r, mydcp.ErrFrame
				}
				break
			}
			if f.Kind != 4 || binary.LittleEndian.Uint64(f.Fields[0].Value) != uint64(offset) || !bytes.Equal(f.Fields[2].Value, header[:]) || int64(len(f.Fields[1].Value)) > job.Request.MaxBytes-offset {
				return r, mydcp.ErrFrame
			}
			data := f.Fields[1].Value
			_, _ = h.Write(data)
			n, e := to.Write(data)
			clear(data)
			if e != nil {
				return r, e
			}
			if n != len(data) {
				return r, io.ErrShortWrite
			}
			offset += int64(n)
		}
	} else {
		r, err = readReply()
		if err != nil {
			return r, err
		}
	}
	if err = streamEOF(stream); err != nil {
		return r, err
	}
	if r.Code != "ok" {
		return r, &Error{Code: r.Code, Phase: mydcp.Completed}
	}
	if job.Method == "volume-file-put" && (r.Result == nil || r.Result.Path != job.Request.Path || r.Result.Size != job.Request.Size || r.Result.Digest != job.Request.Digest) {
		return r, mydcp.ErrFrame
	}
	return r, nil
}
