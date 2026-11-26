// SPDX-License-Identifier: Apache-2.0

package mydcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/quic-go/quic-go"
)

const CheckerArtifactMaxBytes = 64 << 20
const checkerArtifactChunk = 24 << 10
const checkerArtifactWindow = 256 << 10

var ErrCheckerArtifactUncertain = errors.New("original checker artifact receipt is unconfirmed")

type CheckerArtifactRequest struct {
	Schema    uint8
	Metadata  []byte
	Digest    [32]byte
	Bytes     uint64
	ExpiresAt int64
}

func (r CheckerArtifactRequest) valid() bool {
	return r.Schema == 1 && len(r.Metadata) > 0 && len(r.Metadata) <= 20<<10 && r.Digest != ([32]byte{}) && r.Bytes > 0 && r.Bytes <= CheckerArtifactMaxBytes && r.ExpiresAt > 0
}

type CheckerArtifactSource struct {
	Lifetime       context.Context
	Metadata, Data []byte
	Authorize      func(context.Context) error
}

// Metadata is checked before body allocation. Store must validate and sync the
// complete original bytes before returning. This is a content receipt, never
// an app/runner Ready or a remote native effect's completion.
type CheckerArtifactSink struct {
	Metadata func([]byte) error
	Store    func(context.Context, []byte) error
}

func checkerArtifactRead(ctx context.Context, s *Session, stream *quic.Stream, id uint64) (Frame, error) {
	if err := ctx.Err(); err != nil {
		return Frame{}, err
	}
	if err := stream.SetReadDeadline(volumeDeadline(ctx)); err != nil {
		return Frame{}, err
	}
	f, err := ReadFrame(stream, 32<<10)
	if err != nil {
		return Frame{}, err
	}
	if f.Purpose != CheckerArtifact || f.Request != id || s.Admit(f, CheckerArtifact, false) != nil {
		return Frame{}, ErrAdmission
	}
	return f, nil
}
func checkerArtifactWrite(ctx context.Context, s *Session, stream *quic.Stream, f Frame) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.Admit(f, CheckerArtifact, false) != nil {
		return ErrAdmission
	}
	if err := stream.SetWriteDeadline(volumeDeadline(ctx)); err != nil {
		return err
	}
	return writeSensitiveFrame(stream, f)
}
func checkerArtifactReceipt(kind uint8, id uint64, digest, binding [32]byte) Frame {
	return Frame{Purpose: CheckerArtifact, Kind: kind, Request: id, Fields: []Field{{1, true, digest[:]}, {2, true, binding[:]}}}
}
func checkerArtifactReceiptMatches(f Frame, kind uint8, digest, binding [32]byte) bool {
	return f.Kind == kind && bytes.Equal(f.Fields[0].Value, digest[:]) && bytes.Equal(f.Fields[1].Value, binding[:])
}

func (t *Transport) OnCheckerArtifact(resolve func(context.Context, *Session, CheckerArtifactRequest) (CheckerArtifactSource, error)) error {
	if resolve == nil {
		return ErrAdmission
	}
	return t.On(CheckerArtifact, func(base context.Context, s *Session, stream *quic.Stream, f Frame) error {
		if f.Kind != 1 {
			return ErrFrame
		}
		binding := sha256.Sum256(f.Fields[0].Value)
		if !bytes.Equal(binding[:], f.Fields[1].Value) {
			return ErrFrame
		}
		r, err := schema.Decode[CheckerArtifactRequest](f.Fields[0].Value)
		now := time.Now().Unix()
		if err != nil || !r.valid() || r.ExpiresAt <= now || r.ExpiresAt-now > 300 {
			return ErrAdmission
		}
		ctx, cancel := context.WithDeadline(base, time.Unix(r.ExpiresAt, 0))
		defer cancel()
		stop := context.AfterFunc(ctx, func() { stream.CancelRead(1); stream.CancelWrite(1) })
		defer stop()
		requestEnd, err := checkerArtifactRead(ctx, s, stream, f.Request)
		if err != nil || !checkerArtifactReceiptMatches(requestEnd, 7, r.Digest, binding) {
			return ErrFrame
		}
		source, err := resolve(ctx, s, r)
		defer clear(source.Data)
		defer clear(source.Metadata)
		if err != nil || source.Authorize == nil || len(source.Metadata) == 0 || len(source.Metadata) > 20<<10 || uint64(len(source.Data)) != r.Bytes || sha256.Sum256(source.Data) != r.Digest {
			return ErrAdmission
		}
		if source.Lifetime != nil {
			stop := context.AfterFunc(source.Lifetime, cancel)
			defer stop()
		}
		if err := source.Authorize(ctx); err != nil {
			return err
		}
		if err := checkerArtifactWrite(ctx, s, stream, Frame{Purpose: CheckerArtifact, Kind: 2, Request: f.Request, Fields: []Field{{1, true, source.Metadata}, {2, true, binding[:]}}}); err != nil {
			return err
		}
		window := -1
		for offset := 0; offset < len(source.Data); offset += checkerArtifactChunk {
			if next := offset / checkerArtifactWindow; next != window {
				if err := source.Authorize(ctx); err != nil {
					return err
				}
				window = next
			}
			var encoded [8]byte
			binary.LittleEndian.PutUint64(encoded[:], uint64(offset))
			part := source.Data[offset:min(offset+checkerArtifactChunk, len(source.Data))]
			if err := checkerArtifactWrite(ctx, s, stream, Frame{Purpose: CheckerArtifact, Kind: 3, Request: f.Request, Fields: []Field{{1, true, encoded[:]}, {2, true, part}, {3, true, binding[:]}}}); err != nil {
				return err
			}
		}
		if err := source.Authorize(ctx); err != nil {
			return err
		}
		if err := checkerArtifactWrite(ctx, s, stream, checkerArtifactReceipt(4, f.Request, r.Digest, binding)); err != nil {
			return err
		}
		ack, err := checkerArtifactRead(ctx, s, stream, f.Request)
		if err != nil || !checkerArtifactReceiptMatches(ack, 5, r.Digest, binding) {
			return ErrAdmission
		}
		if err := streamEOFChecker(stream); err != nil {
			return err
		}
		if err := source.Authorize(ctx); err != nil {
			return err
		}
		if err := checkerArtifactWrite(ctx, s, stream, checkerArtifactReceipt(6, f.Request, r.Digest, binding)); err != nil {
			return err
		}
		return stream.Close()
	})
}

func streamEOFChecker(r io.Reader) error {
	var extra [1]byte
	n, err := r.Read(extra[:])
	if n != 0 || err != io.EOF {
		return ErrFrame
	}
	return nil
}

// PullCheckerArtifact is one attempt. It does not retry, redirect or replace
// an original input/job ID. Failure after Store may still have durable bytes;
// callers recover that exact local cache before making any next decision.
func (s *Session) PullCheckerArtifact(ctx context.Context, r CheckerArtifactRequest, sink CheckerArtifactSink) error {
	if ctx == nil || !r.valid() || sink.Metadata == nil || sink.Store == nil {
		return ErrAdmission
	}
	now := time.Now().Unix()
	if r.ExpiresAt <= now || r.ExpiresAt-now > 300 {
		return ErrAdmission
	}
	ctx, cancel := context.WithDeadline(ctx, time.Unix(r.ExpiresAt, 0))
	defer cancel()
	r.Metadata = bytes.Clone(r.Metadata)
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	binding := sha256.Sum256(body)
	id := s.transport.NextRequest()
	first := Frame{Purpose: CheckerArtifact, Kind: 1, Request: id, Fields: []Field{{1, true, body}, {2, true, binding[:]}}}
	if s.Admit(first, CheckerArtifact, false) != nil {
		return ErrAdmission
	}
	stream, err := s.Open(ctx)
	if err != nil {
		return err
	}
	defer stream.CancelRead(0)
	defer stream.Close()
	stop := context.AfterFunc(ctx, func() { stream.CancelRead(1); stream.CancelWrite(1) })
	defer stop()
	if err := checkerArtifactWrite(ctx, s, stream, first); err != nil {
		return err
	}
	// End the request with a bounded marker while keeping the ACK direction
	// open. It is written immediately after kind1, without another round trip.
	if err := checkerArtifactWrite(ctx, s, stream, checkerArtifactReceipt(7, id, r.Digest, binding)); err != nil {
		return err
	}
	metadata, err := checkerArtifactRead(ctx, s, stream, id)
	if err != nil || metadata.Kind != 2 || !bytes.Equal(metadata.Fields[1].Value, binding[:]) {
		return errors.Join(ErrAdmission, err)
	}
	if err := sink.Metadata(metadata.Fields[0].Value); err != nil {
		return err
	}
	data := make([]byte, int(r.Bytes))
	defer clear(data)
	for offset := 0; offset < len(data); offset += checkerArtifactChunk {
		f, err := checkerArtifactRead(ctx, s, stream, id)
		want := min(checkerArtifactChunk, len(data)-offset)
		if err != nil || f.Kind != 3 || binary.LittleEndian.Uint64(f.Fields[0].Value) != uint64(offset) || len(f.Fields[1].Value) != want || !bytes.Equal(f.Fields[2].Value, binding[:]) {
			return errors.Join(ErrFrame, err)
		}
		copy(data[offset:], f.Fields[1].Value)
		clear(f.Fields[1].Value)
	}
	end, err := checkerArtifactRead(ctx, s, stream, id)
	if err != nil || !checkerArtifactReceiptMatches(end, 4, r.Digest, binding) || sha256.Sum256(data) != r.Digest {
		return errors.Join(ErrFrame, err)
	}
	if err := sink.Store(ctx, data); err != nil {
		return errors.Join(ErrCheckerArtifactUncertain, err)
	}
	if err := checkerArtifactWrite(ctx, s, stream, checkerArtifactReceipt(5, id, r.Digest, binding)); err != nil {
		return errors.Join(ErrCheckerArtifactUncertain, err)
	}
	if err := stream.Close(); err != nil {
		return errors.Join(ErrCheckerArtifactUncertain, err)
	}
	receipt, err := checkerArtifactRead(ctx, s, stream, id)
	if err != nil || !checkerArtifactReceiptMatches(receipt, 6, r.Digest, binding) {
		return errors.Join(ErrCheckerArtifactUncertain, err)
	}
	if err := streamEOFChecker(stream); err != nil {
		return errors.Join(ErrCheckerArtifactUncertain, err)
	}
	return nil
}
