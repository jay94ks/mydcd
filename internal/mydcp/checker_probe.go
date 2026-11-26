// SPDX-License-Identifier: Apache-2.0

package mydcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"time"

	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/quic-go/quic-go"
)

const CheckerProbeMaxBytes = 2 << 20
const checkerProbeChunk = 24 << 10

var ErrCheckerProbeUncertain = errors.New("original remote checker call is unconfirmed")

type CheckerProbeRequest struct {
	Schema    uint8
	Action    string // run or recover; recover cannot dispatch native effects
	Metadata  []byte
	Digest    [32]byte
	Bytes     uint32
	ExpiresAt int64 // Unix milliseconds
}

func (q CheckerProbeRequest) valid() bool {
	return q.Schema == 1 && (q.Action == "run" && q.Bytes > 0 || q.Action == "recover" && q.Bytes == 0) && len(q.Metadata) > 0 && len(q.Metadata) <= 68<<10 && q.Bytes <= CheckerProbeMaxBytes && q.Digest != ([32]byte{}) && q.ExpiresAt > 0
}

type CheckerProbeResult struct {
	Closed bool
	Data   []byte
}

type CheckerProbeHandler struct {
	Lifetime context.Context
	Execute  func(context.Context, []byte) (CheckerProbeResult, error)
}

type checkerProbeResultHeader struct {
	Schema uint8
	Closed bool
	Digest [32]byte
	Bytes  uint32
}

func checkerProbeRead(ctx context.Context, s *Session, stream *quic.Stream, id uint64) (Frame, error) {
	if err := ctx.Err(); err != nil {
		return Frame{}, err
	}
	if err := stream.SetReadDeadline(volumeDeadline(ctx)); err != nil {
		return Frame{}, err
	}
	f, err := ReadFrame(stream, 128<<10)
	if err != nil {
		return Frame{}, err
	}
	if f.Purpose != CheckerProbe || f.Request != id || s.Admit(f, CheckerProbe, false) != nil {
		return Frame{}, ErrAdmission
	}
	return f, nil
}

func checkerProbeWrite(ctx context.Context, s *Session, stream *quic.Stream, f Frame) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.Admit(f, CheckerProbe, false) != nil {
		return ErrAdmission
	}
	if err := stream.SetWriteDeadline(volumeDeadline(ctx)); err != nil {
		return err
	}
	return writeSensitiveFrame(stream, f)
}

func checkerProbeMarker(kind uint8, id uint64, digest, binding [32]byte) Frame {
	return Frame{Purpose: CheckerProbe, Kind: kind, Request: id, Fields: []Field{{1, true, digest[:]}, {2, true, binding[:]}}}
}
func checkerProbeMarkerMatches(f Frame, kind uint8, digest, binding [32]byte) bool {
	return f.Kind == kind && bytes.Equal(f.Fields[0].Value, digest[:]) && bytes.Equal(f.Fields[1].Value, binding[:])
}

func checkerProbeSend(ctx context.Context, s *Session, stream *quic.Stream, id uint64, kind uint8, binding [32]byte, data []byte) error {
	for offset := 0; offset < len(data); offset += checkerProbeChunk {
		var index [8]byte
		binary.LittleEndian.PutUint64(index[:], uint64(offset))
		if err := checkerProbeWrite(ctx, s, stream, Frame{Purpose: CheckerProbe, Kind: kind, Request: id, Fields: []Field{{1, true, index[:]}, {2, true, data[offset:min(offset+checkerProbeChunk, len(data))]}, {3, true, binding[:]}}}); err != nil {
			return err
		}
	}
	return nil
}

func checkerProbeReceive(ctx context.Context, s *Session, stream *quic.Stream, id uint64, kind uint8, binding [32]byte, data []byte) error {
	for offset := 0; offset < len(data); offset += checkerProbeChunk {
		f, err := checkerProbeRead(ctx, s, stream, id)
		want := min(checkerProbeChunk, len(data)-offset)
		if err != nil {
			return err
		}
		if f.Kind != kind || binary.LittleEndian.Uint64(f.Fields[0].Value) != uint64(offset) || len(f.Fields[1].Value) != want || !bytes.Equal(f.Fields[2].Value, binding[:]) {
			return ErrFrame
		}
		copy(data[offset:], f.Fields[1].Value)
		clear(f.Fields[1].Value)
	}
	return nil
}

// Header resolution authenticates the role/current authority BEFORE payload
// allocation. Execute owns durable native dispatch/closure, not this codec.
func (t *Transport) OnCheckerProbe(resolve func(context.Context, *Session, CheckerProbeRequest) (CheckerProbeHandler, error)) error {
	if resolve == nil {
		return ErrAdmission
	}
	return t.On(CheckerProbe, func(base context.Context, s *Session, stream *quic.Stream, first Frame) error {
		if first.Kind != 1 || s.local != nil || s.Admit(first, CheckerProbe, false) != nil {
			return ErrAdmission
		}
		binding := sha256.Sum256(first.Fields[0].Value)
		if !bytes.Equal(binding[:], first.Fields[1].Value) {
			return ErrFrame
		}
		q, err := schema.Decode[CheckerProbeRequest](first.Fields[0].Value)
		now := time.Now().UnixMilli()
		if err != nil || !q.valid() || q.ExpiresAt <= now || q.Action == "recover" && q.ExpiresAt-now > 30000 {
			return ErrAdmission
		}
		ctx, cancel := context.WithDeadline(base, time.UnixMilli(q.ExpiresAt))
		defer cancel()
		stop := context.AfterFunc(ctx, func() { stream.CancelRead(1); stream.CancelWrite(1) })
		defer stop()
		auth, done := context.WithTimeout(ctx, 30*time.Second)
		handler, err := resolve(auth, s, q)
		done()
		if err != nil || handler.Execute == nil {
			return ErrAdmission
		}
		if handler.Lifetime != nil {
			stop := context.AfterFunc(handler.Lifetime, cancel)
			defer stop()
		}
		payload := make([]byte, int(q.Bytes))
		defer clear(payload)
		if err = checkerProbeReceive(ctx, s, stream, first.Request, 2, binding, payload); err != nil {
			return err
		}
		end, err := checkerProbeRead(ctx, s, stream, first.Request)
		if err != nil {
			return err
		}
		if !checkerProbeMarkerMatches(end, 3, q.Digest, binding) || q.Action == "run" && sha256.Sum256(payload) != q.Digest {
			return ErrFrame
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		result, err := handler.Execute(ctx, payload)
		defer clear(result.Data)
		if err != nil {
			return err
		}
		if len(result.Data) > CheckerProbeMaxBytes || !result.Closed && len(result.Data) != 0 {
			return ErrFrame
		}
		meta := checkerProbeResultHeader{Schema: 1, Closed: result.Closed, Digest: sha256.Sum256(result.Data), Bytes: uint32(len(result.Data))}
		raw, err := json.Marshal(meta)
		if err != nil {
			return err
		}
		if err = checkerProbeWrite(ctx, s, stream, Frame{Purpose: CheckerProbe, Kind: 4, Request: first.Request, Fields: []Field{{1, true, raw}, {2, true, binding[:]}}}); err != nil {
			return err
		}
		if err = checkerProbeSend(ctx, s, stream, first.Request, 5, binding, result.Data); err != nil {
			return err
		}
		if err = checkerProbeWrite(ctx, s, stream, checkerProbeMarker(6, first.Request, meta.Digest, binding)); err != nil {
			return err
		}
		ack, err := checkerProbeRead(ctx, s, stream, first.Request)
		if err != nil || !checkerProbeMarkerMatches(ack, 7, meta.Digest, binding) {
			return ErrFrame
		}
		if err = streamEOFChecker(stream); err != nil {
			return err
		}
		return checkerProbeWrite(ctx, s, stream, checkerProbeMarker(8, first.Request, meta.Digest, binding))
	})
}

// CallCheckerProbe makes ONE attempt. store must preserve the original call's
// closure before ACK; any transport/storage failure requires original lookup,
// never another run request. Private Data is returned only after final ACK/EOF.
func (s *Session) CallCheckerProbe(ctx context.Context, q CheckerProbeRequest, payload []byte, store func(context.Context, bool, []byte) error) (CheckerProbeResult, error) {
	if s == nil || s.local != nil || ctx == nil || !q.valid() || q.ExpiresAt <= time.Now().UnixMilli() || q.Action == "recover" && q.ExpiresAt-time.Now().UnixMilli() > 30000 || len(payload) != int(q.Bytes) || q.Action == "run" && sha256.Sum256(payload) != q.Digest || store == nil {
		return CheckerProbeResult{}, ErrAdmission
	}
	ctx, cancel := context.WithDeadline(ctx, time.UnixMilli(q.ExpiresAt))
	defer cancel()
	q.Metadata = bytes.Clone(q.Metadata)
	payload = bytes.Clone(payload)
	defer clear(payload)
	body, err := json.Marshal(q)
	if err != nil {
		return CheckerProbeResult{}, err
	}
	binding := sha256.Sum256(body)
	id := s.transport.NextRequest()
	first := Frame{Purpose: CheckerProbe, Kind: 1, Request: id, Fields: []Field{{1, true, body}, {2, true, binding[:]}}}
	if s.Admit(first, CheckerProbe, false) != nil {
		return CheckerProbeResult{}, ErrAdmission
	}
	stream, err := s.Open(ctx)
	if err != nil {
		return CheckerProbeResult{}, err
	}
	defer stream.Close()
	defer stream.CancelRead(0)
	stop := context.AfterFunc(ctx, func() { stream.CancelRead(1); stream.CancelWrite(1) })
	defer stop()
	fail := func(err error) (CheckerProbeResult, error) {
		return CheckerProbeResult{}, errors.Join(ErrCheckerProbeUncertain, err)
	}
	if err = checkerProbeWrite(ctx, s, stream, first); err != nil {
		return fail(err)
	}
	if err = checkerProbeSend(ctx, s, stream, id, 2, binding, payload); err != nil {
		return fail(err)
	}
	if err = checkerProbeWrite(ctx, s, stream, checkerProbeMarker(3, id, q.Digest, binding)); err != nil {
		return fail(err)
	}
	header, err := checkerProbeRead(ctx, s, stream, id)
	if err != nil {
		return fail(err)
	}
	if header.Kind != 4 || !bytes.Equal(header.Fields[1].Value, binding[:]) {
		return fail(ErrFrame)
	}
	meta, err := schema.Decode[checkerProbeResultHeader](header.Fields[0].Value)
	if err != nil || meta.Schema != 1 || meta.Bytes > CheckerProbeMaxBytes || !meta.Closed && meta.Bytes != 0 {
		return fail(ErrFrame)
	}
	data := make([]byte, int(meta.Bytes))
	accepted := false
	defer func() {
		if !accepted {
			clear(data)
		}
	}()
	if err = checkerProbeReceive(ctx, s, stream, id, 5, binding, data); err != nil {
		return fail(err)
	}
	end, err := checkerProbeRead(ctx, s, stream, id)
	if err != nil {
		return fail(err)
	}
	if !checkerProbeMarkerMatches(end, 6, meta.Digest, binding) || sha256.Sum256(data) != meta.Digest {
		return fail(ErrFrame)
	}
	if err = store(ctx, meta.Closed, data); err != nil {
		return fail(err)
	}
	if err = checkerProbeWrite(ctx, s, stream, checkerProbeMarker(7, id, meta.Digest, binding)); err != nil {
		return fail(err)
	}
	if err = stream.Close(); err != nil {
		return fail(err)
	}
	ack, err := checkerProbeRead(ctx, s, stream, id)
	if err != nil {
		return fail(err)
	}
	if !checkerProbeMarkerMatches(ack, 8, meta.Digest, binding) {
		return fail(ErrFrame)
	}
	if err = streamEOFChecker(stream); err != nil {
		return fail(err)
	}
	accepted = true
	return CheckerProbeResult{Closed: meta.Closed, Data: data}, nil
}
