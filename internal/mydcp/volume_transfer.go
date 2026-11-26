// SPDX-License-Identifier: Apache-2.0

package mydcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"io"
	"time"

	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/quic-go/quic-go"
)

const VolumeChunkSize = 128 << 10
const volumeBytesPerSecond = 8 << 20

func volumePacing(sent uint64) time.Duration {
	return time.Duration(sent/volumeBytesPerSecond)*time.Second + time.Duration(sent%volumeBytesPerSecond)*time.Second/volumeBytesPerSecond
}

type VolumeTransferRequest struct {
	Schema        uint8
	Metadata      []byte
	Artifact      [32]byte
	Bytes, Offset uint64
	Prefix        [32]byte
	ExpiresAt     int64
}

func (r VolumeTransferRequest) valid() bool {
	return r.Schema == 1 && len(r.Metadata) > 0 && len(r.Metadata) <= 16<<10 && r.Artifact != ([32]byte{}) && r.Bytes >= 1024 && r.Bytes <= 1<<40 && r.Bytes%512 == 0 && r.Offset <= r.Bytes && (r.Offset == r.Bytes || r.Offset%VolumeChunkSize == 0) && r.Prefix != ([32]byte{}) && (r.Offset != 0 || r.Prefix == sha256.Sum256(nil)) && r.ExpiresAt > 0
}

// The application binds the current original job/peer/manifest/deadline and
// holds its durable artifact reference through WithFile. Authorize is checked
// at each bounded two-chunk window and before the final receipt exchange.
type VolumeSource struct {
	Lifetime  context.Context
	WithFile  func(context.Context, func(io.ReadSeeker) error) error
	Authorize func(context.Context) error
}

// WriteChunk returns only the OFFSET DURABLY SYNCED with its exact file data.
// Finish must verify the complete original artifact/profile and sync completion
// before success. The wire engine never equates a network write with this ACK.
type VolumeSink interface {
	WriteChunk(context.Context, uint64, []byte) (uint64, error)
	Finish(context.Context) error
}

func volumeChunkDigest(binding [32]byte, offset uint64, data []byte) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("mydc-volume-chunk-1\x00"))
	_, _ = h.Write(binding[:])
	var encoded [8]byte
	binary.LittleEndian.PutUint64(encoded[:], offset)
	_, _ = h.Write(encoded[:])
	_, _ = h.Write(data)
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}
func volumeOffset(offset uint64) []byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], offset)
	return b[:]
}
func volumeDeadline(ctx context.Context) time.Time {
	d := time.Now().Add(30 * time.Second)
	if end, ok := ctx.Deadline(); ok && end.Before(d) {
		d = end
	}
	return d
}
func volumeWrite(ctx context.Context, stream *quic.Stream, f Frame) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := stream.SetWriteDeadline(volumeDeadline(ctx)); err != nil {
		return err
	}
	return writeSensitiveFrame(stream, f)
}
func volumeRead(ctx context.Context, s *Session, stream *quic.Stream, request uint64) (Frame, error) {
	if err := ctx.Err(); err != nil {
		return Frame{}, err
	}
	if err := stream.SetReadDeadline(volumeDeadline(ctx)); err != nil {
		return Frame{}, err
	}
	f, err := ReadFrame(stream, (128<<10)+64)
	if err != nil {
		return Frame{}, err
	}
	if f.Purpose != VolumeTransfer || f.Request != request || s.Admit(f, VolumeTransfer, false) != nil {
		for _, v := range f.Fields {
			clear(v.Value)
		}
		return Frame{}, ErrAdmission
	}
	return f, nil
}

func (t *Transport) OnVolumeTransfer(resolve func(context.Context, *Session, VolumeTransferRequest) (VolumeSource, error)) error {
	if resolve == nil {
		return ErrAdmission
	}
	return t.On(VolumeTransfer, func(base context.Context, s *Session, stream *quic.Stream, f Frame) error {
		if f.Kind != 1 {
			return ErrFrame
		}
		binding := sha256.Sum256(f.Fields[0].Value)
		if !bytes.Equal(binding[:], f.Fields[1].Value) {
			return ErrFrame
		}
		r, err := schema.Decode[VolumeTransferRequest](f.Fields[0].Value)
		if err != nil || !r.valid() || r.ExpiresAt <= time.Now().Unix() || r.ExpiresAt-time.Now().Unix() > 86400 {
			return ErrAdmission
		}
		ctx, cancel := context.WithDeadline(base, time.Unix(r.ExpiresAt, 0))
		defer cancel()
		stop := context.AfterFunc(ctx, func() { stream.CancelRead(1); stream.CancelWrite(1) })
		defer stop()
		source, err := resolve(ctx, s, r)
		if err != nil || source.WithFile == nil || source.Authorize == nil {
			return ErrAdmission
		}
		if source.Lifetime != nil {
			stopLifetime := context.AfterFunc(source.Lifetime, cancel)
			defer stopLifetime()
		}
		return source.WithFile(ctx, func(file io.ReadSeeker) error {
			if err := source.Authorize(ctx); err != nil {
				return err
			}
			if _, err := file.Seek(0, io.SeekStart); err != nil {
				return err
			}
			h := sha256.New()
			buffer := make([]byte, VolumeChunkSize)
			defer clear(buffer)
			for left := r.Offset; left > 0; {
				if err := ctx.Err(); err != nil {
					return err
				}
				n := min(uint64(len(buffer)), left)
				if _, err := io.ReadFull(file, buffer[:n]); err != nil {
					return err
				}
				_, _ = h.Write(buffer[:n])
				left -= n
			}
			if !bytes.Equal(h.Sum(nil), r.Prefix[:]) {
				return ErrFrame
			}
			offset := r.Offset
			started := time.Now()
			var sent uint64
			for offset < r.Bytes {
				if err := source.Authorize(ctx); err != nil {
					return err
				}
				var pending [2]uint64
				count := 0
				for count < 2 && offset < r.Bytes {
					n := min(uint64(len(buffer)), r.Bytes-offset)
					if _, err := io.ReadFull(file, buffer[:n]); err != nil {
						return err
					}
					digest := volumeChunkDigest(binding, offset, buffer[:n])
					frame := Frame{Purpose: VolumeTransfer, Kind: 2, Request: f.Request, Fields: []Field{{1, true, volumeOffset(offset)}, {2, true, buffer[:n]}, {3, true, digest[:]}}}
					if err := s.Admit(frame, VolumeTransfer, false); err != nil {
						return err
					}
					if err := volumeWrite(ctx, stream, frame); err != nil {
						return err
					}
					offset += n
					sent += n
					pending[count] = offset
					count++
					wait := time.Until(started.Add(volumePacing(sent)))
					if wait > 0 {
						timer := time.NewTimer(wait)
						select {
						case <-ctx.Done():
							timer.Stop()
							return ctx.Err()
						case <-timer.C:
						}
					}
				}
				for _, end := range pending[:count] {
					ack, err := volumeRead(ctx, s, stream, f.Request)
					if err != nil {
						return err
					}
					if ack.Kind != 3 || binary.LittleEndian.Uint64(ack.Fields[0].Value) != end || !bytes.Equal(ack.Fields[1].Value, binding[:]) {
						return ErrFrame
					}
				}
			}
			if err := source.Authorize(ctx); err != nil {
				return err
			}
			end := Frame{Purpose: VolumeTransfer, Kind: 4, Request: f.Request, Fields: []Field{{1, true, volumeOffset(offset)}, {2, true, r.Artifact[:]}, {3, true, binding[:]}}}
			if err := volumeWrite(ctx, stream, end); err != nil {
				return err
			}
			ack, err := volumeRead(ctx, s, stream, f.Request)
			if err != nil {
				return err
			}
			if ack.Kind != 5 || binary.LittleEndian.Uint64(ack.Fields[0].Value) != offset || !bytes.Equal(ack.Fields[1].Value, r.Artifact[:]) || !bytes.Equal(ack.Fields[2].Value, binding[:]) {
				return ErrFrame
			}
			return source.Authorize(ctx)
		})
	})
}

// PullVolume is a fresh authenticated stream for the SAME immutable request/
// artifact and receiver checkpoint. It never invents an offset or retries a
// failed operation; its caller reopens the original durable sink explicitly.
func (s *Session) PullVolume(ctx context.Context, r VolumeTransferRequest, sink VolumeSink) error {
	if !r.valid() || sink == nil {
		return ErrAdmission
	}
	ctx, cancel := context.WithDeadline(ctx, time.Unix(r.ExpiresAt, 0))
	defer cancel()
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	binding := sha256.Sum256(body)
	request := s.transport.NextRequest()
	f := Frame{Purpose: VolumeTransfer, Kind: 1, Request: request, Fields: []Field{{1, true, body}, {2, true, binding[:]}}}
	if err = s.Admit(f, VolumeTransfer, false); err != nil {
		return err
	}
	stream, err := s.Open(ctx)
	if err != nil {
		return err
	}
	defer stream.CancelRead(0)
	defer stream.Close()
	stop := context.AfterFunc(ctx, func() { stream.CancelRead(1); stream.CancelWrite(1) })
	defer stop()
	if err = volumeWrite(ctx, stream, f); err != nil {
		return err
	}
	offset := r.Offset
	for {
		frame, err := volumeRead(ctx, s, stream, request)
		if err != nil {
			return err
		}
		if frame.Kind == 4 {
			if offset != r.Bytes || binary.LittleEndian.Uint64(frame.Fields[0].Value) != offset || !bytes.Equal(frame.Fields[1].Value, r.Artifact[:]) || !bytes.Equal(frame.Fields[2].Value, binding[:]) {
				return ErrFrame
			}
			if err = sink.Finish(ctx); err != nil {
				return err
			}
			return volumeWrite(ctx, stream, Frame{Purpose: VolumeTransfer, Kind: 5, Request: request, Fields: []Field{{1, true, volumeOffset(offset)}, {2, true, r.Artifact[:]}, {3, true, binding[:]}}})
		}
		if frame.Kind != 2 || binary.LittleEndian.Uint64(frame.Fields[0].Value) != offset {
			return ErrFrame
		}
		data := frame.Fields[1].Value
		if uint64(len(data)) != min(uint64(VolumeChunkSize), r.Bytes-offset) {
			clear(data)
			return ErrFrame
		}
		digest := volumeChunkDigest(binding, offset, data)
		if !bytes.Equal(digest[:], frame.Fields[2].Value) {
			clear(data)
			return ErrFrame
		}
		next, err := sink.WriteChunk(ctx, offset, data)
		clear(data)
		if err != nil {
			return err
		}
		if next != offset+uint64(len(data)) {
			return ErrFrame
		}
		offset = next
		if err = volumeWrite(ctx, stream, Frame{Purpose: VolumeTransfer, Kind: 3, Request: request, Fields: []Field{{1, true, volumeOffset(offset)}, {2, true, binding[:]}}}); err != nil {
			return err
		}
	}
}
