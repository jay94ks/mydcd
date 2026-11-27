// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"bytes"
	"encoding/binary"
	"io"
)

// Bulk purposes (ImageContent, VolumeFile, ClusterBackup) carry their bytes
// as kind-4 chunk frames: field 1 the little-endian u64 offset of the chunk
// in the transfer, field 2 1..ChunkSize bytes, field 3 the request header
// digest that binds the chunk to its request.

// ChunkSize is the largest chunk payload.
const ChunkSize = 24 << 10

// WriteChunk writes one chunk frame.
func WriteChunk(w io.Writer, p Purpose, request uint64, header [32]byte, offset uint64, data []byte) error {
	if len(data) == 0 || len(data) > ChunkSize {
		return ErrFrame
	}
	var off [8]byte
	binary.LittleEndian.PutUint64(off[:], offset)
	return WriteFrame(w, Frame{Purpose: p, Kind: 4, Request: request, Fields: []Field{{Tag: 1, Required: true, Value: off[:]}, {Tag: 2, Required: true, Value: data}, {Tag: 3, Required: true, Value: header[:]}}})
}

// ChunkWriter cuts a byte stream into consecutive chunk frames. Check, when
// set, runs before each chunk (re-admission, cancellation).
type ChunkWriter struct {
	Stream  io.Writer
	Purpose Purpose
	Request uint64
	Header  [32]byte
	Offset  uint64
	Check   func() error
}

func (w *ChunkWriter) Write(p []byte) (int, error) {
	n := 0
	for len(p) > 0 {
		if w.Check != nil {
			if err := w.Check(); err != nil {
				return n, err
			}
		}
		take := min(len(p), ChunkSize)
		if err := WriteChunk(w.Stream, w.Purpose, w.Request, w.Header, w.Offset, p[:take]); err != nil {
			return n, err
		}
		w.Offset += uint64(take)
		p, n = p[take:], n+take
	}
	return n, nil
}

// Chunk returns the payload of a received chunk frame f when it is the next
// one expected: kind 4, the given header, offset equal to the bytes received
// so far and no more than remaining bytes. Purpose, request ID and admission
// are the caller's checks, as for every frame of the stream.
func Chunk(f Frame, header [32]byte, offset, remaining uint64) ([]byte, error) {
	if f.Kind != 4 || len(f.Fields) != 3 || len(f.Fields[0].Value) != 8 {
		return nil, ErrFrame
	}
	data := f.Fields[1].Value
	if binary.LittleEndian.Uint64(f.Fields[0].Value) != offset || !bytes.Equal(f.Fields[2].Value, header[:]) || len(data) == 0 || len(data) > ChunkSize || uint64(len(data)) > remaining {
		return nil, ErrFrame
	}
	return data, nil
}
