// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"bytes"
	"context"
	"crypto/sha256"

	"github.com/quic-go/quic-go"
)

// VolumeFSData is the largest data part of one VolumeFS frame: one FUSE
// read or write.
const VolumeFSData = 128 << 10

// volumeFSDataTag is the optional data extension (tags >= 128 are optional).
const volumeFSDataTag = 128

// VolumeFSHandler answers one VolumeFS operation. header is the request
// JSON, data the optional write payload; the reply is JSON plus optional
// read data. An error refuses the operation without a reply.
type VolumeFSHandler func(ctx context.Context, s *Session, header, data []byte) (reply, replyData []byte, err error)

// OnVolumeFS serves VolumeFS. Only cluster members are admitted; the
// handler checks the share binding.
func (t *Transport) OnVolumeFS(handler VolumeFSHandler) error {
	if handler == nil {
		return ErrAdmission
	}
	return t.On(VolumeFS, func(ctx context.Context, s *Session, stream *quic.Stream, f Frame) error {
		if f.Kind != 1 {
			return ErrFrame
		}
		digest := sha256.Sum256(f.Fields[0].Value)
		if !bytes.Equal(digest[:], f.Fields[1].Value) {
			return ErrFrame
		}
		data, err := volumeFSData(f)
		if err != nil {
			return err
		}
		reply, out, err := handler(ctx, s, f.Fields[0].Value, data)
		if err != nil {
			return ErrAdmission
		}
		if len(out) > VolumeFSData {
			return ErrFrame
		}
		if err = s.Admit(f, VolumeFS, false); err != nil {
			return err
		}
		return WriteFrame(stream, volumeFSFrame(2, f.Request, reply, digest[:], out))
	})
}

// CallVolumeFS sends one operation and returns its reply and data. Use
// CallSent on the error to tell an operation that never left from one whose
// outcome is unknown.
func (s *Session) CallVolumeFS(ctx context.Context, header, data []byte) (reply, replyData []byte, err error) {
	if len(data) > VolumeFSData {
		return nil, nil, ErrFrame
	}
	digest := sha256.Sum256(header)
	f, err := s.Call(ctx, volumeFSFrame(1, s.transport.NextRequest(), header, digest[:], data), CallOptions{Admit: true, CloseWrite: true, Echo: digest[:]})
	if err != nil {
		return nil, nil, err
	}
	out, err := volumeFSData(f)
	if err != nil {
		return nil, nil, &CallError{Stage: "validate", Sent: true, Err: err}
	}
	return f.Fields[0].Value, out, nil
}

func volumeFSFrame(kind uint8, request uint64, header, digest, data []byte) Frame {
	f := Frame{Purpose: VolumeFS, Kind: kind, Request: request, Fields: []Field{{Tag: 1, Required: true, Value: header}, {Tag: 2, Required: true, Value: digest}}}
	if len(data) > 0 {
		f.Fields = append(f.Fields, Field{Tag: volumeFSDataTag, Value: data})
	}
	return f
}

func volumeFSData(f Frame) ([]byte, error) {
	var data []byte
	for _, field := range f.Fields[2:] {
		if field.Tag != volumeFSDataTag || data != nil || len(field.Value) > VolumeFSData {
			return nil, ErrFrame
		}
		data = field.Value
	}
	return data, nil
}
