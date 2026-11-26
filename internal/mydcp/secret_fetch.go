// SPDX-License-Identifier: Apache-2.0

package mydcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"

	"github.com/quic-go/quic-go"
)

// SecretFetch is a dedicated member-to-member sensitive read. There is no
// relay, datagram, early-data or management-envelope fallback.
func (t *Transport) OnSecretFetch(handler func(context.Context, *Session, []byte) ([]byte, error)) error {
	if handler == nil {
		return ErrAdmission
	}
	return t.On(SecretFetch, func(ctx context.Context, s *Session, stream *quic.Stream, f Frame) error {
		defer clear(f.Fields[0].Value)
		if f.Kind != 1 {
			return ErrFrame
		}
		digest := sha256.Sum256(f.Fields[0].Value)
		if !bytes.Equal(digest[:], f.Fields[1].Value) {
			return ErrFrame
		}
		body, err := handler(ctx, s, f.Fields[0].Value)
		defer clear(body)
		if err != nil {
			return ErrAdmission
		}
		if err = s.Admit(f, SecretFetch, false); err != nil {
			return err
		}
		return writeSensitiveFrame(stream, Frame{Purpose: SecretFetch, Kind: 2, Request: f.Request, Fields: []Field{{1, true, body}, {2, true, digest[:]}}})
	})
}
func writeSensitiveFrame(w io.Writer, f Frame) error {
	b, err := Encode(f)
	if err != nil {
		return err
	}
	defer clear(b)
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
		b = b[n:]
	}
	return nil
}

// FetchSecret returns private response bytes owned by the caller, which must
// clear them after consuming them. Only the public request digest is echoed.
func (s *Session) FetchSecret(ctx context.Context, body []byte) ([]byte, error) {
	digest := sha256.Sum256(body)
	f := Frame{Purpose: SecretFetch, Kind: 1, Request: s.transport.NextRequest(), Fields: []Field{{1, true, body}, {2, true, digest[:]}}}
	if err := s.Admit(f, SecretFetch, false); err != nil {
		return nil, err
	}
	stream, err := s.Open(ctx)
	if err != nil {
		return nil, err
	}
	defer stream.CancelRead(0)
	defer stream.Close()
	stop := context.AfterFunc(ctx, func() { stream.CancelRead(1); stream.CancelWrite(1) })
	defer stop()
	if err = writeSensitiveFrame(stream, f); err != nil {
		return nil, err
	}
	ack, err := ReadFrame(stream, 128<<10)
	if err != nil {
		return nil, err
	}
	if ack.Purpose != SecretFetch || ack.Kind != 2 || ack.Request != f.Request || s.Admit(ack, SecretFetch, false) != nil || !bytes.Equal(ack.Fields[1].Value, digest[:]) {
		for _, field := range ack.Fields {
			clear(field.Value)
		}
		return nil, ErrAdmission
	}
	return ack.Fields[0].Value, nil
}
