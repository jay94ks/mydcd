// SPDX-License-Identifier: Apache-2.0

package mydcp

import (
	"bytes"
	"context"
	"crypto/sha256"

	"github.com/quic-go/quic-go"
)

// CertificateMaterial is exclusively member-to-member certificate key input.
// It shares sensitive frame encoding with SecretFetch, never its Secret grant
// authorization, user path, relay or ordinary management response encoding.
func (t *Transport) OnCertificateMaterial(handler func(context.Context, *Session, []byte) ([]byte, error)) error {
	if handler == nil {
		return ErrAdmission
	}
	return t.On(CertificateMaterial, func(ctx context.Context, s *Session, stream *quic.Stream, f Frame) error {
		defer clear(f.Fields[0].Value)
		if f.Kind != 1 {
			return ErrFrame
		}
		digest := sha256.Sum256(f.Fields[0].Value)
		if !bytes.Equal(digest[:], f.Fields[1].Value) {
			return ErrFrame
		}
		if err := streamEOFChecker(stream); err != nil {
			return err
		}
		body, err := handler(ctx, s, f.Fields[0].Value)
		defer clear(body)
		if err != nil {
			return ErrAdmission
		}
		if err = s.Admit(f, CertificateMaterial, false); err != nil {
			return err
		}
		return writeSensitiveFrame(stream, Frame{Purpose: CertificateMaterial, Kind: 2, Request: f.Request, Fields: []Field{{1, true, body}, {2, true, digest[:]}}})
	})
}
func (s *Session) FetchCertificateMaterial(ctx context.Context, body []byte) ([]byte, error) {
	digest := sha256.Sum256(body)
	f := Frame{Purpose: CertificateMaterial, Kind: 1, Request: s.transport.NextRequest(), Fields: []Field{{1, true, body}, {2, true, digest[:]}}}
	if err := s.Admit(f, CertificateMaterial, false); err != nil {
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
	if err = stream.Close(); err != nil {
		return nil, err
	}
	ack, err := ReadFrame(stream, 64<<10)
	if err != nil {
		return nil, err
	}
	if ack.Purpose != CertificateMaterial || ack.Kind != 2 || ack.Request != f.Request || s.Admit(ack, CertificateMaterial, false) != nil || !bytes.Equal(ack.Fields[1].Value, digest[:]) {
		for _, field := range ack.Fields {
			clear(field.Value)
		}
		return nil, ErrAdmission
	}
	if err = streamEOFChecker(stream); err != nil {
		for _, field := range ack.Fields {
			clear(field.Value)
		}
		return nil, err
	}
	return ack.Fields[0].Value, nil
}
