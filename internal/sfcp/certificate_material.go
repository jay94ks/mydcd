// SPDX-License-Identifier: Apache-2.0

package sfcp

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
	return t.onSensitive(CertificateMaterial, handler)
}
func (s *Session) FetchCertificateMaterial(ctx context.Context, body []byte) ([]byte, error) {
	return s.callSensitive(ctx, CertificateMaterial, body)
}

// onSensitive serves one member-only request/response purpose whose bodies
// may carry private bytes: kind 1 asks, kind 2 answers, each with the
// SHA-256 of the request body, and nothing is relayed.
func (t *Transport) onSensitive(p Purpose, handler func(context.Context, *Session, []byte) ([]byte, error)) error {
	if handler == nil {
		return ErrAdmission
	}
	return t.On(p, func(ctx context.Context, s *Session, stream *quic.Stream, f Frame) error {
		defer clear(f.Fields[0].Value)
		if f.Kind != KindRequest {
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
		if err = s.Admit(f, p, false); err != nil {
			return err
		}
		return writeSensitiveFrame(stream, Frame{Purpose: p, Kind: KindResponse, Request: f.Request, Fields: []Field{{Tag: 1, Required: true, Value: body}, {Tag: 2, Required: true, Value: digest[:]}}})
	})
}
func (s *Session) callSensitive(ctx context.Context, p Purpose, body []byte) ([]byte, error) {
	digest := sha256.Sum256(body)
	f := Frame{Purpose: p, Kind: KindRequest, Request: s.transport.NextRequest(), Fields: []Field{{Tag: 1, Required: true, Value: body}, {Tag: 2, Required: true, Value: digest[:]}}}
	reply, err := s.Call(ctx, f, CallOptions{Admit: true, Sensitive: true, CloseWrite: true, ExpectEOF: true, Echo: digest[:]})
	if err != nil {
		return nil, CallCause(err)
	}
	return reply.Fields[0].Value, nil
}
