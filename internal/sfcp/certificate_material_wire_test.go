// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// Actual member QUIC/frame/EOF. The key provider is injected; this does not
// establish the Runtime's current ingress authorization or durable holder DB.
func TestCertificateMaterialActualQUICRequiresInputAndOutputEOF(t *testing.T) {
	body := []byte(`{"Schema":1}`)
	t.Run("complete", func(t *testing.T) {
		var calls atomic.Int32
		session, _ := checkerProbeWirePair(t, func(server *Transport) error {
			return server.OnCertificateMaterial(func(_ context.Context, _ *Session, input []byte) ([]byte, error) {
				if !bytes.Equal(input, body) {
					return nil, ErrFrame
				}
				calls.Add(1)
				return []byte("protected material"), nil
			})
		})
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		got, err := session.FetchCertificateMaterial(ctx, body)
		defer clear(got)
		if err != nil || !bytes.Equal(got, []byte("protected material")) || calls.Load() != 1 {
			t.Fatal("finite read did not finish", err, calls.Load())
		}
	})
	t.Run("request-trailing", func(t *testing.T) {
		var calls atomic.Int32
		session, _ := checkerProbeWirePair(t, func(server *Transport) error {
			return server.OnCertificateMaterial(func(_ context.Context, _ *Session, _ []byte) ([]byte, error) {
				calls.Add(1)
				return []byte("never release"), nil
			})
		})
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		stream, err := session.Open(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer stream.CancelRead(0)
		defer stream.Close()
		digest := sha256.Sum256(body)
		if err = writeSensitiveFrame(stream, Frame{Purpose: CertificateMaterial, Kind: 1, Request: 1, Fields: []Field{{Tag: 1, Required: true, Value: body}, {Tag: 2, Required: true, Value: digest[:]}}}); err != nil {
			t.Fatal(err)
		}
		if _, err = stream.Write([]byte{1}); err != nil {
			t.Fatal(err)
		}
		if err = stream.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err = ReadFrame(stream, 64<<10); err == nil {
			t.Fatal("trailing input received private response")
		}
		if calls.Load() != 0 {
			t.Fatal("provider invoked before original EOF")
		}
	})
	t.Run("response-trailing", func(t *testing.T) {
		session, _ := checkerProbeWirePair(t, func(server *Transport) error {
			return server.On(CertificateMaterial, func(_ context.Context, _ *Session, stream *quic.Stream, f Frame) error {
				if err := streamEOFChecker(stream); err != nil {
					return err
				}
				if err := writeSensitiveFrame(stream, Frame{Purpose: CertificateMaterial, Kind: 2, Request: f.Request, Fields: []Field{{Tag: 1, Required: true, Value: []byte("unclosed material")}, {Tag: 2, Required: true, Value: f.Fields[1].Value}}}); err != nil {
					return err
				}
				_, err := stream.Write([]byte{1})
				return err
			})
		})
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		got, err := session.FetchCertificateMaterial(ctx, body)
		defer clear(got)
		if err == nil || len(got) != 0 {
			t.Fatal("unclosed private response accepted", err)
		}
	})
}
