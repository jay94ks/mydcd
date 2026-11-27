// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"

	"github.com/jay94ks/seafield/pkg/sfcp/wire"
)

// CallOptions shape one request/response exchange (Call).
type CallOptions struct {
	// Reply is the kind of the reply frame; zero means 2.
	Reply uint8
	// Echo, when set, must equal the reply's field EchoTag (2 when zero),
	// the digest that binds the reply to this request.
	Echo    []byte
	EchoTag uint16
	// Admit checks the request against the peer's current policy before
	// anything is sent, for purposes whose peer must currently hold the
	// same permission.
	Admit bool
	// CloseWrite sends EOF after the request; ExpectEOF requires the peer
	// to end its side right after the reply.
	CloseWrite, ExpectEOF bool
	// Sensitive clears the encoded request after writing and the reply on
	// any failure.
	Sensitive bool
	// Management opens the stream with OpenManagement, so the call also
	// works over the Unix socket.
	Management bool
	// Sent runs right before the first byte is written. A caller tracking
	// the original request's phase marks it in flight here.
	Sent func()
}

// CallError says at which step a Call failed and whether any byte of the
// request may have reached the peer. Unsent calls are safe to retry; sent
// ones have an unknown outcome.
type CallError struct {
	Stage string
	Sent  bool
	Err   error
}

func (e *CallError) Error() string { return "SFCP call " + e.Stage + ": " + e.Err.Error() }
func (e *CallError) Unwrap() error { return e.Err }

// Call writes one request frame on a new stream and returns the one reply
// frame after checking its purpose, kind, request ID, current admission and
// optional echoed digest. The reply's body budget comes from the purpose
// table. Call never retries.
func (s *Session) Call(ctx context.Context, request Frame, o CallOptions) (Frame, error) {
	if !s.Supports(request.Purpose, request.Kind) {
		return Frame{}, ErrUnsupported
	}
	return call(ctx, request, o, caller{
		codec: codec,
		rule:  fieldRule,
		admit: func(f Frame) error { return s.Admit(f, request.Purpose, false) },
		open: func(ctx context.Context) (Stream, uint64, error) {
			var st Stream
			var err error
			if o.Management {
				st, err = s.OpenManagement(ctx)
			} else {
				st, err = s.Open(ctx)
			}
			return st, 0, err
		},
	})
}

// caller is what differs between a mesh/Unix session and the engine socket.
type caller struct {
	codec wire.Rules
	rule  func(Purpose, uint8) ([]int, int)
	admit func(Frame) error
	// open returns a new stream and, when the stream fixes the request ID
	// (engine socket, assigns), that ID; zero keeps request.Request.
	open    func(context.Context) (Stream, uint64, error)
	assigns bool
}

func call(ctx context.Context, request Frame, o CallOptions, c caller) (Frame, error) {
	sent := false
	fail := func(stage string, err error) (Frame, error) {
		return Frame{}, &CallError{Stage: stage, Sent: sent, Err: err}
	}
	reply := o.Reply
	if reply == 0 {
		reply = 2
	}
	_, budget := c.rule(request.Purpose, reply)
	if budget == 0 {
		return fail("encode", ErrFrame)
	}
	if c.assigns {
		request.Request = 1 // placeholder until the stream assigns its ID
	}
	b, err := c.codec.Encode(request)
	if err != nil {
		return fail("encode", err)
	}
	if o.Sensitive {
		defer clear(b)
	}
	if o.Admit {
		if err = c.admit(request); err != nil {
			return fail("admit", err)
		}
	}
	stream, id, err := c.open(ctx)
	if err != nil {
		return fail("open", err)
	}
	if id != 0 {
		request.Request = id
		binary.LittleEndian.PutUint64(b[12:20], id)
	}
	defer stream.CancelRead(0)
	defer stream.Close()
	stop := context.AfterFunc(ctx, func() { stream.CancelRead(1); stream.CancelWrite(1) })
	defer stop()
	if err = ctx.Err(); err != nil {
		return fail("open", err)
	}
	if o.Sent != nil {
		o.Sent()
	}
	sent = true
	if err = writeAll(stream, b); err != nil {
		return fail("send", err)
	}
	if o.CloseWrite {
		if err = stream.Close(); err != nil {
			return fail("send-eof", err)
		}
	}
	f, err := c.codec.ReadFrame(stream, budget)
	if err != nil {
		return fail("receive", err)
	}
	if f.Purpose != request.Purpose || f.Kind != reply || f.Request != request.Request || c.admit(f) != nil || o.Echo != nil && !echoes(f, o) {
		if o.Sensitive {
			clearFields(f)
		}
		return fail("validate", ErrAdmission)
	}
	if o.ExpectEOF {
		if err = streamEOFChecker(stream); err != nil {
			if o.Sensitive {
				clearFields(f)
			}
			return fail("receive-eof", err)
		}
	}
	return f, nil
}

func echoes(f Frame, o CallOptions) bool {
	tag := o.EchoTag
	if tag == 0 {
		tag = 2
	}
	for _, field := range f.Fields {
		if field.Tag == tag {
			return bytes.Equal(field.Value, o.Echo)
		}
	}
	return false
}

// CallSent reports whether err is a Call failure after the request may have
// reached the peer.
func CallSent(err error) bool {
	var c *CallError
	return errors.As(err, &c) && c.Sent
}

// CallCause returns the error a caller reports for a failed Call:
// ErrAdmission for a refused request or a reply that does not belong to it,
// the underlying transport or frame error otherwise.
func CallCause(err error) error {
	var c *CallError
	if !errors.As(err, &c) {
		return err
	}
	switch c.Stage {
	case "admit", "validate":
		return ErrAdmission
	}
	return c.Err
}

func clearFields(f Frame) {
	for _, field := range f.Fields {
		clear(field.Value)
	}
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
