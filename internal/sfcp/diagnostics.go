// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"syscall"

	quic "github.com/quic-go/quic-go"
)

// TransportErrorCause exposes a fixed category, never an error's text. Shared
// client/server classification does not change the error, delivery or retry rules.
func TransportErrorCause(err error) string {
	for _, known := range []struct {
		err  error
		name string
	}{
		{context.DeadlineExceeded, "deadline"},
		{context.Canceled, "canceled"},
		{os.ErrDeadlineExceeded, "io-deadline"},
		{ErrAdmission, "admission"},
		{ErrFrame, "frame"},
		{ErrBudget, "budget"},
		{ErrTruncated, "truncated"},
		{io.ErrUnexpectedEOF, "unexpected-eof"},
		{io.EOF, "eof"},
		{net.ErrClosed, "closed"},
	} {
		if errors.Is(err, known.err) {
			return known.name
		}
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return "timeout"
	}
	return "other"
}

func serverFailureCause(err error) string {
	// QUIC errors can unwrap to net.ErrClosed and contain peer-supplied text.
	// Recognize their types first, without printing messages or TLS records.
	var application *quic.ApplicationError
	var transport *quic.TransportError
	var stream *quic.StreamError
	var idle *quic.IdleTimeoutError
	var handshake *quic.HandshakeTimeoutError
	var reset *quic.StatelessResetError
	var certificate *tls.CertificateVerificationError
	var record tls.RecordHeaderError
	switch {
	case errors.As(err, &application):
		return "quic-application"
	case errors.As(err, &transport):
		return "quic-transport"
	case errors.As(err, &stream):
		return "quic-stream"
	case errors.As(err, &idle):
		return "quic-idle"
	case errors.As(err, &handshake):
		return "quic-handshake-timeout"
	case errors.As(err, &reset):
		return "quic-reset"
	case errors.As(err, &certificate):
		return "tls-certificate"
	case errors.As(err, &record):
		return "tls-record"
	case errors.Is(err, syscall.EPIPE):
		return "broken-pipe"
	case errors.Is(err, syscall.ECONNRESET):
		return "connection-reset"
	default:
		return TransportErrorCause(err)
	}
}

func quietQUICClose(err error) bool {
	var application *quic.ApplicationError
	var transport *quic.TransportError
	var idle *quic.IdleTimeoutError
	return errors.As(err, &application) && application.ErrorCode == 0 ||
		errors.As(err, &transport) && transport.ErrorCode == quic.NoError ||
		errors.As(err, &idle)
}

func idleUnixClose(stream *localStream, err error) bool {
	// Only an untouched exchange may end quietly. A partial record header,
	// frame or request EOF is still a failed input, including on timeout.
	if stream.readStarted {
		return false
	}
	var timeout net.Error
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.As(err, &timeout) && timeout.Timeout()
}

func (t *Transport) serverFailure(network, stage string, peer Identity, frame Frame, err error) {
	if err == nil || t.ctx.Err() != nil {
		return
	}
	if network == "unix" {
		t.mu.Lock()
		closed := t.localClosed
		t.mu.Unlock()
		if closed {
			return
		}
	}
	if stage == "accept-stream" && quietQUICClose(err) {
		return
	}
	if network == "quic" && t.starting.hold(stage, serverFailureCause(err)) {
		return
	}
	key := "unknown"
	if peer != (Identity{}) {
		key = hex.EncodeToString(peer[:])
	}
	// Every string is a local constant or fixed category; only authenticated
	// peer keys and validated frame scalars are included. Never err.Error(),
	// peer names/endpoints, fields, signatures, tickets or secret values.
	var step pathStepError
	if errors.As(err, &step) {
		stage += "/path-" + step.step
	}
	log.Printf("SFCP server failure: transport=%s stage=%s cause=%s peer=%s purpose=%d kind=%d request=%d",
		network, stage, serverFailureCause(err), key, frame.Purpose, frame.Kind, frame.Request)
}
