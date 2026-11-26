// SPDX-License-Identifier: Apache-2.0

package mydcp

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
)

const diagnosticPrivate = "PRIVATE-password-token-signature-endpoint\nforged-event"

type failureLog struct {
	mu      sync.Mutex
	data    bytes.Buffer
	changed chan struct{}
}

func captureFailures(t *testing.T) *failureLog {
	t.Helper()
	w := &failureLog{changed: make(chan struct{}, 1)}
	previous := log.Writer()
	log.SetOutput(w)
	t.Cleanup(func() { log.SetOutput(previous) })
	return w
}
func (w *failureLog) Write(p []byte) (int, error) {
	w.mu.Lock()
	n, err := w.data.Write(p)
	w.mu.Unlock()
	select {
	case w.changed <- struct{}{}:
	default:
	}
	return n, err
}
func (w *failureLog) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.data.String()
}
func (w *failureLog) wait(t *testing.T, ctx context.Context, want string) string {
	t.Helper()
	for {
		if text := w.String(); strings.Contains(text, want) {
			return text
		}
		select {
		case <-w.changed:
		case <-ctx.Done():
			t.Fatalf("missing diagnostic %q; logs=%s", want, w.String())
		}
	}
}

func TestServerFailureSafeCategoriesAndQuietClosure(t *testing.T) {
	w := captureFailures(t)
	server, client, _, _ := u0UnixPair(t)
	frame := u0UserFrame(91, []byte(diagnosticPrivate))
	for _, tc := range []struct {
		err   error
		cause string
	}{
		{context.DeadlineExceeded, "deadline"}, {context.Canceled, "canceled"},
		{os.ErrDeadlineExceeded, "io-deadline"}, {ErrFrame, "frame"},
		{ErrAdmission, "admission"}, {ErrBudget, "budget"},
		{ErrTruncated, "truncated"}, {io.ErrUnexpectedEOF, "unexpected-eof"},
		{io.EOF, "eof"}, {net.ErrClosed, "closed"},
		{syscall.EPIPE, "broken-pipe"}, {syscall.ECONNRESET, "connection-reset"},
		{&quic.ApplicationError{ErrorCode: 7, ErrorMessage: diagnosticPrivate}, "quic-application"},
		{&quic.TransportError{ErrorCode: quic.InternalError, ErrorMessage: diagnosticPrivate}, "quic-transport"},
		{&quic.StreamError{ErrorCode: 5}, "quic-stream"},
		{&quic.IdleTimeoutError{}, "quic-idle"},
		{&quic.HandshakeTimeoutError{}, "quic-handshake-timeout"},
		{&quic.StatelessResetError{}, "quic-reset"},
		{&tls.CertificateVerificationError{Err: errors.New(diagnosticPrivate)}, "tls-certificate"},
		{tls.RecordHeaderError{Msg: diagnosticPrivate}, "tls-record"},
		{errors.New(diagnosticPrivate), "other"},
	} {
		err := fmt.Errorf("%s: %w", diagnosticPrivate, tc.err)
		if got := serverFailureCause(err); got != tc.cause {
			t.Fatalf("cause=%s want=%s", got, tc.cause)
		}
		server.serverFailure("quic", "handler", client.LocalKey(), frame, err)
	}
	text := w.String()
	if strings.Contains(text, "PRIVATE") || strings.Contains(text, "forged-event") ||
		!strings.Contains(text, fmt.Sprintf("peer=%x purpose=8 kind=1 request=91", client.LocalKey())) {
		t.Fatal("unsafe or incomplete log", text)
	}
	before := text
	for _, err := range []error{&quic.ApplicationError{}, &quic.TransportError{}, &quic.IdleTimeoutError{}} {
		server.serverFailure("quic", "accept-stream", client.LocalKey(), Frame{}, err)
	}
	if w.String() != before {
		t.Fatal("normal QUIC close logged as a failure")
	}
	// An EOF during an admitted request is not a normal connection close.
	server.serverFailure("quic", "handler", client.LocalKey(), frame, io.EOF)
	if w.String() == before {
		t.Fatal("handler EOF was suppressed")
	}
	before = w.String()
	server.cancel()
	server.serverFailure("quic", "accept-stream", client.LocalKey(), frame, context.Canceled)
	server.serverFailure("unix", "handler", client.LocalKey(), frame, context.Canceled)
	if w.String() != before {
		t.Fatal("transport shutdown produced failure logs")
	}
}

func TestServerFailureUnixPartialRecordIsNotIdle(t *testing.T) {
	for _, err := range []error{io.EOF, io.ErrUnexpectedEOF, os.ErrDeadlineExceeded} {
		if !idleUnixClose(&localStream{}, err) || idleUnixClose(&localStream{readStarted: true}, err) {
			t.Fatal("idle/partial input distinction lost", err)
		}
	}
	w := captureFailures(t)
	server, client, peer, path := u0UnixPair(t)
	if err := server.ListenUnix(path); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := client.Dial(ctx, peer)
	if err != nil {
		t.Fatal(err)
	}
	// One byte of a record header followed by native close must be reported.
	if _, err := s.local.conn.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	w.wait(t, ctx, "transport=unix stage=receive cause=unexpected-eof")
}

func TestServerFailureActualUnixAndQUIC(t *testing.T) {
	// Own only short temp Unix paths, ephemeral TLS identities, transports and
	// loopback UDP sockets. Cleanup closes/Waits both; no existing system state.
	for _, network := range []string{"unix", "quic"} {
		for _, scenario := range []string{"success", "handler", "secret-handler", "admit", "capacity", "dispatch", "frame", "authenticate", "extra-eof"} {
			if scenario == "extra-eof" && network != "unix" {
				continue // QUIC stream completion keeps its existing handler contract.
			}
			t.Run(network+"/"+scenario, func(t *testing.T) {
				w := captureFailures(t)
				server, client, peer, path := u0UnixPair(t)
				ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
				defer cancel()
				var denied atomic.Bool
				server.purposeLookup = func(key Identity, purpose Purpose) (Peer, bool) {
					if denied.Load() && purpose == User {
						return Peer{}, false
					}
					return server.lookup(key)
				}
				purpose := User
				if scenario == "secret-handler" {
					purpose = SecretInput
				}
				if scenario != "dispatch" {
					if err := server.OnManagement(purpose, func(_ context.Context, _ *Session, stream Stream, frame Frame) error {
						switch scenario {
						case "handler":
							return fmt.Errorf("%s: %w", diagnosticPrivate, syscall.EPIPE)
						case "secret-handler":
							return errors.New(diagnosticPrivate)
						case "extra-eof":
							return nil
						case "success":
							if n, err := io.Copy(io.Discard, stream); err != nil || n != 0 {
								return ErrFrame
							}
							frame.Kind = 2
							return WriteFrame(stream, frame)
						default:
							t.Error("rejected input reached handler")
							return ErrAdmission
						}
					}); err != nil {
						t.Fatal(err)
					}
				}
				if scenario == "capacity" {
					for len(server.limits[User]) < cap(server.limits[User]) {
						server.limits[User] <- struct{}{}
					}
				}
				if network == "unix" {
					if err := server.ListenUnix(path); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := server.Listen("127.0.0.1:0"); err != nil {
						t.Fatal(err)
					}
					peer.Endpoint = server.Addr().String()
					lookup := client.lookup
					client.lookup = func(key Identity) (Peer, bool) {
						if key == peer.Key {
							return peer, true
						}
						return lookup(key)
					}
				}
				if scenario == "authenticate" {
					client.cluster = [32]byte{18}
				}
				s, err := client.Dial(ctx, peer)
				if scenario == "authenticate" {
					if err == nil {
						t.Fatal("cross-cluster authentication succeeded")
					}
					w.wait(t, ctx, "transport="+network+" stage=authenticate cause=admission peer=unknown")
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if scenario == "admit" {
					denied.Store(true)
				}
				stream, err := s.OpenManagement(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer stream.CancelRead(0)
				frame := u0UserFrame(42, []byte(diagnosticPrivate))
				frame.Purpose = purpose
				if scenario == "frame" {
					_, err = stream.Write(bytes.Repeat([]byte{'x'}, HeaderSize))
				} else {
					err = WriteFrame(stream, frame)
				}
				if err != nil {
					t.Fatal(err)
				}
				if scenario == "extra-eof" {
					_, _ = stream.Write([]byte{1})
				}
				_ = stream.Close()
				reply, replyErr := ReadFrame(stream, MaxBody)
				if scenario == "success" {
					if replyErr != nil || reply.Request != frame.Request || reply.Kind != 2 {
						t.Fatal("valid exchange changed", replyErr)
					}
					if n, err := io.Copy(io.Discard, stream); err != nil || n != 0 {
						t.Fatal("response EOF changed", err)
					}
					var accepted *localConnection
					if network == "unix" {
						server.mu.Lock()
						for connection := range server.localConnections {
							accepted = connection
						}
						server.mu.Unlock()
					}
					_ = client.Close()
					if accepted != nil {
						select {
						case <-accepted.done:
						case <-ctx.Done():
							t.Fatal("server did not finish normally closed connection")
						}
					}
					_ = server.Close()
					if strings.Contains(w.String(), "MYDCP server failure:") {
						t.Fatal("valid exchange/shutdown logged as failure", w.String())
					}
					return
				}
				if replyErr == nil {
					t.Fatal("failed request returned a success frame")
				}
				stage, cause := scenario, "admission"
				switch scenario {
				case "handler":
					cause = "broken-pipe"
				case "secret-handler":
					stage, cause = "handler", "other"
				case "capacity":
					cause = "budget"
				case "frame":
					stage, cause = "receive", "frame"
				case "extra-eof":
					stage, cause = "receive-eof", "frame"
				}
				want := "transport=" + network + " stage=" + stage + " cause=" + cause
				text := w.wait(t, ctx, want)
				if strings.Contains(text, "PRIVATE") || strings.Contains(text, "forged-event") || strings.Contains(text, path) {
					t.Fatal("private data leaked", text)
				}
				if scenario != "frame" && !strings.Contains(text, fmt.Sprintf("peer=%x purpose=%d kind=1 request=42", client.LocalKey(), purpose)) {
					t.Fatal("original wire identity lost", text)
				}
			})
		}
	}
}

func TestServerFailureUnixTLSAndPublicDiscovery(t *testing.T) {
	w := captureFailures(t)
	server, _, _, path := u0UnixPair(t)
	if err := server.EnableDiscovery("server"); err != nil {
		t.Fatal(err)
	}
	if err := server.ListenUnix(path); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := Discover(ctx, "unix", path); err != nil {
		t.Fatal(err)
	}
	// Discovery uses a special successful return from authenticateLocal; it
	// must not be misreported as an authentication rejection.
	if strings.Contains(w.String(), "MYDCP server failure:") {
		t.Fatal("successful discovery reported as failure", w.String())
	}
	raw, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Write([]byte("BAD!!" + diagnosticPrivate)); err != nil {
		t.Fatal(err)
	}
	text := w.wait(t, ctx, "transport=unix stage=tls-handshake cause=tls-record peer=unknown")
	if strings.Contains(text, "PRIVATE") || strings.Contains(text, "BAD!!") || strings.Contains(text, path) {
		t.Fatal("TLS error leaked record/endpoint", text)
	}
}
