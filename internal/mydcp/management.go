// SPDX-License-Identifier: Apache-2.0

package mydcp

import (
	"context"
	"io"
	"net"
	"strconv"
	"time"

	quic "github.com/quic-go/quic-go"
)

// Stream is the management I/O contract. Close ends the write direction only;
// CancelRead/CancelWrite terminate their direction. An app-plan sender can thus
// send EOF and still read the original result over either QUIC or Unix TLS.
type Stream interface {
	io.ReadWriteCloser
	SetDeadline(time.Time) error
	CancelRead(quic.StreamErrorCode)
	CancelWrite(quic.StreamErrorCode)
}

type ManagementHandler func(context.Context, *Session, Stream, Frame) error

func localPurpose(p Purpose) bool {
	return p == NodeShell || p == User || p == SecretInput || p == ContainerSession || p == ImageContent || p == VolumeFile
}

// DuplexStream adds per-direction deadlines only where long-lived sessions
// need them. Ordinary RPC/test stream implementations retain Stream unchanged.
type DuplexStream interface {
	Stream
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

// OnManagement connects ONE handler to both transport adapters. Registration
// never extends node replication, relay, snapshot or packet access to Unix.
func (t *Transport) OnManagement(p Purpose, h ManagementHandler) error {
	if !localPurpose(p) || h == nil {
		return ErrAdmission
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.handlers[p] != nil {
		return ErrAdmission
	}
	t.managementHandlers[p] = h
	t.handlers[p] = func(ctx context.Context, s *Session, stream *quic.Stream, f Frame) error {
		return h(ctx, s, stream, f)
	}
	return nil
}

func (s *Session) OpenManagement(ctx context.Context) (Stream, error) {
	if s.local == nil {
		return s.Open(ctx)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case s.local.active <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.local.done:
		return nil, net.ErrClosed
	}
	s.transport.mu.Lock()
	now := time.Now()
	if s.local.closed.Load() || !now.Before(s.local.reuseUntil) {
		s.local.closed.Store(true)
		s.transport.mu.Unlock()
		_ = s.local.finish()
		<-s.local.active
		return nil, net.ErrClosed
	}
	s.local.reuseUntil = now.Add(localManagementTimeout)
	s.transport.mu.Unlock()
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(10 * time.Second)
	}
	if err := s.local.conn.SetDeadline(deadline); err != nil {
		_ = s.local.finish()
		<-s.local.active
		return nil, err
	}
	return &localStream{connection: s.local, release: func() { <-s.local.active }}, nil
}

// OpenContainerStream claims a dedicated local connection even for a finite
// resolve/status exchange. The server closes purpose15 connections after the
// exchange; they must not remain in the ordinary reusable Unix RPC cache.
// QUIC retains its normal per-stream ownership and connection multiplexing.
func (s *Session) OpenContainerStream(ctx context.Context) (Stream, error) {
	return s.openDedicatedStream(ctx)
}

// OpenImageContentStream shares the finite transfer connection ownership.
func (s *Session) OpenImageContentStream(ctx context.Context) (Stream, error) {
	return s.openDedicatedStream(ctx)
}

func (s *Session) openDedicatedStream(ctx context.Context) (Stream, error) {
	stream, err := s.OpenManagement(ctx)
	if err != nil || s.local == nil {
		return stream, err
	}
	local := stream.(*localStream)
	local.disposable = true
	s.transport.mu.Lock()
	if s.transport.localSessions[s.peer.Key] == s {
		delete(s.transport.localSessions, s.peer.Key)
	}
	s.transport.mu.Unlock()
	return stream, nil
}

// CredentialSource is a native rate-limit identity, never an authorization.
// Unix uses the kernel peer UID, so rotating TLS keys cannot rotate this budget.
// A UID, including root, still needs the same user credentials and session proof.
func (s *Session) CredentialSource() (string, error) {
	if s.local != nil {
		return "unix-uid:" + strconv.FormatUint(uint64(s.local.uid), 10), nil
	}
	host, _, err := net.SplitHostPort(s.RemoteAddr().String())
	return host, err
}

func (s *Session) OpenVolumeFileStream(ctx context.Context) (Stream, error) {
	return s.openDedicatedStream(ctx)
}
