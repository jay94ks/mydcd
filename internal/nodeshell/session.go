// SPDX-License-Identifier: Apache-2.0

package nodeshell

import (
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
)

type Exit struct {
	Code   int
	Signal string
}

// Session is one SSH PTY, not a reconnectable authorization or OS process
// supervisor. Close tears down this original SSH channel/connection only.
type Session struct {
	client    *ssh.Client
	ssh       *ssh.Session
	input     io.WriteCloser
	output    *io.PipeReader
	writer    *io.PipeWriter
	done      chan struct{}
	closeOnce sync.Once
	inputMu   sync.Mutex
	inputDone bool
	stop      func() bool
	exit      Exit
	err       error
}

func (a *Adapter) hostKey() (ssh.PublicKey, error) {
	raw, err := readOwned(a.config.HostPublicKeyFile, 0644, 16<<10)
	if err != nil {
		return nil, ErrNotReady
	}
	key, _, options, rest, err := ssh.ParseAuthorizedKey(raw)
	if err != nil || len(options) != 0 || strings.TrimSpace(string(rest)) != "" || key.Type() != ssh.KeyAlgoED25519 {
		return nil, ErrNotReady
	}
	return key, nil
}

func (a *Adapter) connect(ctx context.Context) (*ssh.Client, error) {
	key, err := a.hostKey()
	if err != nil {
		return nil, err
	}
	signer, err := a.signer(false)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", a.config.Endpoint)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline := time.Now().Add(10 * time.Second)
	if parent, ok := ctx.Deadline(); ok && parent.Before(deadline) {
		deadline = parent
	}
	if err := conn.SetDeadline(deadline); err != nil {
		_ = conn.Close()
		return nil, err
	}
	config := &ssh.ClientConfig{User: Account, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyAlgorithms: []string{ssh.KeyAlgoED25519}, HostKeyCallback: func(_ string, _ net.Addr, actual ssh.PublicKey) error {
		if subtle.ConstantTimeCompare(key.Marshal(), actual.Marshal()) != 1 {
			return ErrNotReady
		}
		return nil
	}}
	channel, channels, requests, err := ssh.NewClientConn(conn, a.config.Endpoint, config)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil || ctx.Err() != nil {
		_ = channel.Close()
		return nil, ErrNotReady
	}
	return ssh.NewClient(channel, channels, requests), nil
}

func shellUser(value string) bool {
	if value == "" || len(value) > 128 || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func (a *Adapter) Open(ctx context.Context, cols, rows uint16, mydcUser string) (*Session, error) {
	if cols == 0 || rows == 0 || !shellUser(mydcUser) || ctx.Err() != nil {
		return nil, ErrSession
	}
	a.mu.Lock()
	ready := a.ready.Ready
	a.mu.Unlock()
	if !ready {
		return nil, ErrNotReady
	}
	if err := a.checkAccountIdentity(); err != nil {
		return nil, ErrNotReady
	}
	client, err := a.connect(ctx)
	if err != nil {
		return nil, err
	}
	opening := context.AfterFunc(ctx, func() { _ = client.Close() })
	channel, err := client.NewSession()
	if err != nil {
		opening()
		_ = client.Close()
		return nil, err
	}
	output, writer := io.Pipe()
	session := &Session{client: client, ssh: channel, output: output, writer: writer, done: make(chan struct{})}
	session.stop = context.AfterFunc(ctx, func() {
		_ = client.Close()
		// Ending our output writer exposes EOF to the stream consumer. Closing
		// its reader instead would report ErrClosedPipe and hide the actual
		// SSH completion that the consumer must still collect with Wait.
		_ = writer.Close()
	})
	opening()
	channel.Stdout, channel.Stderr = writer, writer
	session.input, err = channel.StdinPipe()
	if err == nil {
		err = channel.RequestPty("xterm-256color", int(rows), int(cols), ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 38400, ssh.TTY_OP_OSPEED: 38400})
	}
	if err == nil {
		// SSH Setenv depends on the operator's AcceptEnv configuration and
		// may silently fail to provide attribution. A fixed command exports a
		// single safely quoted value before the dedicated account's shell.
		err = channel.Start("export MYDC_USER=" + shellQuote(mydcUser) + "; exec /bin/sh -l")
	}
	if err != nil {
		_ = session.Close()
		return nil, err
	}
	go func() {
		err := channel.Wait()
		exit := Exit{}
		if err != nil {
			exit.Code = 255
			var status *ssh.ExitError
			if errors.As(err, &status) {
				exit.Code, exit.Signal = status.ExitStatus(), status.Signal()
				if exit.Code < 0 {
					exit.Code = 255
				}
			}
		}
		session.exit, session.err = exit, err
		_ = writer.Close()
		session.stop()
		_ = client.Close()
		close(session.done)
	}()
	return session, nil
}

func (s *Session) Read(p []byte) (int, error) { return s.output.Read(p) }

func (s *Session) Write(p []byte) (int, error) {
	s.inputMu.Lock()
	defer s.inputMu.Unlock()
	if s.inputDone {
		return 0, io.ErrClosedPipe
	}
	return s.input.Write(p)
}

func (s *Session) CloseWrite() error {
	s.inputMu.Lock()
	defer s.inputMu.Unlock()
	if s.inputDone {
		return nil
	}
	s.inputDone = true
	if s.input == nil {
		return nil
	}
	return s.input.Close()
}

func (s *Session) Resize(cols, rows uint16) error {
	if cols == 0 || rows == 0 {
		return ErrSession
	}
	return s.ssh.WindowChange(int(rows), int(cols))
}

func (s *Session) Wait() (Exit, error) {
	<-s.done
	return s.exit, s.err
}

func (s *Session) Close() error {
	s.closeOnce.Do(func() {
		if s.stop != nil {
			s.stop()
		}
		// Close the underlying connection first: a blocked SSH stdin write
		// cannot hold teardown behind its input mutex.
		_ = s.client.Close()
		_ = s.ssh.Close()
		_ = s.CloseWrite()
		// Close is a local stream end, not an SSH exit result. Unblock Read
		// with EOF; only the goroutine collecting ssh.Wait completes done.
		_ = s.writer.Close()
	})
	return nil
}

var _ io.ReadWriteCloser = (*Session)(nil)
