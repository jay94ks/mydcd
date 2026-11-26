// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/containerops"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/userauth"
)

// Container sessions (logs follow, top/stats watch, exec) over the
// ContainerSession purpose, as the CLI opens them (cmd/mydc
// container_stream.go). A Stream has its own transport and its own copy of
// the session key, so closing or logging out of the Conn that opened it
// does not cut it; it ends with its own Close.

func (c *realConn) ResolveStream(ctx context.Context, tenant string, sel ContainerSelection, spec StreamSpec) (StreamTarget, error) {
	return realCall(ctx, c, "container-resolve", func(u userauth.Client, s access.Session) (StreamTarget, error) {
		return u.ResolveContainerSession(ctx, c.peer, s, tenant, sel.Ops(), spec)
	})
}

func (c *realConn) PrepareStream(ctx context.Context, target StreamTarget, spec StreamSpec, requestID string) (SignedIntent, error) {
	const m = "container-prepare"
	s, done, err := c.open(ctx, m, true)
	if err != nil {
		return nil, err
	}
	defer done()
	if requestID == "" {
		id := make([]byte, 12)
		if _, err := rand.Read(id); err != nil {
			return nil, fail(m, CodeTransport, err.Error())
		}
		requestID = "observe-" + hex.EncodeToString(id)
		if spec.Kind == "exec" {
			requestID = "exec-" + hex.EncodeToString(id)
		}
	}
	q := SessionIntent{Schema: 1, Request: requestID, User: s.User, Session: access.ExactSessionDigest(s), At: time.Now().Unix(), Target: target, Spec: spec}
	q.Signature = ed25519.Sign(c.c.Self.Private, containerops.SessionIntentBytes(q))
	if q.Verify(s.Key) != nil {
		return nil, fail(m, CodeInvalid, "intent")
	}
	b, err := json.Marshal(q)
	if err != nil {
		return nil, fail(m, CodeInvalid, err.Error())
	}
	return b, nil
}

func (c *realConn) ExecStatus(ctx context.Context, tenant string, intent SignedIntent) (ExecStatus, error) {
	const m = "container-exec-status"
	q, err := DecodeIntent(intent)
	if err != nil || q.Target.Tenant != tenant {
		return ExecStatus{}, fail(m, CodeInvalid, "intent")
	}
	return realCall(ctx, c, m, func(u userauth.Client, s access.Session) (ExecStatus, error) {
		return u.ContainerExecStatus(ctx, c.peer, s, q)
	})
}

// OpenStream copies the session key into a stream-owned client before it
// opens the channel; the copy is wiped when the stream closes.
func (c *realConn) OpenStream(ctx context.Context, tenant string, intent SignedIntent) (Stream, error) {
	const m = "container-open"
	q, err := DecodeIntent(intent)
	if err != nil || q.Target.Tenant != tenant {
		return nil, fail(m, CodeInvalid, "intent")
	}
	s, done, err := c.open(ctx, m, true)
	if err != nil {
		return nil, err
	}
	self, err := identity.FromSeed(c.c.Self.Private.Seed())
	done()
	if err != nil {
		return nil, fail(m, CodeTransport, err.Error())
	}
	peer := c.peer
	mesh, err := mydcp.NewTransport(self, c.c.Cluster, func(key mydcp.Identity) (mydcp.Peer, bool) { return peer, key == peer.Key })
	if err != nil {
		clear(self.Private)
		return nil, fail(m, CodeTransport, err.Error())
	}
	client := userauth.Client{Cluster: c.c.Cluster, Self: self, Mesh: mesh, Peers: []mydcp.Peer{peer}}
	sctx, cancel := context.WithCancel(context.Background())
	channel, err := client.OpenContainerSession(sctx, peer, s, q, 10*time.Second)
	if err != nil {
		cancel()
		_ = mesh.Close()
		clear(self.Private)
		return nil, realError(m, err)
	}
	st := &realStream{target: q.Target, channel: channel, mesh: mesh, self: self, cancel: cancel, pinged: make(chan struct{})}
	go st.ping(sctx)
	return st, nil
}

type realStream struct {
	target  StreamTarget
	channel *userauth.ContainerChannel
	mesh    *mydcp.Transport
	self    *identity.Identity
	cancel  context.CancelFunc
	pinged  chan struct{}
	once    sync.Once
}

// ping keeps the channel alive as the CLI does: the server drops a session
// that sends nothing for a minute.
func (s *realStream) ping(ctx context.Context) {
	defer close(s.pinged)
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if s.channel.Send(StreamRecord{Kind: RecordPing}) != nil {
				return
			}
		}
	}
}

func (s *realStream) Target() StreamTarget { return s.target }

func (s *realStream) Recv(ctx context.Context) (StreamRecord, error) {
	const m = "container-stream"
	if err := ctx.Err(); err != nil {
		return StreamRecord{}, fail(m, CodeTransport, err.Error())
	}
	stop := context.AfterFunc(ctx, s.channel.StopReceive)
	defer stop()
	r, err := s.channel.Receive()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return StreamRecord{}, fail(m, CodeClosed, "connection lost")
		}
		return StreamRecord{}, fail(m, CodeClosed, err.Error())
	}
	switch r.Kind {
	case "end":
		return StreamRecord{}, io.EOF
	case "error":
		return StreamRecord{}, fail(m, Code(r.Code), "")
	}
	return r, nil
}

func (s *realStream) send(r StreamRecord) error {
	if err := s.channel.Send(r); err != nil {
		return fail("container-stream", CodeClosed, err.Error())
	}
	return nil
}

func (s *realStream) Stdin(ctx context.Context, data []byte) error {
	for len(data) > 0 {
		if err := ctx.Err(); err != nil {
			return fail("container-stream", CodeTransport, err.Error())
		}
		n := min(len(data), StreamChunkBytes)
		if err := s.send(StreamRecord{Kind: "stdin", Data: data[:n]}); err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

func (s *realStream) CloseStdin(context.Context) error {
	return s.send(StreamRecord{Kind: "stdin-eof"})
}

func (s *realStream) Resize(_ context.Context, rows, cols uint16) error {
	return s.send(StreamRecord{Kind: "resize", Rows: rows, Cols: cols})
}

func (s *realStream) Cancel(context.Context) error { return s.send(StreamRecord{Kind: "cancel"}) }

func (s *realStream) Close() error {
	s.once.Do(func() {
		s.cancel()
		<-s.pinged
		_ = s.channel.Close()
		_ = s.mesh.Close()
		clear(s.self.Private)
	})
	return nil
}
