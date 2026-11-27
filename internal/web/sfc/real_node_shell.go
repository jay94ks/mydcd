// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"context"
	"io"
	"sync"

	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
)

// OpenNodeShell opens sfcd's node-shell channel for an open-node-shell
// original the server has already submitted (W1.2 step 2e). Like a container
// stream it runs on a copy of the session key and its own transport, wiped
// when the shell closes. Keys and screen bytes pass through and are never
// kept or logged here.
func (c *realConn) OpenNodeShell(ctx context.Context, op SignedOp) (NodeShell, error) {
	const m = "node-shell"
	o, err := DecodeOperation(op)
	if err != nil || o.Change.Action != ActionOpenNodeShell {
		return nil, fail(m, CodeInvalid, "open-node-shell original")
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
	mesh, err := sfcp.NewTransport(self, c.c.Cluster, func(key sfcp.Identity) (sfcp.Peer, bool) { return peer, key == peer.Key })
	if err != nil {
		clear(self.Private)
		return nil, fail(m, CodeTransport, err.Error())
	}
	client := userauth.Client{Cluster: c.c.Cluster, Self: self, Mesh: mesh, Peers: []sfcp.Peer{peer}}
	// The channel lives as long as the shell, not as long as ctx (the
	// server's short call context for the open): ctx only bounds the open.
	life, end := context.WithCancel(context.WithoutCancel(ctx))
	opening := context.AfterFunc(ctx, end)
	channel, session, err := client.OpenNodeShell(life, peer, s, o.RequestID)
	if !opening() && err == nil {
		_ = channel.Close()
		err = ctx.Err()
	}
	if err != nil {
		end()
		_ = mesh.Close()
		clear(self.Private)
		return nil, realError(m, err)
	}
	return &realShell{session: session, channel: channel, mesh: mesh, self: self, end: end}, nil
}

type realShell struct {
	session NodeShellSession
	channel *userauth.NodeShellChannel
	mesh    *sfcp.Transport
	self    *identity.Identity
	end     context.CancelFunc // ends the channel's life (OpenNodeShell)
	mu      sync.Mutex
	exit    *NodeShellEnd
	once    sync.Once
}

func (s *realShell) Session() NodeShellSession { return s.session }

// Recv skips sfcd's pings. A cancelled ctx stops the reader for good, as the
// server only cancels it when the shell's page goes away.
func (s *realShell) Recv(ctx context.Context) ([]byte, error) {
	stop := context.AfterFunc(ctx, s.channel.StopReceive)
	defer stop()
	for {
		r, err := s.channel.Receive()
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, realError("node-shell", err)
		}
		switch r.Kind {
		case "stdout":
			return r.Data, nil
		case "end":
			end := NodeShellEnd{Code: r.End.Code, Reason: r.End.Reason}
			if by := r.End.ClosedBy; by != nil {
				end.ClosedBy = &NodeShellUser{User: by.User, Username: by.Username}
			}
			s.mu.Lock()
			s.exit = &end
			s.mu.Unlock()
			return nil, io.EOF
		}
	}
}

func (s *realShell) Send(ctx context.Context, data []byte) error {
	for len(data) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		n := min(len(data), sfcp.NodeShellChunkBytes)
		if err := s.channel.Send(sfcp.NodeShellRecord{Kind: "stdin", Data: data[:n]}); err != nil {
			return realError("node-shell", err)
		}
		data = data[n:]
	}
	return nil
}

func (s *realShell) Resize(ctx context.Context, cols, rows uint16) error {
	if err := s.channel.Send(sfcp.NodeShellRecord{Kind: "resize", Cols: cols, Rows: rows}); err != nil {
		return realError("node-shell", err)
	}
	return nil
}

func (s *realShell) Exit() (int, string) {
	e := s.End()
	return e.Code, e.Reason
}

func (s *realShell) End() NodeShellEnd {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.exit == nil {
		return NodeShellEnd{}
	}
	return *s.exit
}

// Close ends the channel; sfcd closes the PTY when its client goes.
func (s *realShell) Close() error {
	s.once.Do(func() {
		_ = s.channel.Close()
		s.end()
		_ = s.mesh.Close()
		clear(s.self.Private)
	})
	return nil
}
