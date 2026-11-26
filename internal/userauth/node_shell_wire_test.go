// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/schema"
)

// Actual Unix TLS and QUIC framing reuse the ordinary user challenge binding.
// The handler models an accepted native stream; SSH/account effects are tested
// through the Runtime's owned adapter fixture, rather than claimed here.
func TestNodeShellActualWireOriginalBindingHalfCloseResizeAndClosedActor(t *testing.T) {
	for _, network := range []string{"unix", "quic"} {
		t.Run(network, func(t *testing.T) {
			_, c, session, node := journalFixture(t)
			root, err := os.MkdirTemp("", "mydc-shell-wire-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(root) })
			peer := c.Peers[0]
			lookup := func(key mydcp.Identity) (mydcp.Peer, bool) {
				if key == mydcp.Identity(c.Self.Public) {
					return mydcp.Peer{ID: "user", Policy: mydcp.Policy{Key: key, UserAuth: true}}, true
				}
				return peer, key == peer.Key
			}
			server, err := mydcp.NewTransport(node, c.Cluster, lookup)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = server.Close() })
			if network == "unix" {
				peer.Endpoint = "unix://" + filepath.Join(root, "api.sock")
			} else {
				if err = server.Listen("127.0.0.1:0"); err != nil {
					t.Fatal(err)
				}
				peer.Endpoint = server.Addr().String()
			}
			mesh, err := mydcp.NewTransport(c.Self, c.Cluster, lookup)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = mesh.Close() })
			c.Mesh = mesh
			c.Peers = []mydcp.Peer{peer}
			finished := make(chan error, 1)
			bindingService := Service{Mesh: server, Self: node, Policy: control.Policy{Cluster: c.Cluster}}
			if err = server.OnManagement(mydcp.NodeShell, func(ctx context.Context, conn *mydcp.Session, stream mydcp.Stream, frame mydcp.Frame) error {
				result := func() error {
					envelope, e := schema.Decode[Envelope](frame.Fields[0].Value)
					if e != nil {
						return e
					}
					q, e := schema.Decode[NodeShellRequest](envelope.Body)
					if e != nil || !q.valid() || q.SessionID != "original-shell" {
						return mydcp.ErrFrame
					}
					if _, e = bindingService.binding(conn, frame.Kind, envelope); e != nil {
						return e
					}
					metadata := control.NodeShellSession{SessionID: q.SessionID, User: session.User, Username: "alice", Node: "node-b", Account: "mydc-shell", State: "opened", CreatedAt: time.Now().Unix(), OpenedAt: time.Now().Unix()}
					if e = nodeShellResponse(stream, frame, sha256.Sum256(frame.Fields[0].Value), NodeShellReply{Code: "ready", Session: &metadata}); e != nil {
						return e
					}
					channel, e := newNodeShellChannel(ctx, conn, stream, frame.Request, sha256.Sum256(envelope.Body), session.ExpiresAt, false)
					if e != nil {
						return e
					}
					defer channel.releaseContext()
					for _, kind := range []string{"stdin", "resize", "half-close"} {
						r, e := channel.Receive()
						if e != nil {
							return e
						}
						if r.Kind != kind || kind == "stdin" && string(r.Data) != "private input" || kind == "resize" && (r.Cols != 120 || r.Rows != 40) {
							return errors.New("original input/resize/half-close changed")
						}
					}
					if e = channel.Send(mydcp.NodeShellRecord{Kind: "stdout", Data: []byte("output after half-close")}); e != nil {
						return e
					}
					return channel.Send(mydcp.NodeShellRecord{Kind: "end", End: &mydcp.NodeShellEnd{Reason: "closed", Code: 0, ClosedBy: &mydcp.NodeShellActor{User: "bob", Username: "bob"}}})
				}()
				finished <- result
				return result
			}); err != nil {
				t.Fatal(err)
			}
			if network == "unix" {
				if err = server.ListenUnix(filepath.Join(root, "api.sock")); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			channel, metadata, err := c.OpenNodeShell(ctx, peer, session, "original-shell")
			if err != nil {
				t.Fatal(err)
			}
			defer channel.Close()
			if metadata.SessionID != "original-shell" || metadata.Node != "node-b" {
				t.Fatal("ready metadata replaced original")
			}
			for _, r := range []mydcp.NodeShellRecord{{Kind: "stdin", Data: []byte("private input")}, {Kind: "resize", Cols: 120, Rows: 40}, {Kind: "half-close"}} {
				if err = channel.Send(r); err != nil {
					t.Fatal(err)
				}
			}
			output, err := channel.Receive()
			if err != nil || output.Kind != "stdout" || string(output.Data) != "output after half-close" {
				t.Fatal("PTY output missing", err)
			}
			end, err := channel.Receive()
			if err != nil || end.Kind != "end" || end.End.ClosedBy == nil || end.End.ClosedBy.User != "bob" {
				t.Fatal("original signed close actor missing", err)
			}
			select {
			case err = <-finished:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		})
	}
}
