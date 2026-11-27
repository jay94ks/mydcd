// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// Real TLS/SFCP/Unix-or-QUIC framing with an explicit simulated executor.
// Catalog/quorum/native effects are covered by their actual runtime fixture.
func TestContainerSessionActualWirePreservesHalfCloseAndOutputChannels(t *testing.T) {
	for _, network := range []string{"unix", "quic"} {
		t.Run(network, func(t *testing.T) {
			_, c, session, node := journalFixture(t)
			root, err := os.MkdirTemp("", "sfc-rv5-wire-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(root) })
			peer := c.Peers[0]
			lookup := func(key sfcp.Identity) (sfcp.Peer, bool) {
				if key == sfcp.Identity(c.Self.Public) {
					return sfcp.Peer{ID: "user", Policy: sfcp.Policy{Key: key, UserAuth: true}}, true
				}
				return peer, key == peer.Key
			}
			server, err := sfcp.NewTransport(node, c.Cluster, lookup)
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
			mesh, err := sfcp.NewTransport(c.Self, c.Cluster, lookup)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = mesh.Close() })
			c.Mesh = mesh
			c.Peers = []sfcp.Peer{peer}
			spec := containerops.SessionSpec{Kind: "exec", Exec: &containerops.ExecSpec{Argv: []string{"custom-cli"}, Stdin: true}}
			intent := containerops.SessionIntent{Schema: 1, Request: "wire-original", User: session.User, Session: access.ExactSessionDigest(session), At: time.Now().Unix(), Target: containerops.Target{Cluster: c.Cluster, Owner: node.Public, Binding: [32]byte{1}, Tenant: "tenant", App: "app", Service: "web", Node: "node-a", Instance: "workload/task/tenant/app/web", Generation: 1, Revision: 1, NativeID: "native-original", StartedAt: "2026-01-01T00:00:00Z"}, Spec: spec}
			intent.Signature = ed25519.Sign(c.Self.Private, containerops.SessionIntentBytes(intent))
			finished := make(chan error, 2)
			bindingService := Service{Mesh: server, Self: node, Policy: control.Policy{Cluster: c.Cluster}}
			if err = server.OnManagement(sfcp.ContainerSession, func(ctx context.Context, conn *sfcp.Session, stream sfcp.Stream, frame sfcp.Frame) error {
				result := func() error {
					envelope, err := schema.Decode[Envelope](frame.Fields[0].Value)
					if err != nil {
						return err
					}
					q, err := schema.Decode[ContainerSessionRequest](envelope.Body)
					if err != nil || !q.valid() {
						return sfcp.ErrFrame
					}
					if _, err = bindingService.binding(conn, frame.Kind, envelope); err != nil {
						return err
					}
					if q.Method == "resolve" {
						if err = streamEOF(stream); err != nil {
							return err
						}
						return containerSessionReply(stream, frame, sha256.Sum256(frame.Fields[0].Value), ContainerSessionReply{Code: "ok", Supported: true, Target: &intent.Target})
					}
					if q.Intent == nil || q.Intent.Verify(session.Key) != nil {
						return sfcp.ErrAdmission
					}
					if err = containerSessionReply(stream, frame, sha256.Sum256(frame.Fields[0].Value), ContainerSessionReply{Code: "ready", Supported: true, Target: &intent.Target}); err != nil {
						return err
					}
					channel, err := newContainerChannel(ctx, conn, stream, frame.Request, intent, session.ExpiresAt, false)
					if err != nil {
						return err
					}
					defer channel.releaseContext()
					data, err := channel.Receive()
					if err != nil || data.Kind != "stdin" || string(data.Data) != "input" {
						return errors.New("wrong original input")
					}
					eof, err := channel.Receive()
					if err != nil || eof.Kind != "stdin-eof" {
						return errors.New("stdin EOF missing")
					}
					for _, record := range []containerops.SessionRecord{{Kind: "stdout", Data: []byte("output-after-eof")}, {Kind: "stderr", Data: []byte("separate-error")}, {Kind: "output-eof"}, {Kind: "end"}} {
						if err = channel.Send(record); err != nil {
							return err
						}
					}
					return nil
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
			resolved, err := c.ResolveContainerSession(ctx, peer, session, "tenant", containerops.Selection{App: "app", Service: "web"}, spec)
			if err != nil || resolved != intent.Target {
				t.Fatal("finite resolve before dedicated stream", err)
			}
			channel, err := c.OpenContainerSession(ctx, peer, session, intent, 3*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer channel.Close()
			if err = channel.Send(containerops.SessionRecord{Kind: "stdin", Data: []byte("input")}); err != nil {
				t.Fatal(err)
			}
			if err = channel.Send(containerops.SessionRecord{Kind: "stdin-eof"}); err != nil {
				t.Fatal(err)
			}
			for _, kind := range []string{"stdout", "stderr", "output-eof", "end"} {
				record, err := channel.Receive()
				if err != nil || record.Kind != kind {
					t.Fatal("direction/half-close", kind, err)
				}
			}
			for range 2 {
				select {
				case err := <-finished:
					if err != nil {
						t.Fatal(err)
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
		})
	}
}
