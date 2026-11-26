// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/schema"
)

// Production Client.query, transport binding, frame/EOF and response decoding.
// Shared permission/native artifact facts are injected; owner selection and
// Raft/native retention need the final RQ6 full user-path run as well.
func TestBuildContentActualUserWireRejectsCorruptPages(t *testing.T) {
	for _, network := range []string{"unix", "quic"} {
		for _, mode := range []string{"ok", "missing-tree", "bad-cursor", "deleted"} {
			t.Run(network+"/"+mode, func(t *testing.T) {
				_, client, session, node := journalFixture(t)
				dir, err := os.MkdirTemp("", "mydc-build-content-wire-")
				if err != nil {
					t.Fatal(err)
				}
				defer os.RemoveAll(dir)
				peer := client.Peers[0]
				lookup := func(key mydcp.Identity) (mydcp.Peer, bool) {
					if key == mydcp.Identity(client.Self.Public) {
						return mydcp.Peer{ID: "user", Policy: mydcp.Policy{Key: key, UserAuth: true}}, true
					}
					return peer, key == peer.Key
				}
				server, err := mydcp.NewTransport(node, client.Cluster, lookup)
				if err != nil {
					t.Fatal(err)
				}
				defer server.Close()
				q := imagebuild.ContentQuery{Version: [32]byte{1}, Part: "dockerfile"}
				read := control.ImageBuildContentRead{Query: q, Scope: imagebuild.UploadScope{Cluster: client.Cluster}, Tenant: "tenant", Seal: imagebuild.SealReceipt{Tree: [32]byte{2}}, Epoch: 1}
				page := imagebuild.ContentPage{Schema: 1, Version: q.Version, Tree: read.Seal.Tree, Part: q.Part, Total: 4, Data: []byte("text")}
				out, err := read.Page(page)
				if err != nil {
					t.Fatal(err)
				}
				if mode == "missing-tree" {
					out.Page.Tree = [32]byte{}
				}
				if mode == "bad-cursor" {
					out.Next = "unexpected trailing cursor"
				}
				binding := Service{Self: node, Mesh: server, Policy: control.Policy{Cluster: client.Cluster}}
				done := make(chan error, 1)
				if err := server.OnManagement(mydcp.User, func(ctx context.Context, conn *mydcp.Session, stream mydcp.Stream, frame mydcp.Frame) error {
					serve := func() error {
						envelope, err := schema.Decode[Envelope](frame.Fields[0].Value)
						if err != nil {
							return err
						}
						request, err := schema.Decode[Request](envelope.Body)
						if err != nil || !request.validMethodFields() || !request.validQuerySelectors() || request.ImageBuildContent == nil || *request.ImageBuildContent != q {
							return mydcp.ErrFrame
						}
						if _, err := binding.binding(conn, frame.Kind, envelope); err != nil {
							return err
						}
						if err := streamEOF(stream); err != nil {
							return err
						}
						reply := Reply{Schema: 1, Code: "ok", ImageBuildContent: &out}
						if mode == "deleted" {
							reply = Reply{Schema: 1, Code: "conflict"}
						}
						return binding.respond(stream, frame, sha256.Sum256(frame.Fields[0].Value), reply)
					}()
					done <- serve
					return serve
				}); err != nil {
					t.Fatal(err)
				}
				if network == "unix" {
					path := filepath.Join(dir, "api.sock")
					if err := server.ListenUnix(path); err != nil {
						t.Fatal(err)
					}
					peer.Endpoint = "unix://" + path
				} else {
					if err := server.Listen("127.0.0.1:0"); err != nil {
						t.Fatal(err)
					}
					peer.Endpoint = server.Addr().String()
				}
				mesh, err := mydcp.NewTransport(client.Self, client.Cluster, lookup)
				if err != nil {
					t.Fatal(err)
				}
				defer mesh.Close()
				client.Mesh = mesh
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				got, err := client.BuildContextContent(ctx, peer, session, "tenant", q, "")
				if mode == "ok" {
					if err != nil || string(got.Page.Data) != "text" {
						t.Fatal(got, err)
					}
				} else if err == nil {
					t.Fatal("corrupt/deleted content accepted", mode)
				}
				select {
				case err := <-done:
					if err != nil {
						t.Fatal("fixture failed", err)
					}
				case <-ctx.Done():
					t.Fatal("sender did not finish", ctx.Err())
				}
			})
		}
	}
}
