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
	"github.com/jay94ks/mydcd/internal/nodestorage"
	"github.com/jay94ks/mydcd/internal/schema"
)

// Actual SDK, Unix/QUIC frame/binding/EOF and strict request/reply decoding.
// Authority and native bytes are injected here, not claimed as a live owner.
func TestBuildFileActualUnixAndQUICUsesBoundedOriginalSnapshot(t *testing.T) {
	for _, network := range []string{"unix", "quic"} {
		for _, kind := range []string{"retained", "draft"} {
			for _, mode := range []string{"ok", "pending", "changed", "wrong-file", "conflict"} {
				if kind == "retained" && mode == "pending" {
					continue
				}
				t.Run(network+"/"+kind+"/"+mode, func(t *testing.T) {
					_, client, session, node := journalFixture(t)
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
					scope := imagebuild.DraftScope{Schema: 1, Tenant: "tenant", Context: "editable", Root: nodestorage.Reference{Cluster: client.Cluster, Node: "node", Key: node.Public, ID: "data", Generation: 1, Path: "/srv/mydc"}, ContextRevision: 1, PolicyRevision: 1, Dockerfile: "Dockerfile", ExpandedLimit: 1 << 20}
					digest := [32]byte{5}
					q := imagebuild.ContentQuery{Version: [32]byte{1}, Part: "file", Path: "composer.json"}
					dq := imagebuild.DraftRequest{Context: scope.Context, Kind: "file", Scope: &scope, Revision: 3, Digest: &digest, Path: q.Path}
					binding := Service{Self: node, Mesh: server, Policy: control.Policy{Cluster: client.Cluster}}
					done := make(chan error, 1)
					if err = server.OnManagement(mydcp.User, func(ctx context.Context, conn *mydcp.Session, stream mydcp.Stream, frame mydcp.Frame) error {
						serve := func() error {
							envelope, err := schema.Decode[Envelope](frame.Fields[0].Value)
							if err != nil {
								return err
							}
							request, err := schema.Decode[Request](envelope.Body)
							if err != nil || !request.validMethodFields() || !request.validQuerySelectors() {
								return mydcp.ErrFrame
							}
							if kind == "retained" {
								if request.Method != "build-context-content" || request.ImageBuildContent == nil || *request.ImageBuildContent != q {
									return mydcp.ErrFrame
								}
							} else if request.Method != "build-draft" || request.ImageBuildDraft == nil || !request.ImageBuildDraft.Valid() || request.ImageBuildDraft.Kind != "file" || request.ImageBuildDraft.Scope == nil || *request.ImageBuildDraft.Scope != scope || request.ImageBuildDraft.Path != dq.Path || request.ImageBuildDraft.Revision != dq.Revision || *request.ImageBuildDraft.Digest != digest || request.ImageBuildDraft.RequiresProof() {
								return mydcp.ErrFrame
							}
							if _, err := binding.binding(conn, frame.Kind, envelope); err != nil {
								return err
							}
							if err := streamEOF(stream); err != nil {
								return err
							}
							file := imagebuild.FilePage{Entry: imagebuild.Entry{Path: q.Path, Bytes: 4, Digest: sha256.Sum256([]byte("text"))}, Total: 4, Data: []byte("text")}
							if mode == "wrong-file" {
								file.Entry.Path = "private"
							}
							reply := Reply{Schema: 1, Code: "ok"}
							if kind == "retained" {
								read := control.ImageBuildContentRead{Query: q, Scope: imagebuild.UploadScope{Cluster: client.Cluster}, Tenant: "tenant", Seal: imagebuild.SealReceipt{Tree: [32]byte{2}}, Epoch: 1}
								out := control.ImageBuildContentPage{Page: imagebuild.ContentPage{Schema: 1, Version: q.Version, Tree: read.Seal.Tree, Part: "file", File: &file}, Root: read.Snapshot(), Epoch: 1}
								if mode == "changed" {
									out.Page.File.Offset++
								}
								reply.ImageBuildContent = &out
							} else {
								out := imagebuild.DraftResponse{Schema: 1, Scope: scope, Code: "OK", Revision: dq.Revision, Digest: &digest, Content: &file}
								if mode == "changed" {
									out.Revision++
								}
								if mode == "pending" {
									out = imagebuild.DraftResponse{Schema: 1, Scope: scope, Code: "PENDING"}
								}
								reply.ImageBuildDraft = &out
							}
							if mode == "conflict" {
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
						dir, err := os.MkdirTemp("", "mydc-build-file-wire-")
						if err != nil {
							t.Fatal(err)
						}
						defer os.RemoveAll(dir)
						path := filepath.Join(dir, "api.sock")
						if err = server.ListenUnix(path); err != nil {
							t.Fatal(err)
						}
						peer.Endpoint = "unix://" + path
					} else {
						if err = server.Listen("127.0.0.1:0"); err != nil {
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
					if kind == "retained" {
						var result control.ImageBuildContentPage
						result, err = client.BuildContextContent(ctx, peer, session, "tenant", q, "")
						if mode == "ok" && (err != nil || result.Page.File == nil || string(result.Page.File.Data) != "text") {
							t.Fatal(result, err)
						}
					} else {
						var result imagebuild.DraftResponse
						result, err = client.BuildDraft(ctx, peer, session, "tenant", dq)
						if mode == "ok" && (err != nil || result.Content == nil || string(result.Content.Data) != "text") {
							t.Fatal(result, err)
						}
						if mode == "pending" && (err != nil || result.Code != "PENDING" || result.Content != nil) {
							t.Fatal(result, err)
						}
					}
					if mode != "ok" && mode != "pending" && err == nil {
						t.Fatal("corrupt/conflicting file response accepted")
					}
					select {
					case err := <-done:
						if err != nil {
							t.Fatal("wire fixture", err)
						}
					case <-ctx.Done():
						t.Fatal("handler did not end", ctx.Err())
					}
				})
			}
		}
	}
}
