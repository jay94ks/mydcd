// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/nodestorage"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// Production Client.query, transport binding, frame/EOF and response decoding.
// Shared permission/native artifact facts are injected; owner selection and
// Raft/native retention need the final RQ6 full user-path run as well.
func TestBuildCacheActualUserWireRejectsCorruptPages(t *testing.T) {
	for _, network := range []string{"unix", "quic"} {
		for _, selector := range []string{"job", "cache"} {
			for _, mode := range []string{"ok", "missing-job", "bad-cursor", "bad-cleanup", "deleted"} {
				t.Run(network+"/"+selector+"/"+mode, func(t *testing.T) {
					_, client, session, node := journalFixture(t)
					dir, err := os.MkdirTemp("", "sfc-build-cache-wire-")
					if err != nil {
						t.Fatal(err)
					}
					defer os.RemoveAll(dir)
					peer := client.Peers[0]
					lookup := func(key sfcp.Identity) (sfcp.Peer, bool) {
						if key == sfcp.Identity(client.Self.Public) {
							return sfcp.Peer{ID: "user", Policy: sfcp.Policy{Key: key, UserAuth: true}}, true
						}
						return peer, key == peer.Key
					}
					server, err := sfcp.NewTransport(node, client.Cluster, lookup)
					if err != nil {
						t.Fatal(err)
					}
					defer server.Close()
					q := imagebuild.CacheQuery{Job: "build-one"}
					read := control.ImageBuildCacheRead{Query: q, Spec: imagebuild.JobSpec{Cluster: client.Cluster, ID: "build-one", Context: imagebuild.ContextSpec{ID: "source"}, Scope: imagebuild.UploadScope{Root: nodestorage.Reference{Node: "node"}}}, Tenant: "tenant", Epoch: 1}
					if selector == "cache" {
						cache := imagebuild.CacheIdentity(read.Spec)
						q = imagebuild.CacheQuery{Cache: &cache, Node: "node"}
						read.Query = q
					}
					page := imagebuild.CachePage{Schema: 1, Cache: imagebuild.CacheIdentity(read.Spec), Snapshot: [32]byte{1}, ObservedBy: read.Spec.Digest(), Available: true, ObservedAt: 100, LastAttemptAt: 100, LastAttemptCode: "OK", Count: 1, ReportedBytes: 4, Entries: []imagebuild.CacheEntry{{ID: "record-one", Kind: "regular", Bytes: 4}}}
					page.Cleanup = &imagebuild.CacheCleanupStatus{Schema: 1, Cache: page.Cache, Job: read.Spec.Digest(), Steps: []imagebuild.CacheCleanupStep{{Kind: "age", Snapshot: [32]byte{1}, Selection: [32]byte{2}, Code: "SKIPPED"}}}
					out, err := read.Page(page)
					if err != nil {
						t.Fatal(err)
					}
					if mode == "missing-job" {
						out.Page.ObservedBy = [32]byte{}
					}
					if mode == "bad-cursor" {
						out.Next = "unexpected trailing cursor"
					}
					if mode == "bad-cleanup" {
						out.Page.Cleanup.Cache = [32]byte{99}
					}
					binding := Service{Self: node, Mesh: server, Policy: control.Policy{Cluster: client.Cluster}}
					done := make(chan error, 1)
					if err := server.OnManagement(sfcp.User, func(ctx context.Context, conn *sfcp.Session, stream sfcp.Stream, frame sfcp.Frame) error {
						serve := func() error {
							envelope, err := schema.Decode[Envelope](frame.Fields[0].Value)
							if err != nil {
								return err
							}
							request, err := schema.Decode[Request](envelope.Body)
							var params ImageBuildCacheQuery
							if err != nil || !typedParams(request, ImageBuildCacheMethod.Name, &params) || params.Tenant != "tenant" || !reflect.DeepEqual(params.Query, q) {
								return sfcp.ErrFrame
							}
							if _, err := binding.binding(conn, frame.Kind, envelope); err != nil {
								return err
							}
							if err := streamEOF(stream); err != nil {
								return err
							}
							reply := okReply(out)
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
					mesh, err := sfcp.NewTransport(client.Self, client.Cluster, lookup)
					if err != nil {
						t.Fatal(err)
					}
					defer mesh.Close()
					client.Mesh = mesh
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					got, err := client.ImageBuildCacheUsage(ctx, peer, session, "tenant", q, "")
					if mode == "ok" {
						if err != nil || got.Page.ReportedBytes != 4 || len(got.Page.Entries) != 1 || got.Page.Entries[0].ID != "record-one" {
							t.Fatal(got, err)
						}
					} else if err == nil {
						t.Fatal("corrupt/deleted cache observation accepted", mode)
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
}
