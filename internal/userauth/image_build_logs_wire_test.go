// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// Production Client.query, transport binding, frame/EOF and response decoding.
// Shared permission/native artifact facts are injected; owner selection and
// Raft/native retention need the final RQ6 full user-path run as well.
func TestBuildLogsActualUserWireRejectsCorruptPages(t *testing.T) {
	for _, network := range []string{"unix", "quic"} {
		for _, mode := range []string{"ok", "missing-job", "bad-cursor", "deleted", "tail", "tail-bad-offset"} {
			t.Run(network+"/"+mode, func(t *testing.T) {
				_, client, session, node := journalFixture(t)
				dir, err := os.MkdirTemp("", "sfc-build-logs-wire-")
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
				q := imagebuild.LogQuery{Job: "build-one", MaxBytes: 4096}
				read := control.ImageBuildLogRead{Query: q, Spec: imagebuild.JobSpec{Cluster: client.Cluster}, Tenant: "tenant", Epoch: 1, Phase: "running"}
				page := imagebuild.LogPage{Schema: 1, Job: read.Spec.Digest(), Available: true, Total: 4, Next: 4, Data: []byte("text")}
				isTail := mode == "tail" || mode == "tail-bad-offset"
				if isTail {
					q.Tail = true
					read.Query = q
					page.Total, page.Next = 400<<10, 400<<10
					page.Offset = page.Total - q.MaxBytes
					page.Data = bytes.Repeat([]byte{'x'}, int(q.MaxBytes))
				}
				out, err := read.Page(page)
				if err != nil {
					t.Fatal(err)
				}
				if mode == "missing-job" {
					out.Page.Job = [32]byte{}
				}
				if mode == "bad-cursor" {
					out.Next = "unexpected trailing cursor"
				}
				if mode == "tail-bad-offset" {
					out.Page.Offset = 0
				}
				after := ""
				binding := Service{Self: node, Mesh: server, Policy: control.Policy{Cluster: client.Cluster}}
				done := make(chan error, 1)
				if err := server.OnManagement(sfcp.User, func(ctx context.Context, conn *sfcp.Session, stream sfcp.Stream, frame sfcp.Frame) error {
					serve := func() error {
						envelope, err := schema.Decode[Envelope](frame.Fields[0].Value)
						if err != nil {
							return err
						}
						request, err := schema.Decode[Request](envelope.Body)
						if err != nil || !request.validMethodFields() || !request.validQuerySelectors() || request.ImageBuildLog == nil || *request.ImageBuildLog != q || request.After != after {
							return sfcp.ErrFrame
						}
						if _, err := binding.binding(conn, frame.Kind, envelope); err != nil {
							return err
						}
						if err := streamEOF(stream); err != nil {
							return err
						}
						reply := Reply{Schema: 1, Code: "ok", ImageBuildLog: &out}
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
				got, err := client.ImageBuildLogs(ctx, peer, session, "tenant", q, "")
				if mode == "ok" || mode == "tail" {
					if err != nil || !bytes.Equal(got.Page.Data, page.Data) || got.Page.Offset != page.Offset {
						t.Fatal(got, err)
					}
				} else if err == nil {
					t.Fatal("corrupt/deleted logs accepted", mode)
				}
				select {
				case err := <-done:
					if err != nil {
						t.Fatal("fixture failed", err)
					}
				case <-ctx.Done():
					t.Fatal("sender did not finish", ctx.Err())
				}
				if mode == "tail" {
					q.Tail = false
					after = got.Next
					read.Query, read.After = q, after
					out, err = read.Page(imagebuild.LogPage{Schema: 1, Job: read.Spec.Digest(), Available: true, Offset: 400 << 10, Total: 400<<10 + 3, Next: 400<<10 + 3, Data: []byte("new")})
					if err != nil {
						t.Fatal(err)
					}
					follow, err := client.ImageBuildLogs(ctx, peer, session, "tenant", q, after)
					if err != nil || string(follow.Page.Data) != "new" || follow.Page.Offset != 400<<10 {
						t.Fatal("tail cursor did not follow appended bytes", err)
					}
					select {
					case err := <-done:
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
}
