// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"crypto/sha256"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/schema"
	"path/filepath"
	"testing"
	"time"
)

// Wire decoding/binding/EOF use the real product client. Projection fixtures
// here do not stand in for a Raft/native-owner test.
func TestPublicReadActualUnixAndQUICRejectForeignMethodAndTenantRows(t *testing.T) {
	for _, network := range []string{"unix", "quic"} {
		for _, mode := range []string{"ok", "foreign-tenant", "wrong-union", "backup-original", "backup-no-original", "backup-foreign"} {
			t.Run(network+"/"+mode, func(t *testing.T) {
				_, client, session, node := journalFixture(t)
				backup := mode == "backup-original" || mode == "backup-no-original" || mode == "backup-foreign"
				method, query := "network-users", control.PublicReadQuery{Name: "services"}
				if backup {
					method, query = "volume-backup-limits", control.PublicReadQuery{Node: "node-a"}
				}
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
				binding := Service{Self: node, Mesh: server, Policy: control.Policy{Cluster: client.Cluster}}
				done := make(chan error, 1)
				if err := server.OnManagement(mydcp.User, func(ctx context.Context, conn *mydcp.Session, stream mydcp.Stream, frame mydcp.Frame) error {
					serve := func() error {
						envelope, err := schema.Decode[Envelope](frame.Fields[0].Value)
						if err != nil {
							return err
						}
						request, err := schema.Decode[Request](envelope.Body)
						if err != nil || !request.validMethodFields() || request.Method != method || request.PublicRead == nil || *request.PublicRead != query {
							return mydcp.ErrAdmission
						}
						if _, err := binding.binding(conn, frame.Kind, envelope); err != nil {
							return err
						}
						if err := streamEOF(stream); err != nil {
							return err
						}
						row := control.PublicReadRow{Key: "task", User: &control.PublicResourceUser{Tenant: "tenant", Kind: "app-service", App: "app", Service: "web"}}
						if mode == "foreign-tenant" {
							row.User.Tenant = "foreign"
						}
						if mode == "wrong-union" {
							row = control.PublicReadRow{Key: "limit", BackupLimit: &control.PublicBackupLimit{Tenant: "tenant"}}
						}
						if backup {
							row = control.PublicReadRow{Key: "node-a", BackupLimit: &control.PublicBackupLimit{Tenant: "tenant", Node: "node-a", Revision: 7, Bytes: 65536, Count: 2}}
							if mode != "backup-no-original" {
								row.BackupLimit.Original = &control.OriginalVolumeLimit{Bytes: 131072, Count: 3}
							}
							if mode == "backup-foreign" {
								row.BackupLimit.Tenant = "foreign"
							}
						}
						page := control.PublicReadPage{Schema: 1, Method: method, Tenant: "tenant", Rows: []control.PublicReadRow{row}, Total: 1}
						return binding.respond(stream, frame, sha256.Sum256(frame.Fields[0].Value), Reply{Schema: 1, Code: "ok", PublicRead: &page})
					}()
					done <- serve
					return serve
				}); err != nil {
					t.Fatal(err)
				}
				if network == "unix" {
					path := filepath.Join(t.TempDir(), "api.sock")
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
				reply, err := client.PublicRead(ctx, peer, session, method, "tenant", query, "")
				if (err == nil) != (mode == "ok" || mode == "backup-original" || mode == "backup-no-original") {
					t.Fatal("untrusted page result", mode, err)
				}
				if err == nil && backup {
					original := reply.PublicRead.Rows[0].BackupLimit.Original
					if mode == "backup-original" && (original == nil || original.Bytes != 131072 || original.Count != 3) || mode == "backup-no-original" && original != nil {
						t.Fatal("wire changed optional original policy", original)
					}
				}
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			})
		}
	}
}
