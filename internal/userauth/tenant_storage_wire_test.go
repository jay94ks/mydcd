// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/nodestorage"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// Actual production Unix/QUIC framing, client selectors and connection proof.
// ACL/membership/FSM facts are injected here and covered by control core tests.
func TestTenantStorageActualUserWireAndGenericQuery(t *testing.T) {
	for _, network := range []string{"unix", "quic"} {
		for _, mode := range []string{"ok", "foreign-cluster", "mismatched-node", "invalid-path", "missing-generation"} {
			t.Run(network+"/"+mode, func(t *testing.T) {
				_, client, session, node := journalFixture(t)
				dir, err := os.MkdirTemp("", "sfc-tenant-storage-wire-")
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
				root := nodestorage.Reference{Cluster: client.Cluster, Node: "node-a", Key: node.Public, ID: "ssd", Generation: 3, Path: "/mnt/ssd"}
				row := control.TenantStorageRoot{Node: root.Node, ID: root.ID, Generation: root.Generation, Revision: 4, Allowed: true, Root: root}
				switch mode {
				case "foreign-cluster":
					row.Root.Cluster = [32]byte{99}
				case "mismatched-node":
					row.Root.Node = "other-node"
				case "invalid-path":
					row.Root.Path = "/"
				case "missing-generation":
					row.Generation = 0
				}
				binding := Service{Self: node, Mesh: server, Policy: control.Policy{Cluster: client.Cluster}}
				done := make(chan error, 1)
				if err = server.OnManagement(sfcp.User, func(ctx context.Context, conn *sfcp.Session, stream sfcp.Stream, frame sfcp.Frame) error {
					serve := func() error {
						envelope, err := schema.Decode[Envelope](frame.Fields[0].Value)
						if err != nil {
							return err
						}
						request, err := schema.Decode[Request](envelope.Body)
						if err != nil || !request.validMethodFields() || !request.validQuerySelectors() || request.Method != "tenant-storage" || request.Tenant != "tenant" {
							return sfcp.ErrFrame
						}
						if _, err = binding.binding(conn, frame.Kind, envelope); err != nil {
							return err
						}
						if err = streamEOF(stream); err != nil {
							return err
						}
						return binding.respond(stream, frame, sha256.Sum256(frame.Fields[0].Value), Reply{Schema: 1, Code: "ok", TenantStorage: []control.TenantStorageRoot{row}, TenantStorageViewIndex: 9, NodeStorageRootRevision: 4, NodeStorageRevision: 4})
					}()
					done <- serve
					return serve
				}); err != nil {
					t.Fatal(err)
				}
				if network == "unix" {
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
				mesh, err := sfcp.NewTransport(client.Self, client.Cluster, lookup)
				if err != nil {
					t.Fatal(err)
				}
				defer mesh.Close()
				client.Mesh = mesh
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				got, err := client.Query(ctx, peer, session, "tenant-storage", "tenant")
				if mode == "ok" {
					if err != nil || len(got.TenantStorage) != 1 || got.TenantStorage[0].Root != root {
						t.Fatal(got, err)
					}
				} else if err == nil {
					t.Fatal("invalid complete root accepted", mode)
				}
				select {
				case err := <-done:
					if err != nil {
						t.Fatal("wire fixture failed", err)
					}
				case <-ctx.Done():
					t.Fatal("wire did not finish", ctx.Err())
				}
			})
		}
	}
}
