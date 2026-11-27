// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// Actual production framing/client/connection binding and EOF; owner snapshot,
// ACL and Raft facts are injected here and require the full RQ7 adapter gate.
func TestIngressActualUserWireRejectsForeignRows(t *testing.T) {
	for _, network := range []string{"unix", "quic"} {
		for _, mode := range []string{"ok", "foreign-tenant", "foreign-key", "missing-generation"} {
			t.Run(network+"/"+mode, func(t *testing.T) {
				_, client, session, node := journalFixture(t)
				dir, err := os.MkdirTemp("", "sfc-ingress-wire-")
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
				q := control.IngressQuery{Tenant: "tenant", Node: "node-a", Key: "ingress/app/tenant/shop/http", Part: "metrics"}
				row := control.IngressMapping{Tenant: q.Tenant, Node: q.Node, App: "shop", Key: q.Key, Generation: 1, Revision: 1}
				switch mode {
				case "foreign-tenant":
					row.Tenant = "other"
				case "foreign-key":
					row.Key = "ingress/app/tenant/other/http"
				case "missing-generation":
					row.Generation = 0
				}
				page := control.IngressPage{Schema: 1, Index: 100, Epoch: 1, RootRevision: 77, BlockRevision: 3, Mappings: []control.IngressMapping{row}}
				data, err := json.Marshal(page)
				if err != nil {
					t.Fatal(err)
				}
				binding := Service{Self: node, Mesh: server, Policy: control.Policy{Cluster: client.Cluster}}
				done := make(chan error, 1)
				err = server.OnManagement(sfcp.User, func(ctx context.Context, conn *sfcp.Session, stream sfcp.Stream, frame sfcp.Frame) error {
					serve := func() error {
						envelope, err := schema.Decode[Envelope](frame.Fields[0].Value)
						if err != nil {
							return err
						}
						request, err := schema.Decode[Request](envelope.Body)
						var got control.IngressQuery
						if err != nil || !request.validMethodFields() || !request.validQuerySelectors() || request.Method != IngressesMethod.Name || strict(request.Params, &got) != nil || got != q {
							return sfcp.ErrFrame
						}
						if _, err = binding.binding(conn, frame.Kind, envelope); err != nil {
							return err
						}
						if err = streamEOF(stream); err != nil {
							return err
						}
						return binding.respond(stream, frame, sha256.Sum256(frame.Fields[0].Value), Reply{Schema: 1, Code: "ok", Data: data})
					}()
					done <- serve
					return serve
				})
				if err != nil {
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
				got, err := client.Ingresses(ctx, peer, session, q)
				if mode == "ok" {
					if err != nil || len(got.Mappings) != 1 || got.Mappings[0].Key != q.Key || got.RootRevision != 77 || got.BlockRevision != 3 {
						t.Fatal(got, err)
					}
				} else if err == nil {
					t.Fatal("foreign/invalid owner page accepted", mode)
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
