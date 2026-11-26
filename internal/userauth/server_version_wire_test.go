// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"path/filepath"
	"testing"
	"time"
)

// Real product handler + TLS/frames/EOF, with no Engine, catalog or wallet.
// Any accidental quorum/authentication read fails instead of faking success.
func TestServerVersionActualUnixAndQUICWithoutSessionOrQuorum(t *testing.T) {
	for _, network := range []string{"unix", "quic"} {
		t.Run(network, func(t *testing.T) {
			_, client, _, node := journalFixture(t)
			peer := client.Peers[0]
			server, err := mydcp.NewTransport(node, client.Cluster, func(key mydcp.Identity) (mydcp.Peer, bool) {
				return mydcp.Peer{ID: "public-user", Policy: mydcp.Policy{Key: key, UserAuth: true}}, key == mydcp.Identity(client.Self.Public)
			})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			service := Service{Self: node, Mesh: server, Policy: control.Policy{Cluster: client.Cluster}}
			if err := server.OnManagement(mydcp.User, service.handle); err != nil {
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
			mesh, err := mydcp.NewTransport(client.Self, client.Cluster, func(key mydcp.Identity) (mydcp.Peer, bool) { return peer, key == peer.Key })
			if err != nil {
				t.Fatal(err)
			}
			defer mesh.Close()
			client.Mesh = mesh
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			version, err := client.ServerVersion(ctx, peer)
			if err != nil || version.Version != "1" || version.Protocol != 1 {
				t.Fatal("sessionless responding daemon", version, err)
			}
		})
	}
}
