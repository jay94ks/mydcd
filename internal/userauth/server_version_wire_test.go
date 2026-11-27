// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"github.com/jay94ks/seafield/internal/buildinfo"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/sfcp"
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
			server, err := sfcp.NewTransport(node, client.Cluster, func(key sfcp.Identity) (sfcp.Peer, bool) {
				return sfcp.Peer{ID: "public-user", Policy: sfcp.Policy{Key: key, UserAuth: true}}, key == sfcp.Identity(client.Self.Public)
			})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			service := Service{Self: node, Mesh: server, Policy: control.Policy{Cluster: client.Cluster}}
			if err := server.OnManagement(sfcp.User, service.handle); err != nil {
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
			mesh, err := sfcp.NewTransport(client.Self, client.Cluster, func(key sfcp.Identity) (sfcp.Peer, bool) { return peer, key == peer.Key })
			if err != nil {
				t.Fatal(err)
			}
			defer mesh.Close()
			client.Mesh = mesh
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			version, err := client.ServerVersion(ctx, peer)
			if err != nil || version.Version != buildinfo.Version() || version.Protocol != 1 {
				t.Fatal("sessionless responding daemon", version, err)
			}
		})
	}
}
