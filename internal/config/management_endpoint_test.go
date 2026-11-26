// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestU0ClientManagementEndpointsDoNotChangeNodePeerContract(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "client.yaml")
	for _, endpoint := range []string{"unix:///var/run/mydc.sock", "mydcp://127.0.0.1:7443", "127.0.0.1:7443"} {
		body := fmt.Sprintf("version: 1\nauth: user\ncluster: '%064x'\npeers:\n  - {id: node, key: '%064x', endpoint: '%s'}\n", 1, 2, endpoint)
		if err := os.WriteFile(file, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		client, err := LoadClient(file)
		if err != nil {
			t.Fatal(endpoint, err)
		}
		want := endpoint
		if endpoint == "mydcp://127.0.0.1:7443" {
			want = "127.0.0.1:7443"
		}
		if client.Peers[0].Endpoint != want {
			t.Fatal("management endpoint normalization changed", client.Peers[0].Endpoint)
		}
		if endpoint != "127.0.0.1:7443" && validatePeers([]Peer{{ID: "node", Key: fmt.Sprintf("%064x", 2), Endpoint: endpoint}}) == nil {
			t.Fatal("node Raft/packet peer accepted a management URI", endpoint)
		}
	}
	for _, endpoint := range []string{"unix:///tmp/../mydc.sock", "unix://host/tmp/mydc.sock", "unix:///var/run/mydc.sock?query=1"} {
		body := fmt.Sprintf("version: 1\nauth: user\ncluster: '%064x'\npeers:\n  - {id: node, key: '%064x', endpoint: '%s'}\n", 1, 2, endpoint)
		if err := os.WriteFile(file, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadClient(file); err == nil {
			t.Fatal("unsafe management URI accepted", endpoint)
		}
	}
}
