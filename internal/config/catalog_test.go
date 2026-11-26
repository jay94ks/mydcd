// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNodeConfigurationHasNoStaticRootKeys(t *testing.T) {
	text := "version: 1\nnode:\n  id: a\n  state_dir: state\n  identity_dir: keys\n  listen: '127.0.0.1:40001'\nmodules:\n  network: {enabled: false}\n  workload: {enabled: false}\n  ingress: {enabled: false}\n"
	path := filepath.Join(t.TempDir(), "node.yaml")
	load := func(body string) (Node, error) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		return LoadNode(path)
	}
	c, err := load(text)
	if err != nil || c.Common.Cluster != "" || len(c.Common.Peers) != 0 {
		t.Fatal("managed node configuration", err)
	}
	// Cluster, admin and peers come from init/join, never from YAML.
	for _, extra := range []string{
		"common:\n  user_catalog: true\n",
		"common:\n  cluster: '" + strings.Repeat("01", 32) + "'\n",
		"common:\n  peers: []\n",
	} {
		if _, err := load(strings.Replace(text, "node:\n", extra+"node:\n", 1)); err == nil {
			t.Fatal("static root key accepted", extra)
		}
	}
	for _, extra := range []string{"  managed: true\n", "  bootstrap: true\n"} {
		if _, err := load(strings.Replace(text, "  id: a\n", "  id: a\n"+extra, 1)); err == nil {
			t.Fatal("static root key accepted", extra)
		}
	}
	if _, err := os.Stat(c.Node.StateDir); !os.IsNotExist(err) {
		t.Fatal("configuration loading created a runtime root", err)
	}
}
