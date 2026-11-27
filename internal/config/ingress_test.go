// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRealBoundaryIngressLocalConfig(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "node.yaml")
	text := "version: 1\nnode:\n  id: a\n  state_dir: state\n  identity_dir: keys\n  listen: '127.0.0.1:40001'\nmodules:\n  network: {enabled: true}\n  workload: {enabled: false}\n  ingress: {enabled: true}\n"
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadNode(path)
	if err != nil {
		t.Fatal(err)
	}
	var local IngressLocal
	if err = c.Modules["ingress"].Decode(&local); err != nil || !local.Enabled {
		t.Fatal(local, err)
	}
	for _, name := range []string{"state", "keys"} {
		if _, err = os.Stat(filepath.Join(root, name)); !os.IsNotExist(err) {
			t.Fatal("config check opened runtime resource", name, err)
		}
	}
	files := strings.Replace(text, "ingress: {enabled: true}", "ingress: {enabled: true, certificates: {local: {cert_file: 'tls/cert.pem', key_file: 'tls/key.pem'}}}", 1)
	if err = os.WriteFile(path, []byte(files), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadNode(path); err == nil {
		t.Fatal("local certificate files accepted; certificates come from the cluster store")
	}
	bad := strings.Replace(text, "network: {enabled: true", "network: {enabled: false", 1)
	if err = os.WriteFile(path, []byte(bad), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadNode(path); err == nil {
		t.Fatal("ingress accepted without network")
	}
}
