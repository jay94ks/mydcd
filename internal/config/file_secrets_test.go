// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstalledFileSecretConfigIsExplicitAndReadOnly(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "node.yaml")
	base := "version: 1\nnode: {id: node-a, listen: '127.0.0.1:40001', state_dir: state, identity_dir: keys}\nmodules: {network: {enabled: false}, workload: {enabled: false}, ingress: {enabled: false}}\n"
	profile := "vaults:\n - {mode: local-file, realm: tenant, profile: files, root: installed, prefix: tenant, values: true}\n"
	load := func(s string) (Node, error) {
		t.Helper()
		if err := os.WriteFile(file, []byte(base+s), 0600); err != nil {
			t.Fatal(err)
		}
		return LoadNode(file)
	}
	c, err := load(profile)
	if err != nil || c.Vaults[0].Root != filepath.Join(root, "installed") {
		t.Fatal("explicit file source", err)
	}
	for _, bad := range []string{strings.Replace(profile, "mode: local-file", "mode: other", 1), strings.Replace(profile, "root: installed, ", "", 1), strings.Replace(profile, "values: true", "values: true, verifiers: true", 1), strings.Replace(profile, "values: true", "values: true, token_file: token", 1), strings.Replace(profile, "mode: local-file, ", "", 1), profile + strings.TrimPrefix(profile, "vaults:\n")} {
		if _, err := load(bad); err == nil {
			t.Fatal("ambiguous/credential/verifier/duplicate file source accepted")
		}
	}
	if _, err := os.Stat(filepath.Join(root, "installed")); !os.IsNotExist(err) {
		t.Fatal("config loader opened/created provider root")
	}
}
