// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVaultInstallationIsNodeLocalStrictAndHasNoRuntimeEffects(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "node.yaml")
	base := "version: 1\nnode:\n id: node-a\n listen: '127.0.0.1:40001'\n state_dir: state\n identity_dir: identity\nmodules:\n network: {enabled: false}\n workload: {enabled: false}\n ingress: {enabled: false}\n"
	profile := "vaults:\n - realm: tenant\n   profile: values\n   address: https://127.0.0.1:40002\n   mount: kv\n   prefix: tenant\n   ca_file: trust.pem\n   token_file: private.token\n   values: true\n"
	load := func(body string) (Node, error) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		return LoadNode(path)
	}
	old, err := load(base)
	if err != nil {
		t.Fatal(err)
	}
	node, err := load(base + profile)
	if err != nil || len(node.Vaults) != 1 || node.Vaults[0].CAFile != filepath.Join(root, "trust.pem") || node.Vaults[0].TokenFile != filepath.Join(root, "private.token") {
		t.Fatal("explicit installed profile", err)
	}
	before, _ := json.Marshal(old.Common)
	after, _ := json.Marshal(node.Common)
	if !bytes.Equal(before, after) || bytes.Contains(after, []byte("private.token")) {
		t.Fatal("local provider entered common manifest")
	}
	for _, invalid := range []string{strings.Replace(profile, "values: true", "values: false", 1), strings.Replace(profile, "token_file: private.token", "token: inline-private", 1), strings.Replace(profile, "address: https://", "address: http://", 1), profile + strings.TrimPrefix(profile, "vaults:\n"), strings.Replace(profile, "values: true", "values: 'true'", 1)} {
		if _, err = load(base + invalid); err == nil {
			t.Fatal("invalid/private/duplicate provider accepted")
		}
	}
	for _, name := range []string{"state", "identity", "trust.pem", "private.token"} {
		if _, err = os.Stat(filepath.Join(root, name)); !os.IsNotExist(err) {
			t.Fatal("config loading touched installation/runtime", name, err)
		}
	}
}
