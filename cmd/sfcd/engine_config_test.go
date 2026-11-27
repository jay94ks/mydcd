// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// node.yaml engine becomes the engine's daemon.json; a bad value fails
// before anything is written.
func TestEngineConfigWritesTheServersDaemonJSON(t *testing.T) {
	dir := t.TempDir()
	base := "version: 1\nnode:\n  id: node-a\n  state_dir: state\n  identity_dir: key\n  listen: '127.0.0.1:17443'\nmodules:\n  network: {enabled: false}\n  workload: {enabled: false}\n  ingress: {enabled: false}\n"
	node := filepath.Join(dir, "node.yaml")
	if err := os.WriteFile(node, []byte(base+"engine:\n  build: false\n  logs: {notify_quiet: 200ms, max_size: 16m}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "daemon.json")
	var out, diag bytes.Buffer
	if code := run([]string{"--config", node, "engine-config", "--output", target}, &out, &diag); code != 0 || !strings.Contains(out.String(), "restart sfed") {
		t.Fatal(code, out.String(), diag.String())
	}
	b, err := os.ReadFile(target)
	if err != nil || !bytes.Contains(b, []byte(`"buildkit": false`)) || !bytes.Contains(b, []byte(`"notify-quiet": "200ms"`)) || !bytes.Contains(b, []byte(`"max-size": "16384k"`)) {
		t.Fatal(string(b), err)
	}
	out.Reset()
	if code := run([]string{"--config", node, "engine-config", "--output", target}, &out, &diag); code != 0 || out.Len() != 0 {
		t.Fatal("unchanged file reported as changed", code, out.String())
	}
	if code := run([]string{"--config", node, "engine-config", "--output", "-"}, &out, &diag); code != 0 || !bytes.Equal(out.Bytes(), b) {
		t.Fatal("stdout differs", code)
	}
	if err := os.WriteFile(node, []byte(base+"engine:\n  logs: {notify_quiet: 20s}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"--config", node, "engine-config", "--output", target}, &out, &diag); code != 2 {
		t.Fatal("bad engine value accepted", code)
	}
}
