// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A script makes a backup key, takes a backup without a terminal and
// verifies it; a second backup to the same file is refused, and a wrong key
// does not verify.
func TestClusterBackupCreateAndVerifyWithoutTerminal(t *testing.T) {
	n := newCLINode(t)
	t.Setenv("SFC_NONINTERACTIVE", "1")
	dir := t.TempDir()
	key := filepath.Join(dir, "backup.key")
	out := filepath.Join(dir, "lab.sfcbak")
	n.run(0, "cluster", "backup", "keygen", "--out", key)
	if info, err := os.Stat(key); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("key file mode", info, err)
	}
	n.run(2, "cluster", "backup", "create", "--out", out) // no key and no terminal
	shown := n.run(0, "cluster", "backup", "create", "--out", out, "--backup-key-file", key, "--id", "backup-cli", "-o", "json")
	if !strings.Contains(shown, `"Operation": "backup-cli"`) || !strings.Contains(shown, `"User": "admin"`) {
		t.Fatal(shown)
	}
	if info, err := os.Stat(out); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("backup file mode", info, err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 2 {
		t.Fatal("partial file left behind", entries)
	}
	n.run(0, "cluster", "backup", "verify", out, "--backup-key-file", key)
	n.run(1, "cluster", "backup", "create", "--out", out, "--backup-key-file", key)

	other := filepath.Join(dir, "other.key")
	n.run(0, "cluster", "backup", "keygen", "--out", other)
	n.run(1, "cluster", "backup", "verify", out, "--backup-key-file", other)

	password := filepath.Join(dir, "password")
	if err := os.WriteFile(password, []byte("correct horse battery\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	second := filepath.Join(dir, "second.sfcbak")
	n.run(0, "cluster", "backup", "create", "--out", second, "--backup-password-file", password)
	n.run(0, "cluster", "backup", "verify", second, "--backup-password-file", password)
	n.run(1, "cluster", "backup", "verify", second, "--backup-key-file", key)
}
