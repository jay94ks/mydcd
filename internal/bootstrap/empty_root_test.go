// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jay94ks/seafield/internal/config"
)

// A wiped state root can keep the app secret tmpfs mountpoint (rm cannot
// remove a mounted directory): init accepts it while it is empty, and still
// refuses any file in it or any other leftover directory.
func TestEmptyRootAcceptsLeftInputMemoryMountpoint(t *testing.T) {
	root := t.TempDir()
	c := config.Node{Version: 1, Modules: map[string]config.Module{}}
	c.Node.StateDir = filepath.Join(root, "state")
	c.Node.IdentityDir = filepath.Join(root, "identity")
	memory := filepath.Join(c.Node.StateDir, filepath.FromSlash(InputMemoryDir))
	if err := os.MkdirAll(memory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := emptyRoot(c); err != nil {
		t.Fatalf("empty mountpoint refused: %v", err)
	}
	if err := os.WriteFile(filepath.Join(memory, "left"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := emptyRoot(c); err == nil {
		t.Fatal("a file in the mountpoint accepted")
	}
	if err := os.Remove(filepath.Join(memory, "left")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(c.Node.StateDir, "workload", "inputs"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := emptyRoot(c); err == nil {
		t.Fatal("another leftover directory accepted")
	}
}
