// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestClearRootEmptiesButKeepsRoot(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "a", "b"), 0750); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"x", "a/y", "a/b/z"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte(f), 0640); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := ClearRoot(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	left, err := os.ReadDir(dir)
	if err != nil || len(left) != 0 {
		t.Fatal("root not empty", left, err)
	}
	if _, err := os.Stat("/etc/passwd"); err != nil {
		t.Fatal("symlink target touched", err)
	}
}
