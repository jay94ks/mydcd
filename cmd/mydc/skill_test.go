// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSkillPathLooksBesideTheExecutableThenInShare(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	share := filepath.Join(root, "share", "mydc")
	for _, d := range []string{bin, share} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	exe := filepath.Join(bin, "mydc")
	if found, expected := skillPath(exe); found != "" || expected != filepath.Join(share, "SKILL.md") {
		t.Fatal("not installed", found, expected)
	}
	if err := os.WriteFile(filepath.Join(share, "SKILL.md"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if found, _ := skillPath(exe); found != filepath.Join(share, "SKILL.md") {
		t.Fatal("share", found)
	}
	if err := os.WriteFile(filepath.Join(bin, "SKILL.md"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if found, _ := skillPath(exe); found != filepath.Join(bin, "SKILL.md") {
		t.Fatal("beside", found)
	}
}

// The guide in the source tree is the one packages install.
func TestSkillGuideIsInTheSourceTree(t *testing.T) {
	raw, err := os.ReadFile("SKILL.md")
	if err != nil || len(raw) < 100 || string(raw[:4]) != "---\n" {
		t.Fatal("SKILL.md", err)
	}
}
