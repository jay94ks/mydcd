// SPDX-License-Identifier: Apache-2.0

package compat

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Frozen fixtures (files named frozen-* in a testdata directory) are
// historical input that every later build of the major must keep reading:
// they stand for what clusters already stored. Editing one to fit a new
// rule hides the break it should show (2026-11-28 lab, #894). frozen.sha256
// pins each one; a new fixture is added to it, and changing or removing a
// pinned one is a compatibility break that needs Jay's approval
// (devel/design/upgrades.md 3-8).
func TestFrozenFixtures(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]string{}
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "3rd-party", "node_modules", "work":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasPrefix(d.Name(), "frozen-") || filepath.Base(filepath.Dir(path)) != "testdata" {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		sum := sha256.Sum256(b)
		have[filepath.ToSlash(rel)] = hex.EncodeToString(sum[:])
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open("frozen.sha256")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	pinned := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		sum, path, ok := strings.Cut(line, "  ")
		if !ok {
			t.Fatalf("frozen.sha256: bad line %q", line)
		}
		pinned[path] = sum
	}
	if err = sc.Err(); err != nil {
		t.Fatal(err)
	}
	var paths []string
	for p := range have {
		paths = append(paths, p)
	}
	for p := range pinned {
		if _, ok := have[p]; !ok {
			paths = append(paths, p)
		}
	}
	slices.Sort(paths)
	for _, p := range paths {
		switch got, want := have[p], pinned[p]; {
		case want == "":
			t.Errorf("%s is a new frozen fixture: add \"%s  %s\" to tests/compat/frozen.sha256", p, got, p)
		case got == "":
			t.Errorf("%s is pinned but gone: a frozen fixture is never removed without Jay's approval", p)
		case got != want:
			t.Errorf("%s changed (sha256 %s, pinned %s): frozen fixtures are what clusters already stored; keep reading the old form instead of editing it (changing it needs Jay's approval)", p, got, want)
		}
	}
}
