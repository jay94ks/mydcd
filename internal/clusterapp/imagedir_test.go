// SPDX-License-Identifier: Apache-2.0

package clusterapp

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A package keeps the real sfcd in <prefix>/lib/sfc/bin and links
// <prefix>/bin/sfcd to it; both find <prefix>/lib/sfc/images.
func TestImageDirsFollowTheExecutable(t *testing.T) {
	root := t.TempDir()
	for _, prefix := range []string{"usr", "usr/local"} {
		bin := filepath.Join(root, prefix, "lib", "sfc", "bin")
		if err := os.MkdirAll(bin, 0o755); err != nil {
			t.Fatal(err)
		}
		exe := filepath.Join(bin, "sfcd")
		if err := os.WriteFile(exe, nil, 0o755); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(root, prefix, "bin", "sfcd")
		if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(exe, link); err != nil {
			t.Fatal(err)
		}
		want := filepath.Join(root, prefix, "lib", "sfc", "images")
		for _, e := range []string{exe, link} {
			if got := ImageDirs(e); got[0] != want {
				t.Fatalf("%s: %v, want %s first", e, got, want)
			}
		}
	}
	// sfcd copied straight into <prefix>/bin (make install of old) finds
	// <prefix>/lib/sfc/images second.
	if got := ImageDirs("/opt/x/bin/sfcd"); got[1] != "/opt/x/lib/sfc/images" {
		t.Fatal(got)
	}
}

func TestFindImageDirNamesWhereItLooked(t *testing.T) {
	web, _ := Lookup(Web)
	a, b := t.TempDir(), t.TempDir()
	_, err := FindImageDir([]string{a, b}, web)
	if !errors.Is(err, ErrImageNotFound) || !strings.Contains(err.Error(), filepath.Join(a, web.Layout)) || !strings.Contains(err.Error(), filepath.Join(b, web.Layout)) {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(b, web.Layout), 0o755); err != nil {
		t.Fatal(err)
	}
	if dir, err := FindImageDir([]string{a, b}, web); err != nil || dir != b {
		t.Fatal(dir, err)
	}
	if err := os.Mkdir(filepath.Join(a, web.Layout), 0o755); err != nil {
		t.Fatal(err)
	}
	if dir, err := FindImageDir([]string{a, b}, web); err != nil || dir != a {
		t.Fatal("nearest first", dir, err)
	}
}
