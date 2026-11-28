// SPDX-License-Identifier: Apache-2.0

package pathfs

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/jay94ks/seafield/internal/volumeshare"
	"github.com/jay94ks/seafield/internal/volumeshare/back/localroot"
)

func openFS(t *testing.T) (*FS, string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root (open_by_handle_at requires CAP_DAC_READ_SEARCH)")
	}
	dir := filepath.Join(t.TempDir(), "vol")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	r, err := localroot.Open(dir, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Shutdown() })
	return New(r, volumeshare.Caller{UID: 1000, GID: 1000}, 1), dir
}

func TestSplitRefusesEscapes(t *testing.T) {
	for _, ok := range []string{"", "/", "a", "/a/b", "a/b/", "..a", "a..b"} {
		if _, err := Split(ok); err != nil {
			t.Fatalf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"..", "a/../b", "./a", "a//b", "//", "a/.", "a\x00b", strings.Repeat("x", 256)} {
		if _, err := Split(bad); err == nil {
			t.Fatalf("split %q", bad)
		}
	}
}

// Put replaces whole, makes parents, owns the file as the caller, and a
// large body crosses many VolumeFS chunks.
func TestPutAndRead(t *testing.T) {
	fs, dir := openFS(t)
	ctx := context.Background()
	body := bytes.Repeat([]byte("0123456789abcdef"), (3*Chunk+100)/16)
	e, err := fs.Put(ctx, "/a/b/c.bin", bytes.NewReader(body), 0o640)
	if err != nil || e.Attr.Size != uint64(len(body)) {
		t.Fatal(e.Attr.Size, err)
	}
	st, err := os.Stat(filepath.Join(dir, "a/b/c.bin"))
	if err != nil || st.Mode().Perm() != 0o640 || st.Sys().(*syscall.Stat_t).Uid != 1000 {
		t.Fatal(st, err)
	}
	if _, err := fs.Put(ctx, "a/b/c.bin", strings.NewReader("short"), 0o640); err != nil {
		t.Fatal(err)
	}
	f, err := fs.Open(ctx, "a/b/c.bin", syscall.O_RDONLY)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got, err := io.ReadAll(io.NewSectionReader(f, 0, 1<<20))
	if err != nil || string(got) != "short" {
		t.Fatalf("%q %v", got, err)
	}
	left, _ := os.ReadDir(filepath.Join(dir, "a/b"))
	if len(left) != 1 {
		t.Fatal("put left files", left)
	}
	if _, err := fs.Put(ctx, "a/"+tempPrefix+"x", strings.NewReader(""), 0o600); err == nil {
		t.Fatal("put a temp name")
	}
	if _, err := fs.Put(ctx, "/", strings.NewReader(""), 0o600); !errors.Is(err, syscall.EISDIR) {
		t.Fatal("put the root", err)
	}
	// A failed read leaves nothing behind.
	if _, err := fs.Put(ctx, "a/fail", io.MultiReader(strings.NewReader("x"), failing{}), 0o600); err == nil {
		t.Fatal("failed body stored")
	}
	if left, _ := os.ReadDir(filepath.Join(dir, "a")); len(left) != 1 {
		t.Fatal("failed put left files", left)
	}
	if _, err := fs.Open(ctx, "a", syscall.O_RDONLY); !errors.Is(err, syscall.EISDIR) {
		t.Fatal(err)
	}
}

type failing struct{}

func (failing) Read([]byte) (int, error) { return 0, errors.New("gone") }

// A symbolic link in the middle of a path is never followed, even one that
// points inside the Volume; one at the end is returned as itself.
func TestNoSymlinkWalk(t *testing.T) {
	fs, dir := openFS(t)
	ctx := context.Background()
	if err := os.Symlink("/etc", filepath.Join(dir, "out")); err != nil {
		t.Fatal(err)
	}
	_ = os.Mkdir(filepath.Join(dir, "in"), 0o755)
	if err := os.Symlink("in", filepath.Join(dir, "alias")); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"out/passwd", "alias/x"} {
		if _, err := fs.Resolve(ctx, p); !errors.Is(err, syscall.ELOOP) {
			t.Fatal(p, err)
		}
		if _, err := fs.Put(ctx, p, strings.NewReader("x"), 0o600); !errors.Is(err, syscall.ELOOP) {
			t.Fatal("put", p, err)
		}
	}
	if _, err := fs.MkdirAll(ctx, "alias/y", 0o755); !errors.Is(err, syscall.ELOOP) {
		t.Fatal(err)
	}
	if e, err := fs.Resolve(ctx, "out"); err != nil || e.Attr.Mode&syscall.S_IFMT != syscall.S_IFLNK {
		t.Fatal(err)
	}
	if _, err := fs.Open(ctx, "out", syscall.O_RDONLY); err == nil {
		t.Fatal("opened a link")
	}
	if _, err := os.Stat(filepath.Join(dir, "in", "y")); err == nil {
		t.Fatal("followed")
	}
}

// Keys pages in byte order of the whole path, across directories, with a
// prefix, and skips subtrees, links and unfinished puts.
func TestKeysOrder(t *testing.T) {
	fs, dir := openFS(t)
	ctx := context.Background()
	paths := []string{"a-b", "a/b", "a/c/d", "a0", "b/x", "b/y/z", "ab", "a/c-", "a/c/e"}
	for _, p := range paths {
		if _, err := fs.Put(ctx, p, strings.NewReader(p), 0o644); err != nil {
			t.Fatal(p, err)
		}
	}
	_ = os.Symlink("a0", filepath.Join(dir, "link"))
	_ = os.WriteFile(filepath.Join(dir, "b", tempPrefix+"1"), nil, 0o600)
	_ = os.Mkdir(filepath.Join(dir, "empty"), 0o755)
	want := []string{"a-b", "a/b", "a/c-", "a/c/d", "a/c/e", "a0", "ab", "b/x", "b/y/z"}
	list := func(prefix, after string, max int) []string {
		ks, err := fs.Keys(ctx, prefix, after, max)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, k := range ks {
			if k.Entry.Attr.Size != uint64(len(k.Path)) {
				t.Fatal("entry of", k.Path)
			}
			out = append(out, k.Path)
		}
		return out
	}
	if got := list("", "", 100); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatal(got)
	}
	// Paging by the last key gives the same order.
	var paged []string
	for after := ""; ; {
		page := list("", after, 2)
		if len(page) == 0 {
			break
		}
		paged = append(paged, page...)
		after = page[len(page)-1]
	}
	if strings.Join(paged, " ") != strings.Join(want, " ") {
		t.Fatal(paged)
	}
	if got := list("a/c", "", 100); strings.Join(got, " ") != "a/c- a/c/d a/c/e" {
		t.Fatal(got)
	}
	if got := list("a/c/", "a/c/d", 100); strings.Join(got, " ") != "a/c/e" {
		t.Fatal(got)
	}
	if got := list("zz", "", 100); len(got) != 0 {
		t.Fatal(got)
	}
}
