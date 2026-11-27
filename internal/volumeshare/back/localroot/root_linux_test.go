// SPDX-License-Identifier: Apache-2.0

package localroot

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/volumeshare"
	"golang.org/x/sys/unix"
)

func openRoot(t *testing.T) (*Root, string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root (open_by_handle_at requires CAP_DAC_READ_SEARCH)")
	}
	base := t.TempDir()
	dir := filepath.Join(base, "vol")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	r, err := Open(dir, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Shutdown() })
	return r, dir
}

func TestFilesAndDirectories(t *testing.T) {
	r, dir := openRoot(t)
	ctx := context.Background()
	me := volumeshare.Caller{UID: 1234, GID: 5678}

	d, err := r.Mkdir(ctx, me, r.Root(), "sub", 0o750)
	if err != nil {
		t.Fatal(err)
	}
	if d.Attr.Mode != syscall.S_IFDIR|0o750 || d.Attr.UID != 1234 || d.Attr.GID != 5678 {
		t.Fatalf("mkdir attr %+v", d.Attr)
	}
	e, fid, err := r.Create(ctx, 1, me, d.Handle, "a.txt", unix.O_RDWR, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := r.Write(ctx, fid, 2, []byte("hello")); err != nil || n != 5 {
		t.Fatalf("write %d %v", n, err)
	}
	if err = r.Fsync(ctx, fid, false); err != nil {
		t.Fatal(err)
	}
	if got, err := r.Read(ctx, fid, 0, 100); err != nil || string(got) != "\x00\x00hello" {
		t.Fatalf("read %q %v", got, err)
	}
	if err = r.Close(fid); err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(filepath.Join(dir, "sub", "a.txt")); err != nil || string(raw) != "\x00\x00hello" {
		t.Fatalf("on disk %q %v", raw, err)
	}

	// Handles survive a new Root with the same key (a home restart).
	r2, err := Open(dir, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Shutdown()
	if a, err := r2.GetAttr(ctx, e.Handle); err != nil || a.Size != 7 {
		t.Fatalf("attr after reopen %+v %v", a, err)
	}

	if _, err = r.Link(ctx, e.Handle, r.Root(), "hard"); err != nil {
		t.Fatal(err)
	}
	if err = r.Rename(ctx, r.Root(), "hard", d.Handle, "b.txt", 0); err != nil {
		t.Fatal(err)
	}
	if _, err = r.Symlink(ctx, me, r.Root(), "ln", "sub/a.txt"); err != nil {
		t.Fatal(err)
	}
	ln, _ := r.Lookup(ctx, r.Root(), "ln")
	if target, err := r.Readlink(ctx, ln.Handle); err != nil || target != "sub/a.txt" {
		t.Fatalf("readlink %q %v", target, err)
	}
	a, err := r.SetAttr(ctx, me, e.Handle, volumeshare.SetAttr{Valid: 1<<3 | 1<<0 | 1<<5, Size: 3, Mode: 0o600, Mtime: time.Unix(1000, 0)})
	if err != nil || a.Size != 3 || a.Mode&0o7777 != 0o600 || a.Mtime.Unix() != 1000 {
		t.Fatalf("setattr %+v %v", a, err)
	}

	// ReadDir pages through every entry exactly once.
	for _, n := range []string{"c", "d", "e", "f"} {
		if _, f, err := r.Create(ctx, 1, me, d.Handle, n, unix.O_WRONLY, 0o600); err != nil {
			t.Fatal(err)
		} else {
			r.Close(f)
		}
	}
	seen := map[string]bool{}
	var cookie uint64
	for {
		rows, err := r.ReadDir(ctx, d.Handle, cookie, 2)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) == 0 {
			break
		}
		for _, row := range rows {
			if seen[row.Name] {
				t.Fatalf("%s listed twice", row.Name)
			}
			seen[row.Name] = true
			cookie = row.Cookie
		}
	}
	if len(seen) != 6 {
		t.Fatalf("listed %v", seen)
	}

	if err = r.Rmdir(ctx, r.Root(), "sub"); !errors.Is(err, syscall.ENOTEMPTY) {
		t.Fatalf("rmdir non-empty: %v", err)
	}
	if err = r.Unlink(ctx, r.Root(), "ln"); err != nil {
		t.Fatal(err)
	}
	if st, err := r.StatFs(ctx); err != nil || st.Blocks == 0 {
		t.Fatalf("statfs %+v %v", st, err)
	}
}

func TestStaysInsideTheVolume(t *testing.T) {
	r, dir := openRoot(t)
	ctx := context.Background()
	outside := filepath.Join(filepath.Dir(dir), "secret")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "escape")); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"..", ".", "a/b", ""} {
		if _, err := r.Lookup(ctx, r.Root(), name); !errors.Is(err, syscall.EINVAL) {
			t.Fatalf("lookup %q: %v", name, err)
		}
	}
	// A symlink is an entry of its own; opening it never follows it.
	e, err := r.Lookup(ctx, r.Root(), "escape")
	if err != nil || e.Attr.Mode&syscall.S_IFMT != syscall.S_IFLNK {
		t.Fatalf("lookup symlink %+v %v", e.Attr, err)
	}
	if _, err = r.Open(ctx, 1, e.Handle, unix.O_RDONLY); err == nil {
		t.Fatal("opened through a symlink")
	}
	if _, _, err = r.Create(ctx, 1, volumeshare.Caller{}, r.Root(), "escape", unix.O_WRONLY|unix.O_TRUNC, 0o600); err == nil {
		t.Fatal("created through a symlink")
	}
	if raw, _ := os.ReadFile(outside); string(raw) != "x" {
		t.Fatal("outside file changed")
	}

	// Handles are sealed: a forged or another Volume's handle is refused.
	other, err := Open(filepath.Dir(dir), bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Shutdown()
	if _, err = r.GetAttr(ctx, other.Root()); !errors.Is(err, syscall.ESTALE) {
		t.Fatalf("foreign handle: %v", err)
	}
	forged := append(volumeshare.Handle(nil), r.Root()...)
	forged[5] ^= 1
	if _, err = r.GetAttr(ctx, forged); !errors.Is(err, syscall.ESTALE) {
		t.Fatalf("forged handle: %v", err)
	}
}

func TestLocksAreScopedBySessionAndOwner(t *testing.T) {
	r, dir := openRoot(t)
	ctx := context.Background()
	e, f1, err := r.Create(ctx, 1, volumeshare.Caller{}, r.Root(), "lock", unix.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	f2, err := r.Open(ctx, 2, e.Handle, unix.O_RDWR)
	if err != nil {
		t.Fatal(err)
	}
	whole := volumeshare.Lock{Start: 0, End: ^uint64(0), Type: unix.F_WRLCK}
	for _, flock := range []bool{true, false} {
		if err = r.SetLk(ctx, f1, 10, whole, false, flock); err != nil {
			t.Fatalf("flock=%v first: %v", flock, err)
		}
		// Same owner number, other session: still another owner.
		if err = r.SetLk(ctx, f2, 10, whole, false, flock); !errors.Is(err, syscall.EAGAIN) {
			t.Fatalf("flock=%v conflict: %v", flock, err)
		}
	}
	got, err := r.GetLk(ctx, f2, 10, whole, false)
	if err != nil || got.Type != unix.F_WRLCK {
		t.Fatalf("getlk %+v %v", got, err)
	}

	// A process on the home itself sees the remote lock.
	fd, err := unix.Open(filepath.Join(dir, "lock"), unix.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); !errors.Is(err, unix.EWOULDBLOCK) {
		t.Fatalf("local flock against remote: %v", err)
	}

	// A waiter is granted once session 1 goes away; an interrupted waiter gets EINTR.
	cctx, cancel := context.WithTimeout(ctx, 30*time.Millisecond)
	if err = r.SetLk(cctx, f2, 10, whole, true, false); !errors.Is(err, syscall.EINTR) {
		t.Fatalf("cancelled wait: %v", err)
	}
	cancel()
	done := make(chan error, 1)
	go func() { done <- r.SetLk(ctx, f2, 10, whole, true, false) }()
	time.Sleep(20 * time.Millisecond)
	r.Release(1)
	select {
	case err = <-done:
		if err != nil {
			t.Fatalf("wait after release: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("waiter not granted after the holder's session was released")
	}
	if _, err = r.Read(ctx, f1, 0, 1); !errors.Is(err, syscall.EBADF) {
		t.Fatalf("file of released session: %v", err)
	}
}
