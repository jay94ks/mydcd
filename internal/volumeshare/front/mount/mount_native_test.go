// SPDX-License-Identifier: Apache-2.0

//go:build linux

package mount

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/volumeshare/back/localroot"
	"github.com/jay94ks/seafield/internal/volumeshare/fuse"
	"golang.org/x/sys/unix"
)

// TestMountOverLocalRoot serves a real directory through the whole local
// path (FUSE driver → mount front-end → localroot) and checks that what the
// mount shows is what is on disk, including locks shared with processes
// that use the directory directly.
func TestMountOverLocalRoot(t *testing.T) {
	if os.Getenv("SFC_FUSE_NATIVE") != "1" || os.Geteuid() != 0 {
		t.Skip("set SFC_FUSE_NATIVE=1 and run as root on a host with /dev/fuse")
	}
	base := t.TempDir()
	data, mnt := filepath.Join(base, "data"), filepath.Join(base, "mnt")
	for _, d := range []string{data, mnt} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	root, err := localroot.Open(data, bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Shutdown()
	dev, err := fuse.Mount(mnt, fuse.MountOptions{Source: "volume-test", Subtype: "sfc"})
	if err != nil {
		t.Fatal(err)
	}
	watchdog := time.AfterFunc(30*time.Second, func() { abortConnection(t, mnt) })
	defer watchdog.Stop()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- fuse.Serve(ctx, dev, New(root, Options{Session: 1, EntryTTL: time.Second, AttrTTL: time.Second}), fuse.ServeOptions{})
	}()
	unmounted := false
	defer func() {
		if !unmounted && fuse.Unmount(mnt) != nil {
			abortConnection(t, mnt)
			_ = fuse.Unmount(mnt)
		}
		dev.Close()
	}()

	big := make([]byte, 2*fuse.MaxWrite+77)
	_, _ = rand.Read(big)
	if err = os.MkdirAll(filepath.Join(mnt, "a", "b"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err = writeFile(filepath.Join(mnt, "a", "b", "big"), big, 0o640); err != nil {
		t.Fatal(err)
	}
	if raw, e := os.ReadFile(filepath.Join(data, "a", "b", "big")); e != nil || !bytes.Equal(raw, big) {
		t.Fatalf("on disk %d bytes, %v", len(raw), e)
	}
	if st, e := os.Stat(filepath.Join(data, "a", "b")); e != nil || st.Mode().Perm() != 0o750 {
		t.Fatalf("dir mode on disk %v %v", st, e)
	}
	// A change made on the home side shows through the mount.
	if err = os.WriteFile(filepath.Join(data, "from-home"), []byte("home"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, e := readFile(filepath.Join(mnt, "from-home")); e != nil || string(got) != "home" {
		t.Fatalf("home write through mount %q %v", got, e)
	}
	ents, err := os.ReadDir(mnt)
	if err != nil || len(ents) != 2 || ents[0].Name() != "a" || ents[1].Name() != "from-home" {
		t.Fatalf("readdir %v %v", ents, err)
	}
	if err = os.Rename(filepath.Join(mnt, "from-home"), filepath.Join(mnt, "a", "moved")); err != nil {
		t.Fatal(err)
	}
	if _, e := os.Stat(filepath.Join(data, "a", "moved")); e != nil {
		t.Fatalf("rename on disk: %v", e)
	}
	if err = os.Symlink("../../etc/passwd", filepath.Join(mnt, "ln")); err != nil {
		t.Fatal(err)
	}
	if tgt, e := os.Readlink(filepath.Join(data, "ln")); e != nil || tgt != "../../etc/passwd" {
		t.Fatalf("symlink on disk %q %v", tgt, e)
	}

	// flock through the mount conflicts with flock on the home directly.
	lp := filepath.Join(mnt, "lock")
	fd, err := unix.Open(lp, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatalf("flock through mount: %v", err)
	}
	hd, err := unix.Open(filepath.Join(data, "lock"), unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = unix.Flock(hd, unix.LOCK_EX|unix.LOCK_NB); !errors.Is(err, unix.EWOULDBLOCK) {
		t.Fatalf("home flock against mount lock: %v", err)
	}
	unix.Close(fd)
	if err = unix.Flock(hd, unix.LOCK_EX); err != nil { // granted once RELEASE reaches the home
		t.Fatalf("home flock after release: %v", err)
	}
	unix.Close(hd)

	if err = os.RemoveAll(filepath.Join(mnt, "a")); err != nil {
		t.Fatal(err)
	}
	if _, e := os.Stat(filepath.Join(data, "a")); !errors.Is(e, os.ErrNotExist) {
		t.Fatalf("removed dir still on disk: %v", e)
	}

	if err = fuse.Unmount(mnt); err != nil {
		t.Fatal(err)
	}
	unmounted = true
	if err = <-done; err != nil {
		t.Fatalf("Serve: %v", err)
	}
}

// writeFile/readFile use plain syscalls: this process serves the mount, so
// it must not os.Open files on it (see the fuse package doc).
func writeFile(path string, data []byte, mode uint32) error {
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_TRUNC|unix.O_WRONLY|unix.O_CLOEXEC, mode)
	if err != nil {
		return err
	}
	for len(data) > 0 {
		n, e := unix.Write(fd, data)
		if e != nil {
			unix.Close(fd)
			return e
		}
		data = data[n:]
	}
	return unix.Close(fd)
}

func readFile(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	var out []byte
	buf := make([]byte, 64<<10)
	for {
		n, e := unix.Read(fd, buf)
		if e != nil {
			return nil, e
		}
		if n == 0 {
			return out, nil
		}
		out = append(out, buf[:n]...)
	}
}

func abortConnection(t *testing.T, dir string) {
	raw, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) > 4 && f[4] == dir {
			if _, minor, ok := strings.Cut(f[2], ":"); ok {
				t.Errorf("aborting hung FUSE connection %s", minor)
				_ = os.WriteFile("/sys/fs/fuse/connections/"+minor+"/abort", []byte("1"), 0)
			}
		}
	}
}
