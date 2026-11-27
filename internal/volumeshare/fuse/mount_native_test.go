// SPDX-License-Identifier: Apache-2.0

//go:build linux

package fuse

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestRealKernelMount mounts memFS through the real kernel and drives it
// with ordinary file system calls.
func TestRealKernelMount(t *testing.T) {
	if os.Getenv("SFC_FUSE_NATIVE") != "1" || os.Geteuid() != 0 {
		t.Skip("set SFC_FUSE_NATIVE=1 and run as root on a host with /dev/fuse")
	}
	dir := t.TempDir()
	dev, err := Mount(dir, MountOptions{Source: "sfc-test", Subtype: "sfc"})
	if err != nil {
		t.Fatal(err)
	}
	// The test process is also the server: if a call on the mount hangs,
	// the process cannot even exit. Abort only this mount's connection.
	watchdog := time.AfterFunc(10*time.Second, func() { abortConnection(t, dir) })
	defer watchdog.Stop()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	inited := make(chan Session, 1)
	go func() { done <- Serve(ctx, dev, newMemFS(), ServeOptions{OnInit: func(s Session) { inited <- s }}) }()
	unmounted := false
	defer func() {
		if !unmounted && Unmount(dir) != nil {
			abortConnection(t, dir)
			_ = Unmount(dir)
		}
		dev.Close()
	}()
	var negotiated Session
	select {
	case s := <-inited:
		negotiated = s
		if s.Flags&initFlockLocks == 0 || s.Flags&initPosixLocks == 0 {
			t.Fatalf("kernel did not take lock flags: %#x", s.Flags)
		}
	case err := <-done:
		t.Fatalf("Serve ended before INIT: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("no INIT")
	}

	// Files: a write larger than one request, read back, truncate.
	big := make([]byte, 3*MaxWrite+123)
	_, _ = rand.Read(big)
	p := filepath.Join(dir, "big.bin")
	if err = writeFile(p, big, 0o640); err != nil {
		t.Fatal(err)
	}
	got, err := readFile(p)
	if err != nil || !bytes.Equal(got, big) {
		t.Fatalf("read back %d bytes, err %v", len(got), err)
	}
	if err = os.Truncate(p, 10); err != nil {
		t.Fatal(err)
	}
	if st, e := os.Stat(p); e != nil || st.Size() != 10 || st.Mode().Perm() != 0o640 {
		t.Fatalf("stat after truncate: %v %v", st, e)
	}

	// Directories, rename, symlink, readdir, remove.
	if err = os.MkdirAll(filepath.Join(dir, "a", "b"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(p, filepath.Join(dir, "a", "b", "moved.bin")); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink("a/b/moved.bin", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	if target, e := os.Readlink(filepath.Join(dir, "link")); e != nil || target != "a/b/moved.bin" {
		t.Fatalf("readlink %q %v", target, e)
	}
	ents, err := os.ReadDir(dir)
	if err != nil || len(ents) != 2 || ents[0].Name() != "a" || ents[1].Name() != "link" {
		t.Fatalf("readdir %v %v", ents, err)
	}
	if err = os.Remove(filepath.Join(dir, "a")); !errors.Is(err, syscall.ENOTEMPTY) {
		t.Fatalf("rmdir non-empty: %v", err)
	}
	if err = os.RemoveAll(filepath.Join(dir, "a")); err != nil {
		t.Fatal(err)
	}

	var st unix.Statfs_t
	if err = unix.Statfs(dir, &st); err != nil || st.Blocks != 1000 || st.Bavail != 400 {
		t.Fatalf("statfs %+v %v", st, err)
	}

	// flock: two open file descriptions are two owners.
	lp := filepath.Join(dir, "lock")
	f1, err := unix.Open(lp, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if f1 >= 0 {
			unix.Close(f1)
		}
	}()
	f2, err := unix.Open(lp, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if f2 >= 0 {
			unix.Close(f2)
		}
	}()
	if err = unix.Flock(f1, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatalf("first flock: %v", err)
	}
	if err = unix.Flock(f2, unix.LOCK_EX|unix.LOCK_NB); !errors.Is(err, unix.EWOULDBLOCK) {
		t.Fatalf("second flock: %v", err)
	}
	// close returns before the kernel's asynchronous RELEASE (which carries
	// the flock unlock) is served, so wait for the lock instead of LOCK_NB.
	unix.Close(f1)
	f1 = -1
	if err = unix.Flock(f2, unix.LOCK_EX); err != nil {
		t.Fatalf("flock after release: %v", err)
	}
	unix.Close(f2)
	f2 = -1

	// Hand-off: stop this server without unmounting, resume on the same FD
	// (what a restarted sfcd does with an FD from the service manager).
	cancel()
	if err = <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Serve after cancel: %v", err)
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	go func() { done <- Serve(ctx2, dev, newMemFS(), ServeOptions{Resume: &negotiated}) }()
	if err = writeFile(filepath.Join(dir, "after-resume"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write after resume: %v", err)
	}

	if err = Unmount(dir); err != nil {
		t.Fatal(err)
	}
	unmounted = true
	select {
	case err = <-done:
		if err != nil {
			t.Fatalf("Serve after unmount: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not end after unmount")
	}
}

// abortConnection aborts the FUSE connection of the mount at dir through
// fusectl, found by the mount's device number in /proc/self/mountinfo.
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

// writeFile and readFile avoid os.Open on the mount: the Go runtime adds
// every opened file to its netpoller with a raw epoll_ctl that does not
// leave the scheduler, so a FUSE_POLL to this same process during a GC stop
// would never be answered. See the package doc.
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
