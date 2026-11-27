// SPDX-License-Identifier: Apache-2.0

//go:build linux

package volumeshare_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/volumeshare"
	"github.com/jay94ks/seafield/internal/volumeshare/front/mount"
	"github.com/jay94ks/seafield/internal/volumeshare/fuse"
	"golang.org/x/sys/unix"
)

// TestRemoteVolumeThroughEngineClone runs the whole consuming path: a
// FUSE mount whose Ops are a VolumeFS client over real SFCP to a home on
// localroot, handed out the way the Seafield engine receives a volume (a
// directory fd that it clones with open_tree and moves to its own path).
func TestRemoteVolumeThroughEngineClone(t *testing.T) {
	if os.Getenv("SFC_FUSE_NATIVE") != "1" || os.Geteuid() != 0 {
		t.Skip("set SFC_FUSE_NATIVE=1 and run as root on a host with /dev/fuse")
	}
	root, dir := openRoot(t)
	server := volumeshare.NewServer(func(context.Context, [32]byte, string) (volumeshare.Ops, error) {
		return root, nil
	}, volumeshare.ServerOptions{})
	consumer, _, homeKey := homePair(t, server)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client, err := volumeshare.Dial(ctx, volumeshare.CallHome(consumer, homeKey), volumeshare.ClientOptions{Volume: "v", Sent: sfcp.CallSent})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "on-home"), []byte("from the home"), 0o644); err != nil {
		t.Fatal(err)
	}

	base := t.TempDir()
	mnt, engine := filepath.Join(base, "mnt"), filepath.Join(base, "engine")
	for _, d := range []string{mnt, engine} {
		if err = os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	dev, err := fuse.Mount(mnt, fuse.MountOptions{Source: "remote-test", Subtype: "sfc"})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- fuse.Serve(ctx, dev, mount.New(client, mount.Options{Session: client.Session(), EntryTTL: time.Second, AttrTTL: time.Second}), fuse.ServeOptions{})
	}()
	cleanup := []string{mnt}
	defer func() {
		for i := len(cleanup) - 1; i >= 0; i-- {
			_ = unix.Unmount(cleanup[i], unix.MNT_DETACH)
		}
	}()
	watchdog := time.AfterFunc(30*time.Second, func() { _ = unix.Unmount(engine, unix.MNT_DETACH); _ = fuse.Unmount(mnt) })
	defer watchdog.Stop()

	// The volume answer: a directory fd, cloned and moved by the engine.
	fd, _, ino, err := mount.RootFD(mnt)
	if err != nil {
		t.Fatal(err)
	}
	tree, err := unix.OpenTree(fd, "", unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC|unix.AT_EMPTY_PATH)
	unix.Close(fd)
	if err != nil {
		t.Fatalf("open_tree: %v", err)
	}
	err = unix.MoveMount(tree, "", unix.AT_FDCWD, engine, unix.MOVE_MOUNT_F_EMPTY_PATH)
	unix.Close(tree)
	if err != nil {
		t.Fatalf("move_mount: %v", err)
	}
	cleanup = append(cleanup, engine)
	var st unix.Stat_t
	if err = unix.Stat(engine, &st); err != nil || st.Ino != ino {
		t.Fatalf("engine path is not the volume root: %v", err)
	}
	got, err := readAll(filepath.Join(engine, "on-home"))
	if err != nil || string(got) != "from the home" {
		t.Fatalf("read through clone: %q %v", got, err)
	}
	want := bytes.Repeat([]byte("container write "), 20000)
	if err = writeAll(filepath.Join(engine, "from-container"), want); err != nil {
		t.Fatal(err)
	}
	if disk, err := os.ReadFile(filepath.Join(dir, "from-container")); err != nil || !bytes.Equal(disk, want) {
		t.Fatalf("home copy differs: %v", err)
	}

	if err = unix.Unmount(engine, 0); err != nil {
		t.Fatalf("engine unmount: %v", err)
	}
	if err = fuse.Unmount(mnt); err != nil {
		t.Fatalf("unmount: %v", err)
	}
	cleanup = nil
	if err = <-done; err != nil {
		t.Fatalf("Serve: %v", err)
	}
}

// readAll/writeAll use plain syscalls: this process serves the mount.
func readAll(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	var out []byte
	buf := make([]byte, 64<<10)
	for {
		n, err := unix.Read(fd, buf)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return out, nil
		}
		out = append(out, buf[:n]...)
	}
}

func writeAll(path string, data []byte) error {
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_TRUNC|unix.O_WRONLY|unix.O_CLOEXEC, 0o644)
	if err != nil {
		return err
	}
	for len(data) > 0 {
		n, err := unix.Write(fd, data)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			unix.Close(fd)
			return err
		}
		data = data[n:]
	}
	return unix.Close(fd)
}
