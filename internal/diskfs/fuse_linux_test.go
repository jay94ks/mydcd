// SPDX-License-Identifier: Apache-2.0

package diskfs_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/diskfs"
	"github.com/jay94ks/seafield/internal/nodedisks"
	"github.com/jay94ks/seafield/internal/sfcimg"
	"golang.org/x/sys/unix"
)

// TestMain lets the test binary stand in for `sfcd diskfs serve`.
func TestMain(m *testing.M) {
	if len(os.Args) == 4 && os.Args[1] == "diskfs" && os.Args[2] == "serve" {
		if err := diskfs.Serve(os.Args[3]); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// TestServeProcess starts the server as its own process, reads its
// status, and stops it by unmounting.
func TestServeProcess(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skip("no /dev/fuse")
	}
	bundle := fmt.Sprintf("t%d", os.Getpid())
	spec := diskfs.Spec{Schema: 1, Bundle: bundle, ID: [16]byte{4}, Mode: "linear", Copies: [][]diskfs.ChunkSpec{diskfs.Layout([]diskfs.Member{{Dir: filepath.Join(t.TempDir(), "b"), Bytes: 8 * sfcimg.RegionSize, Part: "sdb1"}, {Dir: filepath.Join(t.TempDir(), "b"), Bytes: 4 * sfcimg.RegionSize, Part: "sdc1"}})}}
	if err := diskfs.Create(spec, true); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(spec)
	specPath := filepath.Join(t.TempDir(), "spec.json")
	if err := os.WriteFile(specPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	exe, _ := os.Executable()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := diskfs.Start(ctx, bundle, specPath, exe); err != nil {
		t.Skip("cannot serve here: ", err)
	}
	defer os.RemoveAll(filepath.Join(diskfs.RunDir, bundle))
	defer diskfs.Stop(bundle)
	if !diskfs.Running(bundle, 12*sfcimg.RegionSize) {
		t.Fatal("not running with the full size")
	}
	if err := diskfs.Start(ctx, bundle, specPath, exe); err != nil {
		t.Fatal("second start", err)
	}
	var status diskfs.Status
	for range 50 {
		var ok bool
		if status, ok = diskfs.ReadStatus(bundle); ok {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if status.State != "ok" || status.Size != 12*sfcimg.RegionSize {
		t.Fatal("status", status)
	}
	f, err := os.OpenFile(diskfs.DiskFile(bundle), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte("x"), 9*sfcimg.RegionSize); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := diskfs.Stop(bundle); err != nil {
		t.Fatal(err)
	}
	if diskfs.Running(bundle, 0) {
		t.Fatal("still running")
	}
	if _, ok := diskfs.ReadStatus(bundle); ok {
		t.Fatal("status left after stop")
	}
	if err := diskfs.Remove(spec); err != nil {
		t.Fatal(err)
	}
}

// TestFuseLoopExt4 runs the whole fuse bundle path as root: chunks →
// FUSE file → loop device → ext4 → files, then reads it again after a
// remount.
func TestFuseLoopExt4(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skip("no /dev/fuse")
	}
	if _, err := exec.LookPath("mkfs.ext4"); err != nil {
		t.Skip("no mkfs.ext4")
	}
	spec := diskfs.Spec{Schema: 1, Bundle: "t", ID: [16]byte{3}, Mode: "mirror"}
	for range 2 {
		spec.Copies = append(spec.Copies, diskfs.Layout([]diskfs.Member{{Dir: filepath.Join(t.TempDir(), "b"), Bytes: 40 * sfcimg.RegionSize, Disk: "sdb", Part: "sdb1"}, {Dir: filepath.Join(t.TempDir(), "b"), Bytes: 24 * sfcimg.RegionSize, Disk: "sdc", Part: "sdc1"}}))
	}
	if err := diskfs.Create(spec, true); err != nil {
		t.Fatal(err)
	}
	mountFS := func() (func(), string) {
		d, err := diskfs.Open(spec)
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(t.TempDir(), "fuse")
		server, err := diskfs.Mount(dir, d)
		if err != nil {
			t.Skip("fuse mount not available here: ", err)
		}
		loop, err := nodedisks.AttachLoop(filepath.Join(dir, "disk"))
		if err != nil {
			server.Unmount()
			t.Fatal(err)
		}
		return func() {
			if err := nodedisks.DetachLoop(loop); err != nil {
				t.Error(err)
			}
			server.Unmount()
			d.Close()
		}, loop
	}
	stop, loop := mountFS()
	uuid, _, _ := nodedisks.NewUUID()
	if err := nodedisks.Real.MakeExt4(context.Background(), loop, uuid, "slow"); err != nil {
		stop()
		t.Fatal(err)
	}
	point := t.TempDir()
	if err := unix.Mount("/dev/"+loop, point, "ext4", 0, ""); err != nil {
		stop()
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte("seafield"), 1<<18) // 2 MiB
	if err := os.WriteFile(filepath.Join(point, "f"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	unix.Unmount(point, 0)
	stop()
	stop, loop = mountFS()
	defer stop()
	if err := unix.Mount("/dev/"+loop, point, "ext4", unix.MS_RDONLY, ""); err != nil {
		t.Fatal(err)
	}
	defer unix.Unmount(point, 0)
	got, err := os.ReadFile(filepath.Join(point, "f"))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("file after remount", err)
	}
	if hdr, alloc, err := sfcimg.Check(filepath.Join(spec.Copies[1][0].Dir, spec.Copies[1][0].File)); err != nil || alloc == 0 || alloc >= hdr.Length {
		t.Fatal("grow chunk", alloc, err)
	}
}
