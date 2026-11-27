// SPDX-License-Identifier: Apache-2.0

package nodedisks

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/observability"
)

// TestRealLoopDeviceFormatMountUnmount runs the real steps on a loop device
// with partition scanning (losetup -f --show -P img), as root:
// SFC_DISK_TEST_DEVICE=/dev/loop0. It writes to that device.
func TestRealLoopDeviceFormatMountUnmount(t *testing.T) {
	dev := os.Getenv("SFC_DISK_TEST_DEVICE")
	if dev == "" || !strings.HasPrefix(dev, "/dev/loop") {
		t.Skip("set SFC_DISK_TEST_DEVICE=/dev/loopN (it is overwritten)")
	}
	disk := filepath.Base(dev)
	ctx := context.Background()
	_, dg, _ := NewUUID()
	_, pg, _ := NewUUID()
	part, err := Real.WriteTable(ctx, disk, dg, pg)
	head := make([]byte, 0x11000)
	f, _ := os.Open(dev)
	f.ReadAt(head, 0)
	f.Close()
	if kind, _ := observability.ProbeTable(head, 512); kind != "gpt" {
		t.Fatal("device has no gpt", kind)
	}
	if err != nil && !kernelReadsGPT() {
		// A kernel built without CONFIG_EFI_PARTITION (some sandboxes)
		// never makes the partition; go on with the whole device.
		t.Log("kernel has no GPT support; formatting the whole device:", err)
		if err := Real.WipePart(disk); err != nil {
			t.Fatal(err)
		}
		part = disk
	} else if err != nil || part != disk+"p1" {
		t.Fatal("table", part, err)
	}
	uuid, _, _ := NewUUID()
	if err := Real.MakeExt4(ctx, part, uuid, "data"); err != nil {
		t.Fatal(err)
	}
	f, _ = os.Open("/dev/" + part)
	f.ReadAt(head, 0)
	f.Close()
	if sig, ok := observability.ProbeSignature(head); !ok || sig.Filesystem != "ext4" || sig.UUID != uuid || sig.Label != "data" {
		t.Fatal("probe after mkfs", sig, ok)
	}
	point := filepath.Join(t.TempDir(), "mnt")
	if err := PreparePoint(point); err != nil {
		t.Fatal(err)
	}
	if err := Real.Mount(part, point); err != nil {
		t.Fatal(err)
	}
	// O_EXCL now refuses the mounted part and its disk.
	if err := Real.WipePart(part); code(err) != "busy" {
		Unmount(point)
		t.Fatal("wipe of a mounted part", err)
	}
	if _, err := Real.WriteTable(ctx, disk, dg, pg); code(err) != "busy" {
		Unmount(point)
		t.Fatal("table on a disk with a mounted part", err)
	}
	if err := os.WriteFile(filepath.Join(point, "x"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Unmount(point); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(point, "x")); !os.IsNotExist(err) {
		t.Fatal("file left on the mount point after unmount", err)
	}
	// Re-format with a new table over the old filesystem.
	if _, err := Real.WriteTable(ctx, disk, dg, pg); err != nil && kernelReadsGPT() {
		t.Fatal("reformat", err)
	}
}

func kernelReadsGPT() bool {
	raw, err := exec.Command("sh", "-c", "zcat /proc/config.gz 2>/dev/null | grep -c '^CONFIG_EFI_PARTITION=y'; true").Output()
	return err != nil || strings.TrimSpace(string(raw)) != "0" && strings.TrimSpace(string(raw)) != ""
}
