// SPDX-License-Identifier: Apache-2.0

package nodedisks

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Host is where the device files and sysfs live (tests use a fake tree
// only for the pure parts; these steps need the real kernel).
type Host struct{ Sys, Dev string }

var Real = Host{Sys: "/sys", Dev: "/dev"}

// NewUUID is a random (version 4) filesystem UUID.
func NewUUID() (string, [16]byte, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", b, err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	s := fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
	return s, b, nil
}

// guidBytes turns a random UUID into GPT's mixed-endian bytes.
func guidBytes(b [16]byte) [16]byte {
	g := b
	g[0], g[1], g[2], g[3] = b[3], b[2], b[1], b[0]
	g[4], g[5] = b[5], b[4]
	g[6], g[7] = b[7], b[6]
	return g
}

func sysText(path string) string {
	raw, _ := os.ReadFile(path)
	return strings.TrimSpace(string(raw))
}

// openExclusive opens a block device for writing. O_EXCL on a block device
// fails while the kernel has it mounted or held, the last guard against a
// stale inventory.
func (h Host) openExclusive(name string) (*os.File, error) {
	path := filepath.Join(h.Dev, name)
	f, err := os.OpenFile(path, os.O_RDWR|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, unix.EBUSY) {
			return nil, refuse("busy", name+" is in use")
		}
		return nil, refuse("io", "open "+name+": "+err.Error())
	}
	var st unix.Stat_t
	if unix.Fstat(int(f.Fd()), &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFBLK || fmt.Sprintf("%d:%d", unix.Major(st.Rdev), unix.Minor(st.Rdev)) != h.devNumber(name) {
		f.Close()
		return nil, refuse("changed", name+" is not the block device sysfs lists")
	}
	return f, nil
}

func (h Host) devNumber(name string) string {
	for _, p := range []string{filepath.Join(h.Sys, "class", "block", name, "dev"), filepath.Join(h.Sys, "block", name, "dev")} {
		if s := sysText(p); s != "" {
			return s
		}
	}
	return ""
}

func zero(f *os.File, offset, n int64) error {
	buf := make([]byte, 1<<20)
	for n > 0 {
		chunk := min(n, int64(len(buf)))
		if _, err := f.WriteAt(buf[:chunk], offset); err != nil {
			return err
		}
		offset, n = offset+chunk, n-chunk
	}
	return nil
}

// PartitionName is the kernel's name for partition number of disk.
func PartitionName(disk string, number int) string {
	if last := disk[len(disk)-1]; last >= '0' && last <= '9' {
		return disk + "p" + strconv.Itoa(number)
	}
	return disk + strconv.Itoa(number)
}

// WriteTable wipes the disk's old tables and signatures and writes a new
// GPT table with one partition, then asks the kernel to read it. It
// returns the new partition's name once its device file exists.
func (h Host) WriteTable(ctx context.Context, disk string, diskGUID, partGUID [16]byte) (string, error) {
	f, err := h.openExclusive(disk)
	if err != nil {
		return "", err
	}
	defer f.Close()
	size, err := f.Seek(0, 2)
	if err != nil || size <= 0 {
		return "", refuse("io", "size of "+disk)
	}
	sector, err := unix.IoctlGetInt(int(f.Fd()), unix.BLKSSZGET)
	if err != nil {
		return "", refuse("io", "sector size of "+disk)
	}
	g, err := BuildGPT(sector, uint64(size)/uint64(sector), guidBytes(diskGUID), guidBytes(partGUID), "seafield")
	if err != nil {
		return "", refuse("io", err.Error())
	}
	wipe := int64(gptAlign)
	if err := zero(f, 0, min(wipe, size)); err != nil {
		return "", refuse("io", "wipe "+disk+": "+err.Error())
	}
	if size > wipe {
		if err := zero(f, size-wipe, wipe); err != nil {
			return "", refuse("io", "wipe "+disk+": "+err.Error())
		}
	}
	if _, err := f.WriteAt(g.Primary, 0); err != nil {
		return "", refuse("io", "write table: "+err.Error())
	}
	if _, err := f.WriteAt(g.Backup, g.BackupOffset); err != nil {
		return "", refuse("io", "write backup table: "+err.Error())
	}
	if err := f.Sync(); err != nil {
		return "", refuse("io", "sync "+disk+": "+err.Error())
	}
	if err := unix.IoctlSetInt(int(f.Fd()), unix.BLKRRPART, 0); err != nil {
		return "", refuse("io", "kernel did not reread the table of "+disk+": "+err.Error())
	}
	part := PartitionName(disk, 1)
	deadline := time.Now().Add(20 * time.Second)
	for {
		if h.devNumber(part) != "" {
			if _, err := os.Stat(filepath.Join(h.Dev, part)); err == nil {
				return part, nil
			}
		}
		if time.Now().After(deadline) {
			return "", refuse("io", "partition "+part+" did not appear")
		}
		select {
		case <-ctx.Done():
			return "", refuse("interrupted", ctx.Err().Error())
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// WipePart clears the first MiB of a partition so an old signature cannot
// survive next to the new filesystem.
func (h Host) WipePart(part string) error {
	f, err := h.openExclusive(part)
	if err != nil {
		return err
	}
	defer f.Close()
	size, err := f.Seek(0, 2)
	if err != nil {
		return refuse("io", "size of "+part)
	}
	if err := zero(f, 0, min(size, gptAlign)); err != nil {
		return refuse("io", "wipe "+part+": "+err.Error())
	}
	if err := f.Sync(); err != nil {
		return refuse("io", "sync "+part+": "+err.Error())
	}
	return nil
}

// MakeExt4 runs mkfs.ext4 with a UUID chosen (and journaled) beforehand.
func (h Host) MakeExt4(ctx context.Context, part, uuid, label string) error {
	tool, err := exec.LookPath("mkfs.ext4")
	if err != nil {
		return refuse("tool", "mkfs.ext4 is not installed (e2fsprogs)")
	}
	args := []string{"-F", "-q", "-U", uuid, "-E", "lazy_itable_init=1,lazy_journal_init=1"}
	if label != "" {
		args = append(args, "-L", label)
	}
	cmd := exec.CommandContext(ctx, tool, append(args, filepath.Join(h.Dev, part))...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		detail := strings.TrimSpace(out.String())
		if len(detail) > 300 {
			detail = detail[:300]
		}
		return refuse("tool", "mkfs.ext4: "+err.Error()+" "+detail)
	}
	return nil
}

// PreparePoint makes the mount point, or accepts an existing empty
// directory that is not a symlink.
func PreparePoint(path string) error {
	st, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(path, 0o755); err != nil {
			return refuse("mount-path", "create "+path+": "+err.Error())
		}
		return nil
	}
	if err != nil || !st.IsDir() {
		return refuse("mount-path", path+" exists and is not a directory")
	}
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) > 0 {
		return refuse("mount-path", path+" is not empty")
	}
	return nil
}

// Mount mounts an ext4 part at path. path was prepared and checked.
func (h Host) Mount(part, path string) error {
	if err := unix.Mount(filepath.Join(h.Dev, part), path, "ext4", 0, ""); err != nil {
		if errors.Is(err, unix.EBUSY) {
			return refuse("busy", part+" is already mounted")
		}
		return refuse("io", "mount "+part+" at "+path+": "+err.Error())
	}
	return nil
}

func Unmount(path string) error {
	if err := unix.Unmount(path, 0); err != nil {
		if errors.Is(err, unix.EBUSY) {
			return refuse("in-use", "files on "+path+" are still open")
		}
		if errors.Is(err, unix.EINVAL) {
			return nil // not mounted any more
		}
		return refuse("io", "unmount "+path+": "+err.Error())
	}
	return nil
}

// MakeRootDir makes sub (control.ValidDiskSubPath) under mount, each missing
// part 0700, without leaving the mounted filesystem and without following a
// symlink. An existing directory is kept as it is.
func MakeRootDir(mount, sub string) error {
	fd, err := unix.Openat2(unix.AT_FDCWD, mount, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return refuse("mount-path", "open "+mount+": "+err.Error())
	}
	if sub == "" {
		return unix.Close(fd)
	}
	for _, part := range strings.Split(sub, "/") {
		if err := unix.Mkdirat(fd, part, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
			_ = unix.Close(fd)
			return refuse("mount-path", "create "+part+" under "+mount+": "+err.Error())
		}
		next, err := unix.Openat2(fd, part, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
		_ = unix.Close(fd)
		if err != nil {
			return refuse("mount-path", mount+"/"+sub+" is not a plain directory on that disk: "+err.Error())
		}
		fd = next
	}
	return unix.Close(fd)
}
