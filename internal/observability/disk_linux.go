// SPDX-License-Identifier: Apache-2.0

package observability

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// InspectDisk accepts only a path selected by the runtime from its fixed
// system/Docker root or current registered root. No management query supplies
// an arbitrary path. It reads one filesystem and never scans its contents.
func InspectDisk(ctx context.Context, node, selected string) (Disk, error) {
	if err := ctx.Err(); err != nil {
		return Disk{}, err
	}
	path, err := filepath.EvalSymlinks(selected)
	if err != nil || !filepath.IsAbs(path) {
		return Disk{}, ErrReport
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return Disk{}, err
	}
	defer unix.Close(fd)
	var fs unix.Statfs_t
	var st unix.Stat_t
	if unix.Fstatfs(fd, &fs) != nil || unix.Fstat(fd, &st) != nil || fs.Bsize <= 0 || fs.Blocks == 0 || fs.Bfree > fs.Blocks || fs.Bavail > fs.Bfree || fs.Blocks > ^uint64(0)/uint64(fs.Bsize) {
		return Disk{}, ErrReport
	}
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return Disk{}, err
	}
	defer f.Close()
	mount, device, kind, err := selectedMount(io.LimitReader(f, 16<<20), path)
	if err != nil {
		return Disk{}, err
	}
	unit := uint64(fs.Bsize)
	filesystem := fmt.Sprintf("%v/%d", fs.Fsid, fs.Type)
	// Btrfs subvolumes may have different st_dev values while sharing the
	// same filesystem space. Prefer FSID; use the device only if FSID is absent.
	if fs.Fsid.Val == ([2]int32{}) {
		filesystem = fmt.Sprintf("device/%d/%d", st.Dev, fs.Type)
	}
	d := Disk{ID: FilesystemID(node, filesystem), Mount: mount, Device: device, Filesystem: kind, Total: fs.Blocks * unit, Free: fs.Bfree * unit, Available: fs.Bavail * unit, InodesFree: fs.Ffree}
	d.Used = d.Total - d.Free
	if err := ctx.Err(); err != nil {
		return Disk{}, err
	}
	return d, nil
}

func selectedMount(r io.Reader, path string) (string, string, string, error) {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 4096), 1<<20)
	mount, device, kind := "", "", ""
	decode := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	for s.Scan() {
		parts := strings.SplitN(s.Text(), " - ", 2)
		if len(parts) != 2 {
			return "", "", "", ErrReport
		}
		left, right := strings.Fields(parts[0]), strings.Fields(parts[1])
		if len(left) < 6 || len(right) < 2 {
			return "", "", "", ErrReport
		}
		candidate := decode.Replace(left[4])
		if (candidate == "/" || path == candidate || strings.HasPrefix(path, candidate+"/")) && len(candidate) > len(mount) {
			mount, device, kind = candidate, decode.Replace(right[1]), right[0]
		}
	}
	if s.Err() != nil || mount == "" {
		return "", "", "", ErrReport
	}
	return mount, device, kind, nil
}
