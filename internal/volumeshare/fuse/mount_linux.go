// SPDX-License-Identifier: Apache-2.0

package fuse

import (
	"errors"
	"fmt"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// MountOptions describes one mount. The mount is always nosuid,nodev and
// lets every local user through to the FileSystem (allow_other); the kernel
// checks file modes itself (default_permissions).
type MountOptions struct {
	// Source is shown in /proc/mounts (for example the Volume key).
	Source string
	// Subtype makes the type "fuse.<Subtype>".
	Subtype string
	// ReadOnly mounts with MS_RDONLY.
	ReadOnly bool
}

// Mount opens /dev/fuse and mounts it on dir, which must be an existing
// absolute directory. It needs CAP_SYS_ADMIN (sfcd runs as root); no
// fusermount helper is used. The caller then runs Serve on the Device.
func Mount(dir string, o MountOptions) (*Device, error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return nil, fmt.Errorf("fuse: mount point %q is not a clean absolute path", dir)
	}
	if o.Source == "" || o.Subtype == "" {
		return nil, errors.New("fuse: mount source and subtype are required")
	}
	fd, err := unix.Open("/dev/fuse", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("fuse: open /dev/fuse: %w", err)
	}
	var st unix.Stat_t
	if err = unix.Stat(dir, &st); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("fuse: mount point: %w", err)
	}
	data := fmt.Sprintf("fd=%d,rootmode=%o,user_id=0,group_id=0,allow_other,default_permissions,max_read=%d", fd, st.Mode&unix.S_IFMT, MaxWrite)
	flags := uintptr(unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOATIME)
	if o.ReadOnly {
		flags |= unix.MS_RDONLY
	}
	if err = unix.Mount(o.Source, dir, "fuse."+o.Subtype, flags, data); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("fuse: mount %s: %w", dir, err)
	}
	dev, err := NewDevice(fd)
	if err != nil {
		_ = unix.Unmount(dir, 0)
		unix.Close(fd)
		return nil, err
	}
	return dev, nil
}

// Unmount unmounts dir. It does not detach lazily: a busy mount stays and
// the error says so, so callers settle its users first.
func Unmount(dir string) error {
	if err := unix.Unmount(dir, 0); err != nil {
		return fmt.Errorf("fuse: unmount %s: %w", dir, err)
	}
	return nil
}
