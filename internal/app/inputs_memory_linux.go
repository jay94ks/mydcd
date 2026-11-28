// SPDX-License-Identifier: Apache-2.0

//go:build linux

package app

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// appInputMemoryBytes bounds the tmpfs that holds this node's app input
// values; it takes memory only for what is written.
const appInputMemoryBytes = 64 << 20

// mountInputMemory makes dir a private tmpfs (mode 0700, no swap where the
// kernel allows it) unless it already is one, so app secret values never
// reach a disk. The mount outlives the daemon until the next boot: a daemon
// restart keeps the values, a reboot empties them.
func mountInputMemory(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	var fs unix.Statfs_t
	if err := unix.Statfs(dir, &fs); err != nil {
		return err
	}
	if fs.Type == unix.TMPFS_MAGIC {
		return nil
	}
	flags := uintptr(unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC)
	options := fmt.Sprintf("mode=0700,size=%d", appInputMemoryBytes)
	err := unix.Mount("tmpfs", dir, "tmpfs", flags, options+",noswap")
	if errors.Is(err, unix.EINVAL) {
		// Kernels before 6.4 have no noswap.
		err = unix.Mount("tmpfs", dir, "tmpfs", flags, options)
	}
	if err != nil {
		return fmt.Errorf("app secret values need a tmpfs at %s: %w", dir, err)
	}
	return nil
}
