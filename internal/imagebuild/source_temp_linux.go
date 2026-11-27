// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// Use the already held original solve output directory. The fallback's
// random regular file is unlinked/fsynced before any image bytes are written;
// a crash in that tiny creation interval leaves only an empty job-owned file
// for the existing confined whole-workspace cleanup, never a reusable cache.
func sourceTemporaryFile(dir *os.File) (*os.File, error) {
	fd, err := unix.Openat(int(dir.Fd()), ".", unix.O_TMPFILE|unix.O_RDWR|unix.O_CLOEXEC, 0600)
	if err == nil {
		return os.NewFile(uintptr(fd), "sfc-source-body"), nil
	}
	if !errors.Is(err, unix.EOPNOTSUPP) && !errors.Is(err, unix.EINVAL) && !errors.Is(err, unix.EISDIR) {
		return nil, ErrStorage
	}
	var random [24]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, ErrStorage
	}
	name := ".sfc-source-" + hex.EncodeToString(random[:])
	fd, err = unix.Openat(int(dir.Fd()), name, unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_RDWR|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, ErrStorage
	}
	file := os.NewFile(uintptr(fd), "sfc-source-body")
	var held, actual unix.Stat_t
	if unix.Fstat(fd, &held) != nil || unix.Fstatat(int(dir.Fd()), name, &actual, unix.AT_SYMLINK_NOFOLLOW) != nil || held.Dev != actual.Dev || held.Ino != actual.Ino || actual.Mode&unix.S_IFMT != unix.S_IFREG || actual.Nlink != 1 {
		_ = file.Close()
		return nil, ErrStorage
	}
	if unix.Unlinkat(int(dir.Fd()), name, 0) != nil || unix.Fsync(int(dir.Fd())) != nil {
		_ = file.Close()
		return nil, ErrStorage
	}
	return file, nil
}
