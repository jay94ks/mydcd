// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
)

type Lock struct{ file *os.File }

func LockRoot(root string) (*Lock, error) {
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	path := filepath.Join(root, "node.lock")
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, errors.New("state root already owned")
	}
	return &Lock{f}, nil
}
func (l *Lock) Close() error {
	err := unix.Flock(int(l.file.Fd()), unix.LOCK_UN)
	other := l.file.Close()
	if err != nil {
		return err
	}
	return other
}
