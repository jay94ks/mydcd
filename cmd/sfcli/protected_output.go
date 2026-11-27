// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"os"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// A protected output descriptor (--token-output-fd and similar) receives a
// secret without it passing through stdout or a path the CLI opens.

type registryOutputFD struct {
	value int
	set   bool
}

func (f *registryOutputFD) String() string {
	if !f.set {
		return ""
	}
	return strconv.Itoa(f.value)
}
func (f *registryOutputFD) Set(raw string) error {
	n, err := strconv.Atoi(raw)
	if f.set || err != nil || n < 3 || n > 1<<20 {
		return errors.New("protected registry output descriptor must occur once and be at least 3")
	}
	f.value, f.set = n, true
	return nil
}

// Duplicate only the explicit caller descriptor. Never open a user pathname,
// change file modes, write stdout/stderr, or close the caller's original FD.
func registryCredentialOutput(fd registryOutputFD) (*os.File, error) {
	if !fd.set || fd.value < 3 {
		return nil, errors.New("protected registry output descriptor required")
	}
	flags, err := unix.FcntlInt(uintptr(fd.value), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE == unix.O_RDONLY {
		return nil, errors.New("registry output descriptor is not writable")
	}
	dup, err := unix.FcntlInt(uintptr(fd.value), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(dup), "registry-credential-output")
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	private := false
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		private = info.Mode().IsRegular() && info.Mode().Perm()&0077 == 0 && st.Uid == uint32(os.Geteuid())
	}
	if !private && info.Mode()&(os.ModeNamedPipe|os.ModeSocket) == 0 {
		_ = f.Close()
		return nil, errors.New("registry output must be a pipe, socket or private owned regular file")
	}
	return f, nil
}
