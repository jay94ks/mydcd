// SPDX-License-Identifier: Apache-2.0

package enginemux

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

// soPeerPIDFD is SO_PEERPIDFD (Linux 6.5+; Ubuntu 24.04 ships 6.8).
const soPeerPIDFD = 77

// InstallDirs are where packaged sfc binaries may live.
var InstallDirs = []string{"/usr/lib/sfc/bin", "/usr/local/lib/sfc/bin", "/usr/local/bin"}

var ErrPeer = errors.New("engine socket peer is not the expected root process")

// CheckPeer admits the process at the other end of c only when it runs as
// root and its executable is name in one of InstallDirs. The process is
// pinned with a pidfd before its executable is read and must still be alive
// afterwards, so a recycled PID cannot pass as it. No key or nonce is
// exchanged: only root can open these 0600 root-owned sockets, and root can
// read any key file anyway.
func CheckPeer(c *net.UnixConn, name string) error {
	return CheckPeerExe(c, func(exe string) bool { return Installed(exe, name) })
}

// CheckPeerExe is CheckPeer with the executable rule given by allowed. The
// root and pidfd checks are the same.
func CheckPeerExe(c *net.UnixConn, allowed func(exe string) bool) error {
	if allowed == nil {
		return ErrPeer
	}
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var cred *unix.Ucred
	var pidfd int
	var credErr, pidErr error
	if err = raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		pidfd, pidErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, soPeerPIDFD)
	}); err != nil {
		return err
	}
	if credErr != nil || pidErr != nil {
		return errors.Join(ErrPeer, credErr, pidErr)
	}
	defer unix.Close(pidfd)
	if cred.Uid != 0 || cred.Pid <= 0 {
		return ErrPeer
	}
	exe, err := os.Readlink("/proc/" + strconv.Itoa(int(cred.Pid)) + "/exe")
	if err != nil {
		return errors.Join(ErrPeer, err)
	}
	// The pinned process is still alive, so the PID was not reused between
	// the credential read and the executable read.
	if err = unix.PidfdSendSignal(pidfd, 0, nil, 0); err != nil {
		return errors.Join(ErrPeer, err)
	}
	if !allowed(exe) {
		return ErrPeer
	}
	return nil
}

// Installed reports whether exe is name in one of InstallDirs.
func Installed(exe, name string) bool {
	if name == "" || filepath.Base(name) != name {
		return false
	}
	for _, dir := range InstallDirs {
		if exe == filepath.Join(dir, name) {
			return true
		}
	}
	return false
}
