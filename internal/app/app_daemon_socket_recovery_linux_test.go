// SPDX-License-Identifier: Apache-2.0

package app

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// The product intentionally refuses stale paths. This fixture performs the
// documented EXPLICIT operator recovery for its own socket, not automatic
// daemon adoption. The kernel peer proves which process actually owns it.
type killedDaemonSocket struct {
	path string
	info os.FileInfo
	pid  int
	pin  *os.File
}

func (s killedDaemonSocket) close() {
	if s.pin != nil {
		_ = s.pin.Close()
	}
}

func captureOwnedDaemonSocket(path string, pid int) (killedDaemonSocket, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return killedDaemonSocket{}, err
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || before.Mode()&os.ModeSocket == 0 || before.Mode().Perm() != 0600 || stat.Uid != uint32(os.Geteuid()) || pid <= 0 {
		return killedDaemonSocket{}, errors.New("owned private daemon socket required")
	}
	fd, err := unix.Open(path, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return killedDaemonSocket{}, err
	}
	pin := os.NewFile(uintptr(fd), path)
	retained := false
	defer func() {
		if !retained {
			_ = pin.Close()
		}
	}()
	pinned, err := pin.Stat()
	if err != nil || !os.SameFile(before, pinned) {
		return killedDaemonSocket{}, errors.Join(err, errors.New("daemon socket changed before inode pin"))
	}
	c, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		return killedDaemonSocket{}, err
	}
	defer c.Close()
	u, ok := c.(*net.UnixConn)
	if !ok {
		return killedDaemonSocket{}, errors.New("Unix connection required")
	}
	raw, err := u.SyscallConn()
	if err != nil {
		return killedDaemonSocket{}, err
	}
	var peer *unix.Ucred
	var peerErr error
	if err = raw.Control(func(fd uintptr) { peer, peerErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil {
		return killedDaemonSocket{}, err
	}
	if peerErr != nil || peer == nil || peer.Pid != int32(pid) || peer.Uid != uint32(os.Geteuid()) {
		return killedDaemonSocket{}, fmt.Errorf("socket peer differs from original daemon PID %d: %w", pid, errors.Join(peerErr, os.ErrPermission))
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) {
		return killedDaemonSocket{}, errors.Join(err, errors.New("daemon socket replaced during peer verification"))
	}
	retained = true
	return killedDaemonSocket{path, before, pid, pin}, nil
}

func (s killedDaemonSocket) removeAfterKill(cmd *exec.Cmd) error {
	if s.pin == nil {
		return errors.New("original daemon socket inode must remain pinned")
	}
	pinned, err := s.pin.Stat()
	if err != nil || !os.SameFile(pinned, s.info) {
		return errors.Join(err, errors.New("original daemon socket inode pin lost"))
	}
	if cmd == nil || cmd.Process == nil || cmd.ProcessState == nil || cmd.Process.Pid != s.pid || cmd.ProcessState.Pid() != s.pid {
		return errors.New("original daemon must be killed and waited for")
	}
	status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		return errors.New("original daemon did not exit by SIGKILL")
	}
	current, err := os.Lstat(s.path)
	if err != nil {
		return err
	}
	if s.info == nil || current.Mode()&os.ModeSocket == 0 || current.Mode().Perm() != 0600 || !os.SameFile(s.info, current) {
		return errors.New("daemon socket replaced; foreign entry preserved")
	}
	return os.Remove(s.path)
}
