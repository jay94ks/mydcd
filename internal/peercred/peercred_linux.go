// SPDX-License-Identifier: Apache-2.0

package peercred

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// Close releases the pidfd. It is safe on a zero or closed Process.
func (p *Process) Close() error {
	if p == nil || p.FD < 0 {
		return nil
	}
	err := unix.Close(p.FD)
	p.FD = -1
	return err
}

// Alive reports ErrIdentity once the process behind pidfd has exited. A
// pidfd turns readable exactly when its process ends, so a PID reused after
// that can never pass.
func Alive(pidfd int) error {
	if pidfd < 0 {
		return ErrIdentity
	}
	fds := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
	n, err := unix.Poll(fds, 0)
	if err != nil {
		return errors.Join(ErrIdentity, err)
	}
	if n != 0 || fds[0].Revents != 0 {
		return ErrIdentity
	}
	return nil
}

// Peer returns the process that connected conn (SO_PEERCRED and
// SO_PEERPIDFD, Linux 6.5 and later). On a server socket this is the client
// that called connect, fixed at that moment.
func Peer(conn *net.UnixConn) (Process, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return Process{FD: -1}, errors.Join(ErrIdentity, err)
	}
	var credentials *unix.Ucred
	pidfd := -1
	var optionErr error
	if err = raw.Control(func(fd uintptr) {
		credentials, optionErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if optionErr == nil {
			pidfd, optionErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PEERPIDFD)
		}
	}); err != nil || optionErr != nil || credentials == nil || credentials.Pid <= 0 || pidfd < 0 {
		if pidfd >= 0 {
			_ = unix.Close(pidfd)
		}
		return Process{FD: -1}, errors.Join(ErrIdentity, err, optionErr)
	}
	unix.CloseOnExec(pidfd)
	p := Process{PID: int(credentials.Pid), UID: credentials.Uid, GID: credentials.Gid, FD: pidfd}
	if err = Alive(pidfd); err != nil {
		_ = p.Close()
		return Process{FD: -1}, err
	}
	return p, nil
}

// EnableSender asks the kernel to attach SCM_CREDENTIALS and SCM_PIDFD to
// every message received on conn, so Sender can name who wrote them.
func EnableSender(conn *net.UnixConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return errors.Join(ErrIdentity, err)
	}
	var optionErr error
	if err = raw.Control(func(fd uintptr) {
		optionErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED, 1)
		if optionErr == nil {
			optionErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSPIDFD, 1)
		}
	}); err != nil || optionErr != nil {
		return errors.Join(ErrIdentity, err, optionErr)
	}
	return nil
}

// Sender peeks at the next byte on conn and returns the process that sent
// it. Unlike Peer this names the actual writer, including socket activation
// where SO_PEERCRED refers to the listener's creator. EnableSender must run
// before the peer writes. The byte stays queued for the next read.
func Sender(conn *net.UnixConn) (Process, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return Process{FD: -1}, errors.Join(ErrIdentity, err)
	}
	data := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(unix.SizeofUcred)+unix.CmsgSpace(4)+unix.CmsgSpace(4*253))
	n, oobn, flags := 0, 0, 0
	var readErr error
	err = raw.Read(func(fd uintptr) bool {
		for {
			n, oobn, flags, _, readErr = unix.Recvmsg(int(fd), data, oob, unix.MSG_PEEK|unix.MSG_DONTWAIT|unix.MSG_CMSG_CLOEXEC)
			if errors.Is(readErr, unix.EINTR) {
				continue
			}
			return !errors.Is(readErr, unix.EAGAIN) && !errors.Is(readErr, unix.EWOULDBLOCK)
		}
	})
	messages, parseErr := unix.ParseSocketControlMessage(oob[:oobn])
	var credentials *unix.Ucred
	pidfd := -1
	unexpected := false
	for _, message := range messages {
		if message.Header.Level != unix.SOL_SOCKET {
			unexpected = true
			continue
		}
		switch message.Header.Type {
		case unix.SCM_CREDENTIALS:
			if credentials != nil {
				unexpected = true
			}
			c, e := unix.ParseUnixCredentials(&message)
			if e != nil {
				parseErr = errors.Join(parseErr, e)
			} else {
				credentials = c
			}
		case unix.SCM_PIDFD:
			if len(message.Data) != 4 {
				unexpected = true
				continue
			}
			fd := int(int32(binary.NativeEndian.Uint32(message.Data)))
			if fd < 0 {
				unexpected = true
				continue
			}
			unix.CloseOnExec(fd)
			if pidfd >= 0 {
				_ = unix.Close(fd)
				unexpected = true
			} else {
				pidfd = fd
			}
		case unix.SCM_RIGHTS:
			fds, e := unix.ParseUnixRights(&message)
			parseErr = errors.Join(parseErr, e)
			for _, fd := range fds {
				_ = unix.Close(fd)
			}
			unexpected = true
		default:
			unexpected = true
		}
	}
	if err != nil || readErr != nil || parseErr != nil || n != 1 || flags&unix.MSG_CTRUNC != 0 || unexpected || credentials == nil || credentials.Pid <= 0 || pidfd < 0 {
		if pidfd >= 0 {
			_ = unix.Close(pidfd)
		}
		return Process{FD: -1}, errors.Join(ErrIdentity, err, readErr, parseErr)
	}
	return Process{PID: int(credentials.Pid), UID: credentials.Uid, GID: credentials.Gid, FD: pidfd}, nil
}

// SameContainer proves that p runs in the same cgroup and PID namespace as
// anchor (for example a container's init process held since start). Both
// pidfds are checked again after the /proc reads, so a PID reused while
// reading cannot pass.
func SameContainer(p, anchor Process) error {
	if p.PID <= 0 || anchor.PID <= 0 {
		return ErrIdentity
	}
	if err := errors.Join(Alive(p.FD), Alive(anchor.FD)); err != nil {
		return err
	}
	group, err := cgroupOf(p.PID)
	if err != nil {
		return err
	}
	anchorGroup, err := cgroupOf(anchor.PID)
	if err != nil {
		return err
	}
	ns, err := pidNamespaceOf(p.PID)
	if err != nil {
		return err
	}
	anchorNS, err := pidNamespaceOf(anchor.PID)
	if err != nil {
		return err
	}
	if !bytes.Equal(group, anchorGroup) || ns != anchorNS {
		return ErrIdentity
	}
	return errors.Join(Alive(p.FD), Alive(anchor.FD))
}

const maxCgroupFile = 64 << 10

func cgroupOf(pid int) ([]byte, error) {
	f, err := os.Open("/proc/" + strconv.Itoa(pid) + "/cgroup")
	if err != nil {
		return nil, errors.Join(ErrIdentity, err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxCgroupFile+1))
	if err != nil || len(data) == 0 || len(data) > maxCgroupFile {
		return nil, errors.Join(ErrIdentity, err)
	}
	return data, nil
}

type namespace struct{ dev, ino uint64 }

func pidNamespaceOf(pid int) (namespace, error) {
	var st unix.Stat_t
	if err := unix.Stat("/proc/"+strconv.Itoa(pid)+"/ns/pid", &st); err != nil {
		return namespace{}, errors.Join(ErrIdentity, err)
	}
	return namespace{dev: st.Dev, ino: st.Ino}, nil
}

const maxStatusFile = 16 << 10

// Open pins process pid by pidfd and reads its real UID and GID. The caller
// proves pid is the process it means (for example by asking the container
// engine again after Open) and must Close the result.
func Open(pid int) (Process, error) {
	if pid <= 0 {
		return Process{FD: -1}, ErrIdentity
	}
	pidfd, err := unix.PidfdOpen(pid, unix.PIDFD_NONBLOCK)
	if err != nil {
		return Process{FD: -1}, errors.Join(ErrIdentity, err)
	}
	unix.CloseOnExec(pidfd)
	p := Process{PID: pid, FD: pidfd}
	f, err := os.Open("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		_ = p.Close()
		return Process{FD: -1}, errors.Join(ErrIdentity, err)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxStatusFile+1))
	_ = f.Close()
	uid, uidOK := statusID(data, "Uid:")
	gid, gidOK := statusID(data, "Gid:")
	if err != nil || len(data) > maxStatusFile || !uidOK || !gidOK {
		_ = p.Close()
		return Process{FD: -1}, errors.Join(ErrIdentity, err)
	}
	p.UID, p.GID = uid, gid
	// The status read above is that pid's only if it is still the pinned one.
	if err = Alive(pidfd); err != nil {
		_ = p.Close()
		return Process{FD: -1}, err
	}
	return p, nil
}

// statusID is the real ID (first field) of a /proc status line.
func statusID(data []byte, field string) (uint32, bool) {
	for _, line := range bytes.Split(data, []byte("\n")) {
		rest, ok := bytes.CutPrefix(line, []byte(field))
		if !ok {
			continue
		}
		fields := bytes.Fields(rest)
		if len(fields) == 0 {
			return 0, false
		}
		v, err := strconv.ParseUint(string(fields[0]), 10, 32)
		return uint32(v), err == nil
	}
	return 0, false
}
