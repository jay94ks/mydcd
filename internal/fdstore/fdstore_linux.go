// SPDX-License-Identifier: Apache-2.0

// Package fdstore keeps file descriptors in the service manager's FD store
// (systemd sd_notify FDSTORE=1) so a restarted sfcd gets them back as
// LISTEN_FDS. The unit needs FileDescriptorStoreMax= and NotifyAccess=main.
// Without NOTIFY_SOCKET every call is a no-op and nothing is inherited.
package fdstore

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// ErrUnavailable: sfcd does not run under a service manager with a socket.
var ErrUnavailable = errors.New("fdstore: no NOTIFY_SOCKET")

// Available reports whether stored descriptors can come back.
func Available() bool { return os.Getenv("NOTIFY_SOCKET") != "" }

func validName(name string) bool {
	if name == "" || len(name) > 255 {
		return false
	}
	for _, r := range name {
		if r < 0x21 || r > 0x7e || r == ':' {
			return false
		}
	}
	return true
}

func notify(state string, fds []int) error {
	path := os.Getenv("NOTIFY_SOCKET")
	if path == "" {
		return ErrUnavailable
	}
	if path[0] == '@' {
		path = "\x00" + path[1:]
	}
	sock, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(sock)
	var oob []byte
	if len(fds) > 0 {
		oob = unix.UnixRights(fds...)
	}
	return unix.Sendmsg(sock, []byte(state), oob, &unix.SockaddrUnix{Name: path}, 0)
}

// Store hands fd to the store under name. The store keeps its own copy;
// the caller still owns fd.
func Store(name string, fd int) error {
	if !validName(name) {
		return errors.New("fdstore: bad name")
	}
	return notify("FDSTORE=1\nFDNAME="+name+"\n", []int{fd})
}

// Remove drops every stored descriptor named name.
func Remove(name string) error {
	if !validName(name) {
		return errors.New("fdstore: bad name")
	}
	return notify("FDSTOREREMOVE=1\nFDNAME="+name+"\n", nil)
}

var (
	once      sync.Once
	inherited map[string][]*os.File
)

// Inherited returns the descriptors this process got back, by name (one
// name may come several times). It reads LISTEN_* once and clears them so
// children do not see them. Callers take what they use with Take.
func Inherited() map[string][]*os.File {
	once.Do(func() {
		inherited = map[string][]*os.File{}
		defer func() {
			for _, k := range []string{"LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"} {
				_ = os.Unsetenv(k)
			}
		}()
		if pid, err := strconv.Atoi(os.Getenv("LISTEN_PID")); err != nil || pid != os.Getpid() {
			return
		}
		n, err := strconv.Atoi(os.Getenv("LISTEN_FDS"))
		if err != nil || n <= 0 {
			return
		}
		names := strings.Split(os.Getenv("LISTEN_FDNAMES"), ":")
		for i := 0; i < n; i++ {
			fd := 3 + i
			unix.CloseOnExec(fd)
			name := "unknown"
			if i < len(names) && names[i] != "" {
				name = names[i]
			}
			inherited[name] = append(inherited[name], os.NewFile(uintptr(fd), name))
		}
	})
	return inherited
}

var takeMu sync.Mutex

// Take removes and returns the inherited descriptors named name.
func Take(name string) []*os.File {
	all := Inherited()
	takeMu.Lock()
	defer takeMu.Unlock()
	fs := all[name]
	delete(all, name)
	return fs
}

// Names lists inherited names not taken yet.
func Names() []string {
	all := Inherited()
	takeMu.Lock()
	defer takeMu.Unlock()
	out := make([]string, 0, len(all))
	for name := range all {
		out = append(out, name)
	}
	return out
}

// SetInherited replaces what Inherited returns, for tests that play the
// service manager inside one process.
func SetInherited(m map[string][]*os.File) {
	once.Do(func() {})
	takeMu.Lock()
	defer takeMu.Unlock()
	inherited = m
}
