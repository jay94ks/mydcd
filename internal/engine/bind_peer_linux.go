// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/moby/moby/client"
	"golang.org/x/sys/unix"
)

// BindSource is an adapter-local, held original directory, never app input.
// The caller retains its native A3 pin and these descriptors through the SDK
// effect. Merely finding an existing path in mydcd's namespace is insufficient.
type BindSource struct {
	Path        string
	DirectoryFD int
}

// ErrBindBeforeRequest is positive evidence that the guarded transport never
// handed a connection to this API request. Only its read-only HEAD probe may
// have run. It is not used for SDK write/read errors after a successful dial.
// Fresh connections and disabled redirects are mandatory for this fact.
var ErrBindBeforeRequest = errors.New("fixed bind API request was not dispatched")

func livePeer(fd int) error {
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	n, err := unix.Poll(fds, 0)
	if err != nil {
		return err
	}
	if n != 0 || fds[0].Revents != 0 {
		return ErrOwnership
	}
	return nil
}

// senderIdentity peeks at the response's first byte. Automatic kernel SCM
// credentials/pidfd identify its actual sender, including socket activation
// where SO_PEERCRED refers to the listener creator rather than dockerd.
func senderIdentity(conn *net.UnixConn) (*unix.Ucred, int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, -1, err
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
		return nil, -1, errors.Join(ErrOwnership, err, readErr, parseErr)
	}
	return credentials, pidfd, nil
}

func enableSenderIdentity(conn *net.UnixConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var optionErr error
	if err = raw.Control(func(fd uintptr) {
		optionErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSCRED, 1)
		if optionErr == nil {
			optionErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PASSPIDFD, 1)
		}
	}); err != nil || optionErr != nil {
		return errors.Join(ErrOwnership, err, optionErr)
	}
	return nil
}

func checkBindPeer(conn *net.UnixConn, sources []BindSource) error {
	deadline := time.Now().Add(30 * time.Second)
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	defer conn.SetDeadline(time.Time{})
	if err := enableSenderIdentity(conn); err != nil {
		return err
	}
	request, err := http.NewRequest(http.MethodHead, "http://docker/_ping", nil)
	if err != nil {
		return err
	}
	if err = request.Write(conn); err != nil {
		return err
	}
	credentials, pidfd, err := senderIdentity(conn)
	if err != nil {
		return err
	}
	defer unix.Close(pidfd)
	if err = livePeer(pidfd); err != nil {
		return err
	}
	if err = checkProcessBindSources(int(credentials.Pid), pidfd, sources); err != nil {
		return err
	}
	// Consume exactly this read-only HEAD response before handing the SAME
	// socket to the SDK. Bound header memory and forbid a closed/ambiguous
	// connection; no mutating API request precedes the source check.
	limited := &io.LimitedReader{R: conn, N: 64 << 10}
	reader := bufio.NewReader(limited)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		return err
	}
	closeErr := response.Body.Close()
	if closeErr != nil || response.StatusCode != http.StatusOK || response.Close || reader.Buffered() != 0 || limited.N == 0 {
		return errors.Join(ErrOwnership, closeErr)
	}
	return livePeer(pidfd)
}

// CheckProcessBindSources verifies actual mounted directories in a live
// container's root view. The caller supplies its original inspected PID and
// held native source FDs; API mount metadata alone cannot prove this view.
func CheckProcessBindSources(pid int, sources []BindSource) error {

	if pid <= 0 || len(sources) == 0 || len(sources) > maxBindSources {
		return ErrOwnership
	}
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return errors.Join(ErrOwnership, err)
	}
	defer unix.Close(pidfd)
	return checkProcessBindSources(pid, pidfd, sources)
}

const maxBindSources = 32

func checkProcessBindSources(pid, pidfd int, sources []BindSource) error {
	if err := livePeer(pidfd); err != nil {
		return err
	}
	process, err := unix.Open("/proc/"+strconv.Itoa(pid), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(process)
	var fs unix.Statfs_t
	if err = unix.Fstatfs(process, &fs); err != nil || fs.Type != unix.PROC_SUPER_MAGIC {
		return errors.Join(ErrOwnership, err)
	}
	// This one kernel-provided proc magic link is deliberate. The actual
	// selected source below rejects all symlinks and resolves under this root.
	root, err := unix.Openat(process, "root", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(root)
	for _, source := range sources {
		if source.DirectoryFD < 0 || !filepath.IsAbs(source.Path) || filepath.Clean(source.Path) != source.Path || source.Path == "/" {
			return ErrOwnership
		}
		fd, err := unix.Openat2(root, strings.TrimPrefix(source.Path, "/"), &unix.OpenHow{Flags: unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
		if err != nil {
			return err
		}
		var actual, original unix.Stat_t
		err = unix.Fstat(fd, &actual)
		closeErr := unix.Close(fd)
		if err == nil {
			err = unix.Fstat(source.DirectoryFD, &original)
		}
		if err != nil || closeErr != nil || actual.Mode&unix.S_IFMT != unix.S_IFDIR || original.Mode&unix.S_IFMT != unix.S_IFDIR || actual.Dev != original.Dev || actual.Ino != original.Ino {
			return errors.Join(ErrOwnership, err, closeErr)
		}
	}
	return livePeer(pidfd)
}

// BindClient gives only this operation a guarded SDK transport. Every request
// uses a fresh, positively inspected Unix peer; a connection to a restarted
// daemon cannot bypass the check. The ordinary Engine client is unchanged.
// Close this client before closing the caller-held directory descriptors.
func (c *Client) BindClient(sources []BindSource) (*client.Client, error) {
	return c.bindClient(sources, 30*time.Second)
}

// BindStreamingClient keeps the same peer/path/FD guard for large context
// copies. Caller cancellation bounds the body; dial/header limits stay finite.
func (c *Client) BindStreamingClient(sources []BindSource) (*client.Client, error) {
	return c.bindClient(sources, 0)
}
func (c *Client) bindClient(sources []BindSource, timeout time.Duration) (*client.Client, error) {
	if c == nil || c.API == nil || len(sources) == 0 || len(sources) > maxBindSources {
		return nil, ErrOwnership
	}
	endpoint := c.API.DaemonHost()
	if !strings.HasPrefix(endpoint, "unix://") || !filepath.IsAbs(strings.TrimPrefix(endpoint, "unix://")) {
		return nil, ErrOwnership
	}
	sources = append([]BindSource(nil), sources...)
	transport := &http.Transport{DisableKeepAlives: true, ResponseHeaderTimeout: 30 * time.Second}
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	return client.New(client.WithHTTPClient(&http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}), client.WithHost(endpoint), client.WithScheme("http"), client.WithAPIVersionNegotiation(), client.WithDialContext(func(ctx context.Context, _, _ string) (net.Conn, error) {
		conn, err := dialer.DialContext(ctx, "unix", strings.TrimPrefix(endpoint, "unix://"))
		if err != nil {
			return nil, errors.Join(ErrBindBeforeRequest, err)
		}
		uds, ok := conn.(*net.UnixConn)
		if !ok {
			_ = conn.Close()
			return nil, errors.Join(ErrBindBeforeRequest, ErrOwnership)
		}
		stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
		err = checkBindPeer(uds, sources)
		stop()
		if err != nil || ctx.Err() != nil {
			_ = conn.Close()
			return nil, errors.Join(ErrBindBeforeRequest, err, ctx.Err())
		}
		return conn, nil
	}))
}
