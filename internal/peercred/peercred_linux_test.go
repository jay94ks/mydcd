// SPDX-License-Identifier: Apache-2.0

package peercred

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func listen(t *testing.T) (*net.UnixListener, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "peer.sock")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l, path
}

func self(t *testing.T) Process {
	t.Helper()
	fd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		t.Skipf("pidfd: %v", err)
	}
	p := Process{PID: os.Getpid(), UID: uint32(os.Getuid()), GID: uint32(os.Getgid()), FD: fd}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func TestPeerNamesTheConnectingProcess(t *testing.T) {
	l, path := listen(t)
	client, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := l.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	p, err := Peer(server)
	if errors.Is(err, unix.ENOPROTOOPT) {
		t.Skip("kernel has no SO_PEERPIDFD")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if p.PID != os.Getpid() || p.UID != uint32(os.Getuid()) || p.GID != uint32(os.Getgid()) || p.FD < 0 {
		t.Fatalf("peer = %+v", p)
	}
	if err = SameContainer(p, self(t)); err != nil {
		t.Fatalf("same process is not in its own container: %v", err)
	}
}

func TestSenderNamesTheWriter(t *testing.T) {
	l, path := listen(t)
	client, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := l.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if err = EnableSender(server); err != nil {
		t.Skipf("SO_PASSPIDFD: %v", err)
	}
	if _, err = client.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	p, err := Sender(server)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if p.PID != os.Getpid() {
		t.Fatalf("sender = %+v", p)
	}
	// The peeked byte is still there.
	buf := make([]byte, 1)
	if n, err := server.Read(buf); err != nil || n != 1 || buf[0] != 'x' {
		t.Fatalf("read = %d %q %v", n, buf, err)
	}
}

func TestExitedProcessNeverMatches(t *testing.T) {
	cmd := exec.Command("true")
	if err := cmd.Start(); err != nil {
		t.Skip(err)
	}
	fd, err := unix.PidfdOpen(cmd.Process.Pid, 0)
	if err != nil {
		_ = cmd.Wait()
		t.Skipf("pidfd: %v", err)
	}
	child := Process{PID: cmd.Process.Pid, FD: fd}
	defer child.Close()
	if err = cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	if err = Alive(child.FD); !errors.Is(err, ErrIdentity) {
		t.Fatalf("Alive after exit = %v", err)
	}
	if err = SameContainer(child, self(t)); !errors.Is(err, ErrIdentity) {
		t.Fatalf("SameContainer after exit = %v", err)
	}
	if err = Alive(-1); !errors.Is(err, ErrIdentity) {
		t.Fatalf("Alive(-1) = %v", err)
	}
}

func TestOtherPIDNamespaceDoesNotMatch(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root for a new PID namespace")
	}
	cmd := exec.Command("sleep", "30")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWPID}
	if err := cmd.Start(); err != nil {
		t.Skipf("new PID namespace: %v", err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	fd, err := unix.PidfdOpen(cmd.Process.Pid, 0)
	if err != nil {
		t.Skipf("pidfd: %v", err)
	}
	other := Process{PID: cmd.Process.Pid, FD: fd}
	defer other.Close()
	if err = SameContainer(other, self(t)); !errors.Is(err, ErrIdentity) {
		t.Fatalf("other PID namespace matched: %v", err)
	}
}

func TestOpenPinsAProcessWithItsIDs(t *testing.T) {
	p, err := Open(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if p.UID != uint32(os.Getuid()) || p.GID != uint32(os.Getgid()) || Alive(p.FD) != nil {
		t.Fatalf("open = %+v", p)
	}
	if _, err := Open(0); err == nil {
		t.Fatal("pid 0 accepted")
	}
}
