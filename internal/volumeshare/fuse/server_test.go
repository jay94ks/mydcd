// SPDX-License-Identifier: Apache-2.0

package fuse

import (
	"context"
	"os"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// fakeKernel is the kernel side of a SOCK_SEQPACKET pair: like /dev/fuse,
// every read and write is one whole message.
type fakeKernel struct {
	t      *testing.T
	fd     int
	unique uint64
}

func newFakeKernel(t *testing.T) (*fakeKernel, *Device) {
	t.Helper()
	p, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	dev, err := NewDevice(p[1])
	if err != nil {
		t.Fatal(err)
	}
	k := &fakeKernel{t: t, fd: p[0]}
	t.Cleanup(func() { unix.Close(p[0]) })
	return k, dev
}

func (k *fakeKernel) send(op opcode, node uint64, body []byte) uint64 {
	k.unique++
	w := writer{}
	w.u32(uint32(inHeaderSize + len(body)))
	w.u32(uint32(op))
	w.u64(k.unique)
	w.u64(node)
	w.u32(1000)
	w.u32(1000)
	w.u32(42)
	w.u32(0)
	w.b = append(w.b, body...)
	if _, err := unix.Write(k.fd, w.b); err != nil {
		k.t.Fatal(err)
	}
	return k.unique
}

func (k *fakeKernel) recv(unique uint64) (int32, []byte) {
	k.t.Helper()
	b := make([]byte, readBuffer)
	_ = unix.SetsockoptTimeval(k.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 5})
	n, err := unix.Read(k.fd, b)
	for err == unix.EINTR {
		n, err = unix.Read(k.fd, b)
	}
	if err != nil {
		k.t.Fatalf("read reply: %v", err)
	}
	b = b[:n]
	if n < outHeaderSize || int(ne.Uint32(b)) != n {
		k.t.Fatalf("bad reply length %d", n)
	}
	if got := ne.Uint64(b[8:]); got != unique {
		k.t.Fatalf("reply unique %d, want %d", got, unique)
	}
	return int32(ne.Uint32(b[4:])), b[outHeaderSize:]
}

func (k *fakeKernel) init(minor uint32) {
	w := writer{}
	w.u32(7)
	w.u32(minor)
	w.u32(128 << 10)
	w.u32(^uint32(0))
	u := k.send(opInit, 0, w.b)
	errno, body := k.recv(u)
	if errno != 0 || len(body) != initOutSize {
		k.t.Fatalf("INIT reply errno %d len %d", errno, len(body))
	}
	if ne.Uint32(body[0:]) != 7 || ne.Uint32(body[4:]) != min(minor, protoMinor) || ne.Uint32(body[20:]) != MaxWrite {
		k.t.Fatalf("INIT reply %v", body[:24])
	}
}

func serveFake(t *testing.T, fs FileSystem) (*fakeKernel, context.CancelFunc, chan error) {
	k, dev := newFakeKernel(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, dev, fs, ServeOptions{}) }()
	t.Cleanup(func() { cancel(); <-done; dev.Close() })
	return k, cancel, done
}

func TestServeNegotiatesAndAnswers(t *testing.T) {
	fs := newMemFS()
	k, _, _ := serveFake(t, fs)
	k.init(40)

	// CREATE a file, then LOOKUP it and WRITE/READ through the handle.
	w := writer{}
	w.u32(uint32(os.O_RDWR))
	w.u32(0o644)
	w.u32(0o022)
	w.u32(0)
	w.b = append(w.b, "a.txt\x00"...)
	errno, body := k.recv(k.send(opCreate, RootID, w.b))
	if errno != 0 || len(body) != entryOutSize+openOutSize {
		t.Fatalf("CREATE errno %d len %d", errno, len(body))
	}
	node := ne.Uint64(body)
	if mode := ne.Uint32(body[40+60:]); mode != syscall.S_IFREG|0o644 {
		t.Fatalf("mode %o", mode)
	}

	errno, body = k.recv(k.send(opLookup, RootID, []byte("a.txt\x00")))
	if errno != 0 || ne.Uint64(body) != node {
		t.Fatalf("LOOKUP errno %d", errno)
	}
	errno, _ = k.recv(k.send(opLookup, RootID, []byte("missing\x00")))
	if errno != -int32(syscall.ENOENT) {
		t.Fatalf("LOOKUP missing errno %d", errno)
	}

	w = writer{}
	w.u64(node)
	w.u64(3)
	w.u32(5)
	w.u32(0)
	w.u64(0)
	w.u32(0)
	w.u32(0)
	w.b = append(w.b, "hello"...)
	errno, body = k.recv(k.send(opWrite, node, w.b))
	if errno != 0 || ne.Uint32(body) != 5 {
		t.Fatalf("WRITE errno %d", errno)
	}
	w = writer{}
	w.u64(node)
	w.u64(0)
	w.u32(100)
	w.pad(20)
	errno, body = k.recv(k.send(opRead, node, w.b))
	if errno != 0 || string(body) != "\x00\x00\x00hello" {
		t.Fatalf("READ errno %d %q", errno, body)
	}

	// READDIR packs 8-byte aligned dirents and stops at the size limit.
	errno, _ = k.recv(k.send(opOpendir, RootID, make([]byte, 8)))
	if errno != 0 {
		t.Fatalf("OPENDIR errno %d", errno)
	}
	w = writer{}
	w.u64(RootID)
	w.u64(0)
	w.u32(4096)
	w.pad(20)
	errno, body = k.recv(k.send(opReaddir, RootID, w.b))
	if errno != 0 {
		t.Fatalf("READDIR errno %d", errno)
	}
	var names []string
	for len(body) > 0 {
		nl := int(ne.Uint32(body[16:]))
		names = append(names, string(body[24:24+nl]))
		body = body[(24+nl+7)&^7:]
	}
	if len(names) != 3 || names[2] != "a.txt" {
		t.Fatalf("READDIR names %q", names)
	}
	w = writer{}
	w.u64(RootID)
	w.u64(0)
	w.u32(39) // room for one 32-byte dirent only
	w.pad(20)
	if _, body = k.recv(k.send(opReaddir, RootID, w.b)); len(body) != 32 {
		t.Fatalf("READDIR small buffer len %d", len(body))
	}

	// Unknown opcodes get ENOSYS; FORGET gets no reply.
	k.send(opForget, node, []byte{1, 0, 0, 0, 0, 0, 0, 0})
	errno, _ = k.recv(k.send(opcode(39), RootID, nil))
	if errno != -int32(syscall.ENOSYS) {
		t.Fatalf("IOCTL errno %d", errno)
	}
	fs.mu.Lock()
	forgot := fs.forgot[node]
	fs.mu.Unlock()
	if forgot != 1 {
		t.Fatalf("forget count %d", forgot)
	}

	// A short body is EINVAL, not a crash.
	errno, _ = k.recv(k.send(opRead, node, []byte{1, 2}))
	if errno != -int32(syscall.EINVAL) {
		t.Fatalf("short READ errno %d", errno)
	}
}

func TestServeRefusesOldKernel(t *testing.T) {
	k, dev := newFakeKernel(t)
	done := make(chan error, 1)
	go func() { done <- Serve(context.Background(), dev, newMemFS(), ServeOptions{}) }()
	w := writer{}
	w.u32(7)
	w.u32(minMinor - 1)
	w.u32(0)
	w.u32(0)
	errno, _ := k.recv(k.send(opInit, 0, w.b))
	if errno != -int32(syscall.EPROTO) {
		t.Fatalf("errno %d", errno)
	}
	if err := <-done; err == nil {
		t.Fatal("Serve accepted an old kernel")
	}
}

func TestInterruptCancelsBlockedLock(t *testing.T) {
	fs := newMemFS()
	k, _, _ := serveFake(t, fs)
	k.init(31)
	lk := func(owner uint64, typ uint32) []byte {
		w := writer{}
		w.u64(1)
		w.u64(owner)
		w.lock(Lock{Start: 0, End: ^uint64(0), Type: typ})
		w.u32(lkFlock)
		w.u32(0)
		return w.b
	}
	if errno, _ := k.recv(k.send(opSetlk, RootID, lk(1, syscall.F_WRLCK))); errno != 0 {
		t.Fatalf("first lock errno %d", errno)
	}
	if errno, _ := k.recv(k.send(opSetlk, RootID, lk(2, syscall.F_WRLCK))); errno != -int32(syscall.EAGAIN) {
		t.Fatalf("conflicting lock errno %d", errno)
	}
	u := k.send(opSetlkw, RootID, lk(2, syscall.F_WRLCK))
	time.Sleep(50 * time.Millisecond)
	w := writer{}
	w.u64(u)
	k.send(opInterrupt, 0, w.b)
	if errno, _ := k.recv(u); errno != -int32(syscall.EINTR) {
		t.Fatalf("interrupted SETLKW errno %d", errno)
	}
}

func TestServeResumeSkipsInit(t *testing.T) {
	k, dev := newFakeKernel(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, dev, newMemFS(), ServeOptions{Resume: &Session{Minor: 31, MaxWrite: MaxWrite}})
	}()
	errno, body := k.recv(k.send(opGetattr, RootID, make([]byte, 16)))
	if errno != 0 || len(body) != attrOutSize {
		t.Fatalf("GETATTR errno %d len %d", errno, len(body))
	}
	cancel()
	if err := <-done; err != context.Canceled {
		t.Fatalf("Serve after cancel: %v", err)
	}
}
