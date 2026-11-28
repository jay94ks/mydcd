// SPDX-License-Identifier: Apache-2.0

//go:build linux

package volumeshare_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/volumeshare"
	"github.com/jay94ks/seafield/internal/volumeshare/back/localroot"
	"golang.org/x/sys/unix"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// homePair is a consuming node and a home over real SFCP QUIC.
func homePair(t *testing.T, server *volumeshare.Server) (*sfcp.Transport, sfcp.Identity, sfcp.Identity) {
	t.Helper()
	a, err := identity.Create(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	b, err := identity.Create(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(a.Private); clear(b.Private) })
	var endpoint string
	var mu sync.Mutex
	lookup := func(key sfcp.Identity) (sfcp.Peer, bool) {
		mu.Lock()
		defer mu.Unlock()
		switch key {
		case sfcp.Identity(a.Public):
			return sfcp.Peer{ID: "consumer", Policy: sfcp.Policy{Key: key, Member: true, Respond: true}}, true
		case sfcp.Identity(b.Public):
			return sfcp.Peer{ID: "home", Endpoint: endpoint, Policy: sfcp.Policy{Key: key, Member: true, Respond: true}}, true
		}
		return sfcp.Peer{}, false
	}
	home, err := sfcp.NewTransport(b, [32]byte{24}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = home.Close() })
	if err = volumeshare.Serve(home, server); err != nil {
		t.Fatal(err)
	}
	if err = home.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	endpoint = home.Addr().String()
	mu.Unlock()
	consumer, err := sfcp.NewTransport(a, [32]byte{24}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = consumer.Close() })
	return consumer, sfcp.Identity(a.Public), sfcp.Identity(b.Public)
}

func openRoot(t *testing.T) (*localroot.Root, string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root (open_by_handle_at requires CAP_DAC_READ_SEARCH)")
	}
	dir := t.TempDir()
	root, err := localroot.Open(dir, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Shutdown() })
	return root, dir
}

func TestRemoteVolumeOverSFCP(t *testing.T) {
	root, dir := openRoot(t)
	now := &clock{t: time.Unix(1_800_000_000, 0)}
	var mu sync.Mutex
	allowed := true
	var consumerKey sfcp.Identity
	server := volumeshare.NewServer(func(_ context.Context, peer [32]byte, volume string) (volumeshare.Ops, error) {
		mu.Lock()
		defer mu.Unlock()
		if !allowed || volume != "tenant/data" || peer != consumerKey {
			return nil, syscall.EACCES
		}
		return root, nil
	}, volumeshare.ServerOptions{Now: now.Now})
	consumer, key, homeKey := homePair(t, server)
	consumerKey = key
	call := volumeshare.CallHome(consumer, homeKey)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	opts := volumeshare.ClientOptions{Volume: "tenant/data", Sent: sfcp.CallSent, Retry: time.Second}

	if _, err := volumeshare.Dial(ctx, call, volumeshare.ClientOptions{Volume: "tenant/other", Sent: sfcp.CallSent, Retry: time.Second}); !errors.Is(err, syscall.EACCES) {
		t.Fatalf("unbound volume: %v", err)
	}
	c, err := volumeshare.Dial(ctx, call, opts)
	if err != nil {
		t.Fatal(err)
	}
	if server.Mounts() != 1 {
		t.Fatalf("mounts = %d", server.Mounts())
	}

	// Data larger than one frame goes through in frame-sized pieces.
	who := volumeshare.Caller{UID: 0, GID: 0}
	e, f, err := c.Create(ctx, 0, who, c.Root(), "big", uint32(os.O_RDWR), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	want := make([]byte, 300<<10)
	for i := range want {
		want[i] = byte(i * 7)
	}
	for off := 0; off < len(want); {
		n, err := c.Write(ctx, f, uint64(off), want[off:min(off+128<<10, len(want))])
		if err != nil {
			t.Fatal(err)
		}
		off += int(n)
	}
	if err = c.Fsync(ctx, f, false); err != nil {
		t.Fatal(err)
	}
	disk, err := os.ReadFile(filepath.Join(dir, "big"))
	if err != nil || !bytes.Equal(disk, want) {
		t.Fatalf("home file differs: %v", err)
	}
	var got []byte
	for off := uint64(0); ; {
		b, err := c.Read(ctx, f, off, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		if len(b) == 0 {
			break
		}
		got, off = append(got, b...), off+uint64(len(b))
	}
	if !bytes.Equal(got, want) {
		t.Fatal("read back differs")
	}
	if a, err := c.GetAttr(ctx, e.Handle); err != nil || a.Size != uint64(len(want)) {
		t.Fatalf("getattr: %+v %v", a, err)
	}
	if _, err := c.Mkdir(ctx, who, c.Root(), "sub", 0o755); err != nil {
		t.Fatal(err)
	}
	rows, err := c.ReadDir(ctx, c.Root(), 0, 100)
	if err != nil || len(rows) != 2 {
		t.Fatalf("readdir: %+v %v", rows, err)
	}
	if _, err := c.Lookup(ctx, c.Root(), "missing"); !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("lookup missing: %v", err)
	}

	// A waiting lock is polled until the holder lets go.
	whole := volumeshare.Lock{Start: 0, End: ^uint64(0), Type: unix.F_WRLCK, PID: 1}
	if err = c.SetLk(ctx, f, 1, whole, false, false); err != nil {
		t.Fatal(err)
	}
	if err = c.SetLk(ctx, f, 2, whole, false, false); !errors.Is(err, syscall.EAGAIN) {
		t.Fatalf("conflicting lock: %v", err)
	}
	short, stop := context.WithTimeout(ctx, 100*time.Millisecond)
	if err = c.SetLk(short, f, 2, whole, true, false); !errors.Is(err, syscall.EINTR) {
		t.Fatalf("interrupted wait: %v", err)
	}
	stop()
	granted := make(chan error, 1)
	go func() { granted <- c.SetLk(ctx, f, 2, whole, true, false) }()
	time.Sleep(50 * time.Millisecond)
	unlock := whole
	unlock.Type = unix.F_UNLCK
	if err = c.SetLk(ctx, f, 1, unlock, false, false); err != nil {
		t.Fatal(err)
	}
	if err = <-granted; err != nil {
		t.Fatalf("wait after unlock: %v", err)
	}

	// The home forgets an idle mount; the client mounts again, keeps its
	// handles, and loses the old mount's open files.
	now.Add(20 * time.Second)
	server.Expire()
	if server.Mounts() != 0 {
		t.Fatal("idle mount not expired")
	}
	old := c.Session()
	if a, err := c.GetAttr(ctx, e.Handle); err != nil || a.Size != uint64(len(want)) {
		t.Fatalf("getattr after remount: %+v %v", a, err)
	}
	if c.Session() == old || server.Mounts() != 1 {
		t.Fatal("client did not mount again")
	}
	if _, err := c.Read(ctx, f, 0, 10); !errors.Is(err, syscall.EBADF) {
		t.Fatalf("old file after remount: %v", err)
	}

	// A withdrawn binding stops the mount at the next recheck.
	mu.Lock()
	allowed = false
	mu.Unlock()
	if _, err := c.GetAttr(ctx, e.Handle); err != nil {
		t.Fatalf("before recheck: %v", err)
	}
	now.Add(6 * time.Second)
	if _, err := c.GetAttr(ctx, e.Handle); !errors.Is(err, syscall.EACCES) {
		t.Fatalf("after withdrawal: %v", err)
	}
	if server.Mounts() != 0 {
		t.Fatal("withdrawn mount kept")
	}
}

// TestServerScopesMounts checks that a mount and its files belong to the
// peer that made them.
func TestServerScopesMounts(t *testing.T) {
	root, _ := openRoot(t)
	server := volumeshare.NewServer(func(context.Context, [32]byte, string) (volumeshare.Ops, error) {
		return root, nil
	}, volumeshare.ServerOptions{})
	ctx := context.Background()
	as := func(peer byte) volumeshare.Call {
		return func(ctx context.Context, header, data []byte) ([]byte, []byte, error) {
			return server.Handle(ctx, [32]byte{peer}, header, data)
		}
	}
	a, err := volumeshare.Dial(ctx, as(1), volumeshare.ClientOptions{Volume: "v"})
	if err != nil {
		t.Fatal(err)
	}
	_, f, err := a.Create(ctx, 0, volumeshare.Caller{}, a.Root(), "x", uint32(os.O_RDWR), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	b, err := volumeshare.Dial(ctx, as(2), volumeshare.ClientOptions{Volume: "v"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Read(ctx, f, 0, 1); !errors.Is(err, syscall.EBADF) {
		t.Fatalf("other mount's file: %v", err)
	}
	// Peer 2 presenting peer 1's session is not peer 1: it gets a mount of
	// its own instead.
	stolen := []byte(`{"Schema":1,"Op":"getattr","Session":` + itoa(a.Session()) + `,"Caller":{"UID":0,"GID":0}}`)
	raw, _, err := server.Handle(ctx, [32]byte{2}, stolen, nil)
	if err != nil || !bytes.Contains(raw, []byte(`"Errno":116`)) {
		t.Fatalf("foreign session: %s %v", raw, err)
	}
	if _, _, err := server.Handle(ctx, [32]byte{1}, []byte(`{"Schema":2}`), nil); err == nil {
		t.Fatal("bad schema answered")
	}
	a.Release(0)
	b.Release(0)
	if server.Mounts() != 0 {
		t.Fatalf("mounts after release = %d", server.Mounts())
	}
}

func itoa(v uint64) string {
	var b [20]byte
	i := len(b)
	for {
		i--
		b[i] = byte('0' + v%10)
		if v /= 10; v == 0 {
			return string(b[i:])
		}
	}
}

// A read-only mount reads through but every change is EROFS on the home.
func TestReadOnlyMountRefusesChanges(t *testing.T) {
	root, dir := openRoot(t)
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	ro := volumeshare.ReadOnly(root)
	server := volumeshare.NewServer(func(context.Context, [32]byte, string) (volumeshare.Ops, error) { return ro, nil }, volumeshare.ServerOptions{})
	ctx := context.Background()
	c, err := volumeshare.Dial(ctx, func(ctx context.Context, h, d []byte) ([]byte, []byte, error) {
		return server.Handle(ctx, [32]byte{1}, h, d)
	}, volumeshare.ClientOptions{Volume: "v"})
	if err != nil {
		t.Fatal(err)
	}
	e, err := c.Lookup(ctx, c.Root(), "f")
	if err != nil {
		t.Fatal(err)
	}
	f, err := c.Open(ctx, 0, e.Handle, uint32(os.O_RDONLY))
	if err != nil {
		t.Fatal(err)
	}
	if b, err := c.Read(ctx, f, 0, 16); err != nil || string(b) != "data" {
		t.Fatalf("read %q %v", b, err)
	}
	checks := map[string]error{}
	_, checks["open-write"] = c.Open(ctx, 0, e.Handle, uint32(os.O_RDWR))
	_, _, checks["create"] = c.Create(ctx, 0, volumeshare.Caller{}, c.Root(), "new", uint32(os.O_RDWR), 0o644)
	_, checks["mkdir"] = c.Mkdir(ctx, volumeshare.Caller{}, c.Root(), "d", 0o755)
	checks["unlink"] = c.Unlink(ctx, c.Root(), "f")
	_, checks["write"] = c.Write(ctx, f, 0, []byte("x"))
	checks["write-lock"] = c.SetLk(ctx, f, 1, volumeshare.Lock{End: ^uint64(0), Type: unix.F_WRLCK}, false, false)
	for name, err := range checks {
		if !errors.Is(err, syscall.EROFS) {
			t.Errorf("%s: %v, want EROFS", name, err)
		}
	}
	if err := c.SetLk(ctx, f, 1, volumeshare.Lock{End: ^uint64(0), Type: unix.F_RDLCK}, false, false); err != nil {
		t.Fatal("read lock refused", err)
	}
}

// A change is authorized against the current state every time: once the
// writer's pin is withdrawn the very next write is refused, with no
// recheck window.
func TestWriteChecksAuthorizationEveryTime(t *testing.T) {
	root, _ := openRoot(t)
	var mu sync.Mutex
	writer := true
	ro := volumeshare.ReadOnly(root)
	now := &clock{t: time.Unix(1_800_000_000, 0)}
	server := volumeshare.NewServer(func(context.Context, [32]byte, string) (volumeshare.Ops, error) {
		mu.Lock()
		defer mu.Unlock()
		if writer {
			return root, nil
		}
		return ro, nil
	}, volumeshare.ServerOptions{Now: now.Now})
	ctx := context.Background()
	c, err := volumeshare.Dial(ctx, func(ctx context.Context, h, d []byte) ([]byte, []byte, error) {
		return server.Handle(ctx, [32]byte{1}, h, d)
	}, volumeshare.ClientOptions{Volume: "v"})
	if err != nil {
		t.Fatal(err)
	}
	_, f, err := c.Create(ctx, 0, volumeshare.Caller{}, c.Root(), "f", uint32(os.O_RDWR), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(ctx, f, 0, []byte("a")); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	writer = false
	mu.Unlock()
	// Same instant: no recheck is due, yet the write is refused.
	if _, err := c.Write(ctx, f, 1, []byte("b")); !errors.Is(err, syscall.EACCES) {
		t.Fatalf("write after the pin went: %v", err)
	}
	if server.Mounts() != 0 {
		t.Fatal("mount kept after its writer pin went")
	}
}

// blockingOps holds Write until release closes.
type blockingOps struct {
	volumeshare.Ops
	entered chan struct{}
	release chan struct{}
}

func (b blockingOps) Write(ctx context.Context, f volumeshare.FileID, off uint64, data []byte) (uint32, error) {
	b.entered <- struct{}{}
	<-b.release
	return b.Ops.Write(ctx, f, off, data)
}

// Revoke ends a volume's mounts, returns only after the operations they had
// in flight are done, refuses the volume
// from then on, and leaves other volumes alone.
func TestRevokeWaitsOutOperationsInFlight(t *testing.T) {
	root, _ := openRoot(t)
	ops := blockingOps{Ops: root, entered: make(chan struct{}, 1), release: make(chan struct{})}
	server := volumeshare.NewServer(func(context.Context, [32]byte, string) (volumeshare.Ops, error) { return ops, nil }, volumeshare.ServerOptions{})
	ctx := context.Background()
	dial := func(volume string) *volumeshare.Client {
		c, err := volumeshare.Dial(ctx, func(ctx context.Context, h, d []byte) ([]byte, []byte, error) {
			return server.Handle(ctx, [32]byte{1}, h, d)
		}, volumeshare.ClientOptions{Volume: volume})
		if err != nil {
			t.Fatal(volume, err)
		}
		return c
	}
	gone, kept := dial("gone"), dial("kept")
	_, f, err := gone.Create(ctx, 0, volumeshare.Caller{}, gone.Root(), "f", uint32(os.O_RDWR), 0o644)
	if err != nil {
		t.Fatal(err)
	}
	wrote := make(chan error, 1)
	go func() { _, err := gone.Write(ctx, f, 0, []byte("late")); wrote <- err }()
	<-ops.entered
	revoked := make(chan struct{})
	go func() { server.Revoke("gone"); close(revoked) }()
	select {
	case <-revoked:
		t.Fatal("revoke returned with a write in flight")
	case <-time.After(100 * time.Millisecond):
	}
	close(ops.release)
	<-revoked
	if err := <-wrote; err != nil {
		t.Fatal("the write in flight was cut", err)
	}
	if _, err := gone.Lookup(ctx, gone.Root(), "f"); err == nil {
		t.Fatal("revoked mount still answered")
	}
	if _, err := volumeshare.Dial(ctx, func(ctx context.Context, h, d []byte) ([]byte, []byte, error) {
		return server.Handle(ctx, [32]byte{1}, h, d)
	}, volumeshare.ClientOptions{Volume: "gone"}); err == nil {
		t.Fatal("revoked volume mounted again")
	}
	if _, err := kept.Lookup(ctx, kept.Root(), "f"); err != nil {
		t.Fatal("other volume lost", err)
	}

	server.Revoke("kept")
	if server.Mounts() != 0 {
		t.Fatal("mounts left", server.Mounts())
	}
}
