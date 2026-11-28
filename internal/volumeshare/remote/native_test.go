// SPDX-License-Identifier: Apache-2.0

//go:build linux

package remote_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/nodestorage"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/volumeshare"
	"github.com/jay94ks/seafield/internal/volumeshare/front/mount"
	"github.com/jay94ks/seafield/internal/volumeshare/remote"
	"github.com/jay94ks/seafield/internal/workload/volumes"
	"golang.org/x/sys/unix"
)

// pair is a runner and a home over real SFCP QUIC.
func pair(t *testing.T, server *volumeshare.Server) (*sfcp.Transport, [32]byte, [32]byte) {
	t.Helper()
	a, err := identity.Create(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	b, err := identity.Create(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var endpoint string
	var mu sync.Mutex
	lookup := func(key sfcp.Identity) (sfcp.Peer, bool) {
		mu.Lock()
		defer mu.Unlock()
		switch key {
		case sfcp.Identity(a.Public):
			return sfcp.Peer{ID: "runner", Policy: sfcp.Policy{Key: key, Member: true, Respond: true}}, true
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
	runner, err := sfcp.NewTransport(a, [32]byte{24}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runner.Close() })
	return runner, [32]byte(a.Public), [32]byte(b.Public)
}

// A task's remote Volume end to end: the home grants the runner, the runner
// holds a FUSE mount, the engine's Mount answer opens it for the bound
// container only, a reader cannot write, and Release unmounts.
func TestRemoteMountsEndToEnd(t *testing.T) {
	if os.Getenv("SFC_FUSE_NATIVE") != "1" || os.Geteuid() != 0 {
		t.Skip("set SFC_FUSE_NATIVE=1 and run as root on a host with /dev/fuse")
	}
	data := t.TempDir()
	if err := os.WriteFile(filepath.Join(data, "on-home"), []byte("from the home"), 0o644); err != nil {
		t.Fatal(err)
	}
	scope := volumes.Scope{Cluster: [32]byte{24}, Tenant: "t", App: "a", ID: "data", Generation: 2}
	ready := volumes.NativeReady{Spec: volumes.NativeSpec{Kind: "node-fixed", Scope: scope}, Generation: 1}
	writer := volumes.Consumer{ID: "writer", Generation: 1, Writable: true, Runner: "node-b", RunnerKey: "00"}
	reader := volumes.Consumer{ID: "reader", Generation: 1, Runner: "node-b", RunnerKey: "00"}
	var runnerKey [32]byte
	grants := 0
	home := remote.NewHome(func(_ context.Context, peer [32]byte, ref remote.MountRef) (volumes.Consumer, volumes.NativeReady, error) {
		grants++
		if peer != runnerKey || ref.Scope != scope {
			return volumes.Consumer{}, volumes.NativeReady{}, syscall.EACCES
		}
		switch ref.Consumer {
		case writer.ID:
			return writer, ready, nil
		case reader.ID:
			return reader, ready, nil
		}
		return volumes.Consumer{}, volumes.NativeReady{}, syscall.EACCES
	}, func(context.Context, volumes.NativeReady) (*nodestorage.DirectoryHandle, error) {
		return nodestorage.OpenDirectory(data)
	}, func(volumes.NativeReady) []byte { return bytes.Repeat([]byte{5}, 32) })
	t.Cleanup(func() { _ = home.Close() })
	server := volumeshare.NewServer(home.Authorize, volumeshare.ServerOptions{})
	runner, rk, hk := pair(t, server)
	runnerKey = rk
	base := filepath.Join(t.TempDir(), "remote")
	m := remote.New(remote.FUSE(base, func(h [32]byte) volumeshare.Call { return volumeshare.CallHome(runner, sfcp.Identity(h)) }, sfcp.CallSent))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	w := remote.Spec{Scope: scope, Consumer: writer, Home: hk}
	name, err := m.Hold(ctx, w)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Release(name) }()
	if err = m.Bind(name, "container-w"); err != nil {
		t.Fatal(err)
	}
	dir, ro, found, err := m.EngineMountDir(ctx, name, "mount-1", "container-w")
	if err != nil || !found || ro {
		t.Fatal(dir, ro, found, err)
	}
	fd, _, _, err := mount.RootFD(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 64)
	f, err := unix.Openat(fd, "on-home", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := unix.Read(f, got)
	unix.Close(f)
	if string(got[:n]) != "from the home" {
		t.Fatalf("read %q", got[:n])
	}
	f, err = unix.Openat(fd, "from-runner", unix.O_WRONLY|unix.O_CREAT|unix.O_CLOEXEC, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = unix.Write(f, []byte("written remotely"))
	unix.Close(f)
	unix.Close(fd)
	if disk, err := os.ReadFile(filepath.Join(data, "from-runner")); err != nil || string(disk) != "written remotely" {
		t.Fatalf("home copy %q %v", disk, err)
	}

	r := remote.Spec{Scope: scope, Consumer: reader, Home: hk}
	rname, err := m.Hold(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Release(rname) }()
	_ = m.Bind(rname, "container-r")
	rdir, ro, _, err := m.EngineMountDir(ctx, rname, "mount-2", "container-r")
	if err != nil || !ro {
		t.Fatal("reader", ro, err)
	}
	if _, err := unix.Open(filepath.Join(rdir, "nope"), unix.O_WRONLY|unix.O_CREAT|unix.O_CLOEXEC, 0o644); err != syscall.EROFS {
		t.Fatal("reader wrote", err)
	}

	m.EngineUnmounted(name, "mount-1")
	if err = m.Release(name); err != nil {
		t.Fatal(err)
	}
	if err = m.Release(rname); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("mount point left", err)
	}
	// A sweep on a read older than the last grant keeps the root; one
	// after it, with no consumer left, stops serving it.
	none := func(volumes.NativeReady) bool { return false }
	if n := home.Sweep(time.Now().Add(-time.Hour), none); n != 0 {
		t.Fatal("swept a root granted after the read", n)
	}
	if n := home.Sweep(time.Now(), none); n != 1 {
		t.Fatal("unused root kept", n)
	}
	if _, err := m.Hold(ctx, remote.Spec{Scope: scope, Consumer: volumes.Consumer{ID: "late", Generation: 1, Writable: true, Runner: "node-b", RunnerKey: "00"}, Home: hk}); err == nil {
		t.Fatal("unknown consumer granted")
	}
}
