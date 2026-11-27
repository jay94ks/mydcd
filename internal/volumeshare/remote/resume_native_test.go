// SPDX-License-Identifier: Apache-2.0

//go:build linux

package remote_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/fdstore"
	"github.com/jay94ks/seafield/internal/nodestorage"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/storage"
	"github.com/jay94ks/seafield/internal/volumeshare"
	"github.com/jay94ks/seafield/internal/volumeshare/front/mount"
	"github.com/jay94ks/seafield/internal/volumeshare/remote"
	"github.com/jay94ks/seafield/internal/workload/volumes"
	"golang.org/x/sys/unix"
)

// fakeStore plays systemd's FD store on a NOTIFY_SOCKET.
type fakeStore struct {
	mu  sync.Mutex
	fds map[string][]int
}

func serveStore(t *testing.T) *fakeStore {
	t.Helper()
	path := filepath.Join(t.TempDir(), "notify")
	sock, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = unix.Bind(sock, &unix.SockaddrUnix{Name: path}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NOTIFY_SOCKET", path)
	s := &fakeStore{fds: map[string][]int{}}
	go func() {
		buf, oob := make([]byte, 1024), make([]byte, 256)
		for {
			n, oobn, _, _, err := unix.Recvmsg(sock, buf, oob, 0)
			if err != nil {
				return
			}
			var fds []int
			if msgs, err := unix.ParseSocketControlMessage(oob[:oobn]); err == nil && len(msgs) > 0 {
				fds, _ = unix.ParseUnixRights(&msgs[0])
			}
			state := string(buf[:n])
			name := ""
			for _, line := range strings.Split(state, "\n") {
				if v, ok := strings.CutPrefix(line, "FDNAME="); ok {
					name = v
				}
			}
			s.mu.Lock()
			switch {
			case strings.HasPrefix(state, "FDSTORE=1"):
				s.fds[name] = append(s.fds[name], fds...)
			case strings.HasPrefix(state, "FDSTOREREMOVE=1"):
				for _, fd := range s.fds[name] {
					unix.Close(fd)
				}
				delete(s.fds, name)
			}
			s.mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		unix.Close(sock)
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, fds := range s.fds {
			for _, fd := range fds {
				unix.Close(fd)
			}
		}
	})
	return s
}

// handBack gives the next sfcd copies of what is stored, as LISTEN_FDS would.
func (s *fakeStore) handBack(t *testing.T) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := map[string][]*os.File{}
	for name, fds := range s.fds {
		for _, fd := range fds {
			d, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			m[name] = append(m[name], os.NewFile(uintptr(d), name))
		}
	}
	fdstore.SetInherited(m)
}

func (s *fakeStore) names() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for name := range s.fds {
		out = append(out, name)
	}
	return out
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); !ok(); {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// sfcd dies with a remote Volume mounted in a "container" (fds opened on
// the mount and a subdirectory); the next sfcd gets the mount back from the
// FD store and serves the same kernel mount: the old fds keep working,
// including lookups under the subdirectory's node.
func TestRemoteMountSurvivesRestart(t *testing.T) {
	if os.Getenv("SFC_FUSE_NATIVE") != "1" || os.Geteuid() != 0 {
		t.Skip("set SFC_FUSE_NATIVE=1 and run as root on a host with /dev/fuse")
	}
	store := serveStore(t)
	data := t.TempDir()
	if err := os.MkdirAll(filepath.Join(data, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "sub", "before"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	scope := volumes.Scope{Cluster: [32]byte{24}, Tenant: "t", App: "a", ID: "data", Generation: 2}
	ready := volumes.NativeReady{Spec: volumes.NativeSpec{Kind: "node-fixed", Scope: scope}, Generation: 1}
	var runnerKey [32]byte
	writer := volumes.Consumer{ID: "writer", Generation: 1, Writable: true, Runner: "node-b"}
	home := remote.NewHome(func(_ context.Context, peer [32]byte, ref remote.MountRef) (volumes.Consumer, volumes.NativeReady, error) {
		if peer != runnerKey || ref.Consumer != writer.ID {
			return volumes.Consumer{}, volumes.NativeReady{}, syscall.EACCES
		}
		return writer, ready, nil
	}, func(context.Context, volumes.NativeReady) (*nodestorage.DirectoryHandle, error) {
		return nodestorage.OpenDirectory(data)
	}, func(volumes.NativeReady) []byte { return bytes.Repeat([]byte{5}, 32) })
	t.Cleanup(func() { _ = home.Close() })
	runner, rk, hk := pair(t, volumeshare.NewServer(home.Authorize, volumeshare.ServerOptions{}))
	runnerKey = rk
	writer.RunnerKey = hex.EncodeToString(rk[:])
	db, err := storage.Open(filepath.Join(t.TempDir(), "remote.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	base := filepath.Join(t.TempDir(), "remote")
	attach := func() remote.Attach {
		return remote.FUSE(base, func(h [32]byte) volumeshare.Call { return volumeshare.CallHome(runner, sfcp.Identity(h)) }, sfcp.CallSent)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	m, err := remote.Open(db, attach())
	if err != nil {
		t.Fatal(err)
	}
	spec := remote.Spec{Scope: scope, Consumer: writer, Home: hk}
	name, err := m.Hold(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	cleanup := func() { _ = unix.Unmount(filepath.Join(base, name), unix.MNT_DETACH) }
	defer cleanup()
	_ = m.Bind(name, "c")
	dir, _, _, err := m.EngineMountDir(ctx, name, "m", "c")
	if err != nil {
		t.Fatal(err)
	}
	root, _, _, err := mount.RootFD(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(root)
	sub, err := unix.Openat(root, "sub", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(sub)
	if got := storedNames(store); !got[name+".dev"] || !got[name+".n1"] {
		t.Fatal("mount not in the store", got)
	}

	remote.Abandon(m, name) // sfcd dies
	store.handBack(t)
	m2, err := remote.Open(db, attach())
	if err != nil {
		t.Fatal(err)
	}
	m2.Resume(ctx)
	waitFor(t, "resume", func() bool { held, _ := m2.Held(name); return held })

	f, err := unix.Openat(sub, "before", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal("lookup under a pre-restart node", err)
	}
	buf := make([]byte, 16)
	n, _ := unix.Read(f, buf)
	unix.Close(f)
	if string(buf[:n]) != "old" {
		t.Fatalf("read %q", buf[:n])
	}
	f, err = unix.Openat(sub, "after", unix.O_WRONLY|unix.O_CREAT|unix.O_CLOEXEC, 0o644)
	if err != nil {
		t.Fatal("create after restart", err)
	}
	_, _ = unix.Write(f, []byte("new"))
	unix.Close(f)
	if disk, err := os.ReadFile(filepath.Join(data, "sub", "after")); err != nil || string(disk) != "new" {
		t.Fatalf("home copy %q %v", disk, err)
	}

	unix.Close(sub)
	unix.Close(root)
	if err = m2.Release(name); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "store emptied", func() bool { return len(storedNames(store)) == 0 })
}

func storedNames(s *fakeStore) map[string]bool {
	out := map[string]bool{}
	for _, n := range s.names() {
		out[n] = true
	}
	return out
}
