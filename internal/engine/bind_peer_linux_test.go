// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	"golang.org/x/sys/unix"
)

func TestProcessBindSourcesRequireLiveOriginalDirectory(t *testing.T) {
	root := t.TempDir()
	original, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	want := []BindSource{{Path: root, DirectoryFD: int(original.Fd())}}
	if err = CheckProcessBindSources(os.Getpid(), want); err != nil {
		t.Fatal("live actual process root", err)
	}
	other, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err = CheckProcessBindSources(os.Getpid(), []BindSource{{Path: root, DirectoryFD: int(other.Fd())}}); err == nil {
		t.Fatal("process path adopted a different held original")
	}
	link := filepath.Join(t.TempDir(), "alias")
	if err = os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if err = CheckProcessBindSources(os.Getpid(), []BindSource{{Path: link, DirectoryFD: int(original.Fd())}}); err == nil {
		t.Fatal("process target followed a symlink")
	}
	if err = CheckProcessBindSources(0, want); err == nil {
		t.Fatal("missing process became mount evidence")
	}
	child := exec.Command("sleep", "30")
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	if err = CheckProcessBindSources(child.Process.Pid, want); err != nil {
		t.Fatal("actual child process root", err)
	}
	if err = child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait()
	if err = CheckProcessBindSources(child.Process.Pid, want); err == nil {
		t.Fatal("terminated process became mount evidence")
	}
}

// Real local Unix peer/procfs/FD comparisons without Docker, mount changes,
// user data or a mock filesystem identity. They run at S1's final boundary.
func TestBindPeerRequiresExactHeldDirectoryAndRejectsSymlinks(t *testing.T) {
	root := t.TempDir()
	endpoint := filepath.Join(root, "engine.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: endpoint, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	var mutations atomic.Int32
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/containers/create") {
			mutations.Add(1)
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = conn.Close() // submitted effect, deliberately no response
			return
		}
		if r.Method != http.MethodHead || r.URL.Path != "/_ping" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("API-Version", client.MaxAPIVersion)
		w.WriteHeader(http.StatusOK)
	})}
	done := make(chan struct{})
	go func() { defer close(done); _ = server.Serve(listener) }()
	t.Cleanup(func() {
		_ = server.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("owned peer server did not close")
		}
	})
	probe := func(sources []BindSource) error {
		conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: endpoint, Net: "unix"})
		if err != nil {
			return err
		}
		defer conn.Close()
		return checkBindPeer(conn, sources)
	}
	original := filepath.Join(root, "original")
	other := filepath.Join(root, "other")
	if err = os.Mkdir(original, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(other, 0700); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(original)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	source := BindSource{Path: original, DirectoryFD: int(f.Fd())}
	if err = probe([]BindSource{source}); err != nil {
		t.Fatal("same actual socket peer/original directory", err)
	}

	bad := source
	bad.Path = other
	if err = probe([]BindSource{bad}); err == nil {
		t.Fatal("different peer-visible inode accepted")
	}
	alias := filepath.Join(root, "alias")
	if err = os.Symlink(original, alias); err != nil {
		t.Fatal(err)
	}
	bad.Path = alias
	if err = probe([]BindSource{bad}); err == nil {
		t.Fatal("source symlink accepted")
	}
	retained := filepath.Join(root, "retained")
	if err = os.Rename(original, retained); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(original, 0700); err != nil {
		t.Fatal(err)
	}
	if err = probe([]BindSource{source}); err == nil {
		t.Fatal("replacement path accepted despite held original FD")
	}
	// The real SDK transport must recheck each connection after namespace/
	// path changes rather than reuse a previous positive observation.
	api, err := client.New(client.WithHost("unix://" + endpoint))
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	e := &Client{API: api, Owner: "owned-test"}
	current, err := os.Open(original)
	if err != nil {
		t.Fatal(err)
	}
	defer current.Close()
	guarded, err := e.BindClient([]BindSource{{Path: original, DirectoryFD: int(current.Fd())}})
	if err != nil {
		t.Fatal(err)
	}
	defer guarded.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err = guarded.Ping(ctx, client.PingOptions{}); err != nil {
		t.Fatal("guarded actual HTTP SDK ping", err)
	}
	options := client.ContainerCreateOptions{Config: &container.Config{Image: "sha256:" + strings.Repeat("a", 64)}}
	if _, err = guarded.ContainerCreate(ctx, options); err == nil || errors.Is(err, ErrBindBeforeRequest) || mutations.Load() != 1 {
		t.Fatal("response loss after actual API request classified as unsent", err, mutations.Load())
	}
	if err = os.Rename(original, filepath.Join(root, "replaced-again")); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(original, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err = guarded.ContainerCreate(ctx, options); !errors.Is(err, ErrBindBeforeRequest) || mutations.Load() != 1 {
		t.Fatal("SDK reused prior source permission or lost positive unsent fact", err, mutations.Load())
	}
}

func TestBindPeerInheritedListenerUsesResponderIdentity(t *testing.T) {
	const childEnv = "MYDC_BIND_PEER_OWNED_CHILD"
	if os.Getenv(childEnv) == "1" {
		file := os.NewFile(3, "owned-inherited-engine-listener")
		listener, err := net.FileListener(file)
		_ = file.Close()
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })}
		if err = server.Serve(listener); err != nil && err != http.ErrServerClosed {
			t.Fatal(err)
		}
		return
	}
	endpoint := filepath.Join(t.TempDir(), "engine.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: endpoint, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	t.Cleanup(func() { _ = listener.Close() })
	file, err := listener.File()
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(executable, "-test.run=^TestBindPeerInheritedListenerUsesResponderIdentity$", "-test.timeout=45s")
	child.Env = append(os.Environ(), childEnv+"=1")
	child.ExtraFiles = []*os.File{file}
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	_ = file.Close()
	_ = listener.Close()
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: endpoint, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err = conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var original *unix.Ucred
	var peerErr error
	if err = raw.Control(func(fd uintptr) { original, peerErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil || peerErr != nil || original == nil || int(original.Pid) != os.Getpid() {
		t.Fatal("fixture listener was not parent-owned", err, peerErr)
	}
	if err = enableSenderIdentity(conn); err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodHead, "http://docker/_ping", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = request.Write(conn); err != nil {
		t.Fatal(err)
	}
	sender, pidfd, err := senderIdentity(conn)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pidfd)
	if int(sender.Pid) != child.Process.Pid || sender.Pid == original.Pid {
		t.Fatal("listener creator substituted for actual inherited-socket responder")
	}
	if err = livePeer(pidfd); err != nil {
		t.Fatal("original responding process not alive", err)
	}
}
