// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/pkg/sfcp/enginemux"
)

// The real peer check admits the test binary only after AllowEnginePeer.
func TestAllowEnginePeerAdmitsNamedExecutable(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("the engine peer check needs root")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		t.Fatal(err)
	}
	listen := func(allow string) (*Transport, string) {
		self, err := identity.Create(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		tr, err := NewTransport(self, [32]byte{3}, func(Identity) (Peer, bool) { return Peer{}, false })
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = tr.Close() })
		if allow != "" {
			if err = tr.AllowEnginePeer(allow); err != nil {
				t.Fatal(err)
			}
		}
		dir := t.TempDir()
		if err = os.Chmod(dir, 0700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "sfcd.sock")
		if err = tr.ListenEngine(path); err != nil {
			t.Fatal(err)
		}
		if tr.AllowEnginePeer(exe) == nil {
			t.Fatal("peer allowed after listening")
		}
		return tr, path
	}
	connected := func(tr *Transport, path string) bool {
		c, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		engine := enginemux.Client(c)
		defer engine.Close()
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if _, ok := tr.Engine(); ok {
				return true
			}
			time.Sleep(10 * time.Millisecond)
		}
		return false
	}
	if tr, path := listen(""); connected(tr, path) {
		t.Fatal("test binary admitted without AllowEnginePeer")
	}
	if tr, path := listen(exe); !connected(tr, path) {
		t.Fatal("allowed test binary was refused")
	}
	for _, bad := range []string{"", "sfed", "/usr/bin/../bin/x"} {
		tr, _ := NewTransport(&identity.Identity{}, [32]byte{3}, func(Identity) (Peer, bool) { return Peer{}, false })
		if tr != nil && tr.AllowEnginePeer(bad) == nil {
			t.Fatal("bad executable path accepted", bad)
		}
	}
}

// Close removes the engine socket it created.
func TestEngineSocketRemovedOnClose(t *testing.T) {
	self, err := identity.Create(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tr, err := NewTransport(self, [32]byte{3}, func(Identity) (Peer, bool) { return Peer{}, false })
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "sfcd.sock")
	if err = tr.ListenEngine(path); err != nil {
		t.Fatal(err)
	}
	if err = tr.Close(); err != nil {
		t.Fatal("close", err)
	}
	if _, err = os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("engine socket left behind", err)
	}
}
