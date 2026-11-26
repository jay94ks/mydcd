// SPDX-License-Identifier: Apache-2.0

package app

import (
	"errors"
	"os"
	"syscall"
	"testing"

	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/nodeapp"
)

func TestNodeAppSocketOpensInItsOwnRunDirectory(t *testing.T) {
	root, err := os.MkdirTemp("", "mydc-na-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	self, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	mesh, err := mydcp.NewTransport(self, [32]byte{3}, func(mydcp.Identity) (mydcp.Peer, bool) { return mydcp.Peer{}, false })
	if err != nil {
		t.Fatal(err)
	}
	defer mesh.Close()
	uid := uint32(10001)
	if os.Geteuid() != 0 {
		uid = uint32(os.Geteuid())
	}
	var c config.Node
	c.Node.StateDir = root
	c.NodeApps.Web = &config.NodeAppWeb{Enabled: true, UID: uid}
	if err = listenNodeAppSockets(mesh, c); err != nil {
		t.Fatal(err)
	}
	dir, err := os.Stat(nodeapp.RunDir(root, nodeapp.Web))
	if err != nil || dir.Mode().Perm() != 0755 {
		t.Fatal("run directory", dir, err)
	}
	sock, err := os.Lstat(nodeapp.SocketPath(root, nodeapp.Web))
	if err != nil || sock.Mode()&os.ModeSocket == 0 || sock.Mode().Perm() != 0600 || sock.Sys().(*syscall.Stat_t).Uid != uid {
		t.Fatal("node app socket", sock, err)
	}
	if err = mesh.CloseUnix(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Lstat(nodeapp.SocketPath(root, nodeapp.Web)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("node app socket remained", err)
	}
	c.NodeApps.Web.Enabled = false
	other, err := mydcp.NewTransport(self, [32]byte{3}, func(mydcp.Identity) (mydcp.Peer, bool) { return mydcp.Peer{}, false })
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err = listenNodeAppSockets(other, c); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Lstat(nodeapp.SocketPath(root, nodeapp.Web)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("disabled node app got a socket", err)
	}
}
