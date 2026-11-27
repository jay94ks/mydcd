// SPDX-License-Identifier: Apache-2.0

package app

import (
	"errors"
	"os"
	"syscall"
	"testing"

	"github.com/jay94ks/seafield/internal/clusterapp"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
)

func TestClusterAppSocketOpensInItsOwnRunDirectory(t *testing.T) {
	root, err := os.MkdirTemp("", "sfc-na-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	self, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	mesh, err := sfcp.NewTransport(self, [32]byte{3}, func(sfcp.Identity) (sfcp.Peer, bool) { return sfcp.Peer{}, false })
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
	c.ClusterApps.Web = &config.ClusterAppWeb{Enabled: true, UID: uid}
	if err = listenClusterAppSockets(mesh, c); err != nil {
		t.Fatal(err)
	}
	dir, err := os.Stat(clusterapp.RunDir(root, clusterapp.Web))
	if err != nil || dir.Mode().Perm() != 0755 {
		t.Fatal("run directory", dir, err)
	}
	sock, err := os.Lstat(clusterapp.SocketPath(root, clusterapp.Web))
	if err != nil || sock.Mode()&os.ModeSocket == 0 || sock.Mode().Perm() != 0600 || sock.Sys().(*syscall.Stat_t).Uid != uid {
		t.Fatal("cluster app socket", sock, err)
	}
	if err = mesh.CloseUnix(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Lstat(clusterapp.SocketPath(root, clusterapp.Web)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cluster app socket remained", err)
	}
	c.ClusterApps.Web.Enabled = false
	other, err := sfcp.NewTransport(self, [32]byte{3}, func(sfcp.Identity) (sfcp.Peer, bool) { return sfcp.Peer{}, false })
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err = listenClusterAppSockets(other, c); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Lstat(clusterapp.SocketPath(root, clusterapp.Web)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("disabled cluster app got a socket", err)
	}
}
