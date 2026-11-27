// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"path/filepath"
	"testing"

	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/storage"
)

// The genesis server moved: node.yaml's new listen is refused until
// set-listen records it; the installed endpoint (bound by the genesis)
// stays, and moving back clears the override.
func TestSetListenAcceptsMovedAddressAndKeepsInstalledEndpoint(t *testing.T) {
	root := t.TempDir()
	c := config.Node{Version: 1, Common: config.Common{}, Modules: map[string]config.Module{}}
	c.Node.ID = "node-a"
	c.Node.Listen = "192.0.2.10:7946"
	c.Node.StateDir = filepath.Join(root, "state")
	c.Node.IdentityDir = filepath.Join(root, "identity")
	admin, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(admin.Private)
	if _, err = PrepareInit(c, admin.Public, "init-a"); err != nil {
		t.Fatal(err)
	}
	if _, err = SetListen(c); err == nil {
		t.Fatal("set-listen without a changed node.yaml")
	}
	moved := c
	moved.Node.Listen = "192.0.2.20:7946"
	if _, err = Read(moved); err == nil {
		t.Fatal("changed listen read without set-listen")
	}
	lock, err := storage.LockRoot(c.Node.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = SetListen(moved); err == nil {
		t.Fatal("set-listen while the state root is locked")
	}
	_ = lock.Close()
	if was, err := SetListen(moved); err != nil || was != c.Node.Listen {
		t.Fatal(was, err)
	}
	r, err := Read(moved)
	if err != nil || r.Endpoint != c.Node.Listen || r.Genesis.Endpoint != c.Node.Listen || r.CurrentListen() != moved.Node.Listen {
		t.Fatal("moved record", r.Endpoint, r.Listen, err)
	}
	if _, err = Read(c); err == nil {
		t.Fatal("old listen still accepted")
	}
	if _, err = SetListen(c); err != nil {
		t.Fatal("move back", err)
	}
	if r, err = Read(c); err != nil || r.Listen != "" {
		t.Fatal("moving back keeps an override", r.Listen, err)
	}
}
