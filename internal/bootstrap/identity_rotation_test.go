// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/storage"
)

// Local persistence test. The installed control prefix is a modeled fact;
// this does not claim a real quorum, native fence or encrypted-data migration.
func TestPreparedIdentityRestartSelectorPreservesOriginalNativeBytes(t *testing.T) {
	root := t.TempDir()
	c := config.Node{Version: 1, Common: config.Common{}, Modules: map[string]config.Module{}}
	c.Node.ID = "node-a"
	c.Node.Listen = "127.0.0.1:43123"
	c.Node.StateDir = filepath.Join(root, "state")
	c.Node.IdentityDir = filepath.Join(root, "identity")
	admin, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(admin.Private)
	record, err := PrepareInit(c, admin.Public, "init-a")
	if err != nil {
		t.Fatal(err)
	}
	old, err := identity.Load(c.Node.IdentityDir)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(old.Private)
	for _, name := range []string{"raft.db", "fsm.db"} {
		db, err := storage.Open(filepath.Join(c.Node.StateDir, "control", name))
		if err != nil {
			t.Fatal(err)
		}
		if err = db.Close(); err != nil {
			t.Fatal(err)
		}
	}
	record.Root, err = record.Root.Install(record.Root.Cluster, lifecycle.Configuration{Index: 100, Members: []lifecycle.Member{record.Root.Self}}, 101)
	if err != nil {
		t.Fatal(err)
	}
	record.Signature = ed25519.Sign(old.Private, signingBytes(record))
	if err = write(c.Node.StateDir, record); err != nil {
		t.Fatal(err)
	}
	native := filepath.Join(c.Node.StateDir, "original-sealed-input")
	ciphertext := []byte("original-owner-sealed-data-sentinel")
	if err = os.WriteFile(native, ciphertext, 0600); err != nil {
		t.Fatal(err)
	}
	proof, err := PrepareIdentityRotation(c, "replace-a")
	if err != nil || !proof.Valid() {
		t.Fatal(proof, err)
	}
	replay, err := PrepareIdentityRotation(c, "replace-a")
	if err != nil || !bytes.Equal(lifecycle.IdentityProofBytes(proof), lifecycle.IdentityProofBytes(replay)) {
		t.Fatal("preparation regenerated key", err)
	}
	before, err := Read(c)
	if err != nil || before.Root.Self.Key != old.Public {
		t.Fatal("prepared key activated early", err)
	}
	after, err := ActivateIdentityRotation(c, proof, 3)
	if err != nil {
		t.Fatal(err)
	}
	if after.Root.AppliedIndex != 101 || after.Root.Installed.Index != 100 || after.Root.Keys[0].Index != 3 {
		t.Fatal("management activation ordinal replaced Raft installation positions")
	}
	effective, reopened, err := Effective(c)
	if err != nil || reopened.Root.Self.Key != proof.New || effective.Node.IdentityDir == c.Node.IdentityDir {
		t.Fatal(reopened, err)
	}
	next, err := identity.Load(effective.Node.IdentityDir)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(next.Private)
	if next.Public != proof.New {
		t.Fatal("TLS selector still uses old identity")
	}
	data, err := os.ReadFile(native)
	if err != nil || !bytes.Equal(data, ciphertext) {
		t.Fatal("activation rewrote original local material", err)
	}
	oldPath, ok := OwnerIdentityPath(c, after, proof.Old)
	if !ok || oldPath != c.Node.IdentityDir || NativeOwnerPath(c, after, proof.Old) != c.Node.StateDir || NativeOwnerPath(c, after, proof.New) == c.Node.StateDir {
		t.Fatal("native original owner namespace lost")
	}
}
