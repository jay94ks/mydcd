// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRealBoundaryIdentityFiles(t *testing.T) {
	root := t.TempDir()
	created, err := Create(root)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(root)
	if err != nil || loaded.Actor() != created.Actor() {
		t.Fatal(err)
	}
	if _, err := Create(root); err == nil {
		t.Fatal("overwrote identity")
	}
	if key, err := ParseKey(created.Actor()); err != nil || key != created.Public {
		t.Fatal(err)
	}
	if err = os.Chmod(filepath.Join(root, "key.pem"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(root); err == nil {
		t.Fatal("exposed private key accepted")
	}
	if _, err := ParseKey("00"); err == nil {
		t.Fatal("short key")
	}
}
