// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
)

func TestReadOnlySourceOpenDoesNotCreateOrWriteOriginalDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source.db")
	if db, err := OpenReadOnly(path); err == nil {
		_ = db.Close()
		t.Fatal("missing source DB was initialized")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("readonly open created a file", err)
	}
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Write(map[string][]byte{"original": []byte("retained")}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	if raw, err := reader.Get("original"); err != nil || string(raw) != "retained" {
		t.Fatal(string(raw), err)
	}
	if err := reader.Write(map[string][]byte{"original": []byte("changed")}); err == nil {
		t.Fatal("readonly source accepted a write")
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil || sha256.Sum256(before) != sha256.Sum256(after) {
		t.Fatal("source bytes changed during readonly observation", err)
	}
}
