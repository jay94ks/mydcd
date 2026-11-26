// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestRealBoundaryTransactionsAndOwnership(t *testing.T) {
	root := t.TempDir()
	lock, err := LockRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	if duplicate, err := LockRoot(root); err == nil {
		_ = duplicate.Close()
		t.Fatal("duplicate root writer")
	}
	db, err := Open(filepath.Join(root, "module.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Write(map[string][]byte{"desired": []byte("new"), "receipt": []byte("committed"), "lastApplied": []byte("1")}); err != nil {
		t.Fatal(err)
	}
	b, _ := db.Get("desired")
	b[0] = '!'
	again, _ := db.Get("desired")
	if string(again) != "new" {
		t.Fatal("read buffer aliases database")
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = Open(filepath.Join(root, "module.db"))
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{"desired": "new", "receipt": "committed", "lastApplied": "1"} {
		value, err := db.Get(key)
		if err != nil || string(value) != want {
			t.Fatal("reopen lost transaction", key, err)
		}
	}
	if err = db.Write(map[string][]byte{"valid": []byte("must rollback"), "": []byte("invalid empty key")}); err == nil {
		t.Fatal("invalid transaction succeeded")
	}
	if _, err := db.Get("valid"); !errors.Is(err, ErrMissing) {
		t.Fatal("failed transaction partially committed", err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	if err = lock.Close(); err != nil {
		t.Fatal(err)
	}
	lock, err = LockRoot(root)
	if err != nil {
		t.Fatal("ownership not released", err)
	}
	_ = lock.Close()
}
