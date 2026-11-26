// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestP0FreshWalletJournalAbsenceRetainsUnsafePathErrors(t *testing.T) {
	home := t.TempDir()
	if err := os.Mkdir(filepath.Join(home, ".mydc"), 0700); err != nil {
		t.Fatal(err)
	}
	client := Client{Cluster: [32]byte{71}}
	if _, err := operationRoot(home, client, "admin", false); !errors.Is(err, ErrOperationMissing) {
		t.Fatal("wallet-only profile rejected its first command", err)
	}
	root, err := operationRoot(home, client, "admin", true)
	if err != nil {
		t.Fatal(err)
	}
	_ = root.Close()
	sessions := filepath.Join(home, ".mydc", "sessions")
	if err = os.Chmod(sessions, 0777); err != nil {
		t.Fatal(err)
	}
	if _, err = operationRoot(home, client, "admin", false); !errors.Is(err, ErrPrivateState) || errors.Is(err, ErrOperationMissing) {
		t.Fatal("unsafe permissions treated as a fresh intent", err)
	}
	if err = os.Chmod(sessions, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(sessions, sessions+"-original"); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink("sessions-original", sessions); err != nil {
		t.Fatal(err)
	}
	if _, err = operationRoot(home, client, "admin", false); !errors.Is(err, ErrPrivateState) || errors.Is(err, ErrOperationMissing) {
		t.Fatal("symlink adopted as a fresh journal", err)
	}
}
