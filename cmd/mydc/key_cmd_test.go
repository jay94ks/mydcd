// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/wallet"
)

func TestKeyCreateImportListShowWithScriptPassword(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if code, _, e := mydc(t, "key", "list"); code != 1 || !strings.Contains(e, "no wallet yet") {
		t.Fatal(code, e)
	}
	if code, _, e := mydc(t, "key", "create", "laptop"); code == 0 {
		t.Fatal("wallet created without any password", e)
	}
	secret := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(secret, []byte("correct horse\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MYDC_WALLET_PASSWORD_FILE", secret)
	if code, _, e := mydc(t, "key", "create", "laptop"); code == 0 || !strings.Contains(e, "mode 0600") {
		t.Fatal("readable password file accepted", code, e)
	}
	if err := os.Chmod(secret, 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, e := mydc(t, "key", "create", "laptop", "-o", "json")
	var created []wallet.PublicKey
	if code != 0 || json.Unmarshal([]byte(out), &created) != nil || len(created) != 1 || created[0].Name != "laptop" || len(created[0].ID) != 64 {
		t.Fatal(code, out, e)
	}
	if strings.Contains(out+e, "correct horse") {
		t.Fatal("password printed")
	}
	dir := filepath.Join(t.TempDir(), "id")
	self, err := identity.Create(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(self.Private)
	if code, _, e := mydc(t, "key", "import", "ops", filepath.Join(t.TempDir(), "missing.pem")); code != 1 {
		t.Fatal(code, e)
	}
	if code, out, e := mydc(t, "key", "import", "ops", filepath.Join(dir, "key.pem")); code != 0 || !strings.Contains(out, fmt.Sprintf("%x", self.Public)) {
		t.Fatal(code, out, e)
	}
	code, out, _ = mydc(t, "key", "list")
	if code != 0 || !strings.Contains(out, "laptop") || !strings.Contains(out, created[0].ID) {
		t.Fatalf("%d %q", code, out)
	}
	if code, out, _ := mydc(t, "key", "show", "laptop"); code != 0 || !strings.Contains(out, created[0].ID) {
		t.Fatalf("%d %q", code, out)
	}
	if code, _, e := mydc(t, "key", "show", "nope"); code != 1 || !strings.Contains(e, "no key named nope") {
		t.Fatal(code, e)
	}
	if code, _, e := mydc(t, "key", "passwd"); code != 1 || !strings.Contains(e, "terminal") {
		t.Fatal(code, e)
	}
	if err := os.WriteFile(secret, []byte("wrong\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := mydc(t, "key", "list"); code == 0 {
		t.Fatal("wrong password unlocked the wallet")
	}
}
