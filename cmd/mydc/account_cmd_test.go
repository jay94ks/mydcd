// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/identity"
)

func TestAccountCommandsHelpAndCheckArgumentsOffline(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	for args, want := range map[string]string{
		"login --help":  "--approve-with",
		"logout --help": "never sent",
		"whoami --help": "tenants",
		"enroll --help": "bootstrap admin key",
	} {
		if code, out, e := mydc(t, strings.Fields(args)...); code != 0 || !strings.Contains(out+e, want) {
			t.Fatal(args, code, out, e)
		}
	}
	for _, args := range [][]string{
		{"login"},          // no user anywhere
		{"login", "alice"}, // no key, password or token
		{"login", "alice", "--password", "--token"},
		{"login", "alice", "--key", "k", "--stdin"},
		{"login", "alice", "--password", "--key", "k"},
		{"enroll", "alice"},
	} {
		if code, _, e := mydc(t, args...); code != 2 {
			t.Fatal(args, code, e)
		}
	}
	if code, out, _ := mydc(t, "version"); code != 0 || !strings.Contains(out, "client") {
		t.Fatal(code, out)
	}
}

func TestAccountCommandsLoginWhoamiLogoutAgainstManagedNode(t *testing.T) {
	root, home := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	operator, err := identity.Create(filepath.Join(root, "operator"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(operator.Private)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	fixture := newManagedNode(t, ctx, root, "node", operator)
	fixture.EnrollAdmin(access.User{ID: "sys", Username: "operator", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: operator.Public, Enabled: true}}})
	node := fixture.Node()
	secret := filepath.Join(root, "wallet-password")
	if err := os.WriteFile(secret, []byte("wallet secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MYDC_WALLET_PASSWORD_FILE", secret)
	steps := [][]string{
		{"key", "import", "ops", filepath.Join(root, "operator", "key.pem")},
		{"context", "add", "prod", "mydcp://" + fixture.Address, "--key", hex.EncodeToString(node.Public[:]), "--user", "operator", "--wallet-key", "ops"},
		{"login"},
	}
	for _, args := range steps {
		if code, out, e := mydc(t, args...); code != 0 {
			t.Fatal(args, code, out, e)
		}
	}
	code, out, e := mydc(t, "whoami", "-o", "json")
	var who struct {
		Username string `json:"username"`
	}
	if code != 0 || json.Unmarshal([]byte(out), &who) != nil || who.Username != "operator" {
		t.Fatal(code, out, e)
	}
	if code, out, _ := mydc(t, "whoami"); code != 0 || !strings.Contains(out, "system admin") {
		t.Fatalf("%d %q", code, out)
	}
	if code, out, e := mydc(t, "version"); code != 0 || !strings.Contains(out, "protocol") {
		t.Fatal(code, out, e)
	}
	if code, out, e := mydc(t, "logout"); code != 0 {
		t.Fatal(code, out, e)
	}
	if code, _, _ := mydc(t, "whoami"); code == 0 {
		t.Fatal("whoami after logout")
	}
	if strings.Contains(out+e, "wallet secret") {
		t.Fatal("password printed")
	}
}
