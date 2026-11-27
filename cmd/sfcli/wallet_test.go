// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/wallet"
)

func TestU0WalletCLIProtectedDescriptorsAndOriginalKeys(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	call := func(want int, args []string, passwords ...string) []byte {
		t.Helper()
		files := make([]*os.File, 0, len(passwords))
		defer func() {
			for _, f := range files {
				_ = f.Close()
			}
		}()
		for i, p := range passwords {
			name := filepath.Join(home, fmt.Sprintf("input-%d", i))
			if e := os.WriteFile(name, []byte(p+"\n"), 0600); e != nil {
				t.Fatal(e)
			}
			f, e := os.Open(name)
			if e != nil {
				t.Fatal(e)
			}
			files = append(files, f)
			flag := "--wallet-password-fd"
			if i == 1 {
				if args[0] == "passwd" {
					flag = "--new-wallet-password-fd"
				} else {
					flag = "--wallet-confirm-fd"
				}
			}
			if i == 2 {
				flag = "--wallet-confirm-fd"
			}
			args = append(args, flag, fmt.Sprint(f.Fd()))
		}
		var out, diag bytes.Buffer
		code := run(append([]string{"wallet"}, args...), &out, &diag)
		if code != want {
			t.Fatalf("wallet %s: code=%d want=%d: %s", args[0], code, want, diag.String())
		}
		for _, p := range passwords {
			if bytes.Contains(out.Bytes(), []byte(p)) || bytes.Contains(diag.Bytes(), []byte(p)) {
				t.Fatal("password leaked to output")
			}
		}
		return bytes.Clone(out.Bytes())
	}
	call(0, []string{"status"})
	if _, e := os.Stat(filepath.Join(home, ".sfc")); !os.IsNotExist(e) {
		t.Fatal("status created private state", e)
	}
	pass, next := "cli-private-password", "new-cli-password"
	call(2, []string{"init", "--no-input"}, pass, "mismatch")
	call(0, []string{"init", "--no-input"}, pass, pass)
	// Existing init must refuse before consuming another private descriptor.
	call(1, []string{"init", "--no-input", "--wallet-password-fd", "999999"})
	generated := call(0, []string{"generate", "--name", "operator", "--no-input"}, pass)
	var public wallet.PublicKey
	if json.Unmarshal(generated, &public) != nil || public.Name != "operator" {
		t.Fatal("public key output")
	}
	call(1, []string{"generate", "--name", "operator", "--no-input"}, pass)
	got := call(0, []string{"public", "operator", "--no-input"}, pass)
	if !bytes.Equal(got, generated) {
		t.Fatal("public identity changed")
	}
	seed := bytes.Repeat([]byte{29}, 32)
	defer clear(seed)
	private := ed25519.NewKeyFromSeed(seed)
	defer clear(private)
	der, e := x509.MarshalPKCS8PrivateKey(private)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(der)
	keyFile := filepath.Join(home, "import.pem")
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	defer clear(encoded)
	if e = os.WriteFile(keyFile, encoded, 0600); e != nil {
		t.Fatal(e)
	}
	imported := call(0, []string{"import", "--name", "imported", "--key-file", keyFile, "--no-input"}, pass)
	call(0, []string{"import", "--name", "imported", "--key-file", keyFile, "--no-input"}, pass)
	call(0, []string{"passwd", "--no-input"}, pass, next, next)
	call(1, []string{"list", "--no-input"}, pass)
	after := call(0, []string{"public", "imported", "--no-input"}, next)
	if !bytes.Equal(after, imported) {
		t.Fatal("password change changed imported signer")
	}
	call(0, []string{"list", "--no-input"}, next)
	call(2, []string{"list", "--no-input", "--wallet-password-fd", "0"})
	call(2, []string{"list", "--password", "must-not-be-accepted"})
	call(0, []string{"status"})
	call(0, []string{"recover"})
}
func TestU0WalletStandaloneProductDoesNotLoadClusterConfiguration(t *testing.T) {
	repo, e := filepath.Abs("../..")
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	root := t.TempDir()
	binary := filepath.Join(root, "sfcli")
	home := filepath.Join(root, "home")
	if e = os.Mkdir(home, 0700); e != nil {
		t.Fatal(e)
	}
	build := exec.CommandContext(ctx, "go", "build", "-p", "2", "-o", binary, "./cmd/sfcli")
	build.Dir = repo
	if b, e := build.CombinedOutput(); e != nil {
		t.Fatal("CLI build", e, string(b))
	}
	command := exec.CommandContext(ctx, binary, "--config", filepath.Join(root, "absent.yaml"), "wallet", "status")
	command.Env = append(os.Environ(), "HOME="+home)
	b, e := command.CombinedOutput()
	if e != nil || !strings.Contains(string(b), `"exists":false`) {
		t.Fatal("wallet required remote configuration", e, string(b))
	}
	if _, e = os.Stat(filepath.Join(home, ".sfc")); !os.IsNotExist(e) {
		t.Fatal("status created user wallet", e)
	}
}
