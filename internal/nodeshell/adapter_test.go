// SPDX-License-Identifier: Apache-2.0

package nodeshell

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"testing"
)

func adapterFixture(t *testing.T) *Adapter {
	t.Helper()
	root := t.TempDir()
	state := filepath.Join(root, "state")
	if err := os.Mkdir(state, 0700); err != nil {
		t.Fatal(err)
	}
	sudoers := filepath.Join(root, "sudoers.d")
	if err := os.Mkdir(sudoers, 0755); err != nil {
		t.Fatal(err)
	}
	a, err := New(Config{StateDir: state, Home: filepath.Join(root, "home"), HostPublicKeyFile: filepath.Join(root, "host.pub"), SudoersDir: sudoers})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestNodeShellAccountPreparationOwnsOnlyItsOriginalNonRootAccount(t *testing.T) {
	a := adapterFixture(t)
	var current *user.User
	a.lookup = func(name string) (*user.User, error) {
		if name != Account {
			t.Fatal("unexpected account lookup", name)
		}
		if current == nil {
			return nil, user.UnknownUserError(Account)
		}
		copy := *current
		return &copy, nil
	}
	var calls int
	a.run = func(_ context.Context, name string, args ...string) error {
		calls++
		if name != "useradd" || len(args) == 0 || args[len(args)-1] != Account {
			t.Fatal("unexpected provisioning command", name, args)
		}
		current = &user.User{Username: Account, Name: "MyDC node shell", Uid: "10001", Gid: "10002", HomeDir: a.config.Home}
		return nil
	}
	if err := a.prepareAccount(context.Background()); err != nil || calls != 1 {
		t.Fatal("first account preparation", err, calls)
	}
	first, _ := os.ReadFile(filepath.Join(a.config.StateDir, "account.json"))
	if err := a.prepareAccount(context.Background()); err != nil || calls != 1 {
		t.Fatal("original account was recreated", err, calls)
	}
	second, _ := os.ReadFile(filepath.Join(a.config.StateDir, "account.json"))
	if !bytes.Equal(first, second) {
		t.Fatal("reuse replaced original account identity")
	}
	current.Uid = "0"
	if err := a.prepareAccount(context.Background()); err == nil || calls != 1 {
		t.Fatal("root substitution was accepted")
	}
	b := adapterFixture(t)
	b.lookup = func(string) (*user.User, error) {
		return &user.User{Username: Account, Name: "operator-owned", Uid: "10003", Gid: "10004", HomeDir: b.config.Home}, nil
	}
	b.run = func(context.Context, string, ...string) error { t.Fatal("adopted an unowned account"); return nil }
	if err := b.prepareAccount(context.Background()); err == nil {
		t.Fatal("pre-existing arbitrary account was adopted")
	}
	if _, err := os.Lstat(filepath.Join(b.config.StateDir, "account.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("refusal wrote an account ownership marker")
	}
}

func TestNodeShellPrivateKeyAndSudoRulesRefuseUnownedFiles(t *testing.T) {
	a := adapterFixture(t)
	first, err := a.signer(true)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(a.config.StateDir, "ssh-key.bin"))
	again, err := a.signer(false)
	if err != nil || !bytes.Equal(first.PublicKey().Marshal(), again.PublicKey().Marshal()) {
		t.Fatal("private key changed during original reuse", err)
	}
	info, _ := os.Lstat(filepath.Join(a.config.StateDir, "ssh-key.bin"))
	if info.Mode().Perm() != 0600 || len(raw) != 32 {
		t.Fatal("private key was not a daemon-private binary seed")
	}
	path := filepath.Join(a.config.SudoersDir, Account)
	var checked int
	a.run = func(_ context.Context, name string, args ...string) error {
		checked++
		if name != "visudo" || len(args) != 3 || args[0] != "-c" || args[1] != "-f" {
			t.Fatal("sudoers syntax was not checked before installation", name, args)
		}
		data, err := os.ReadFile(args[2])
		if err != nil || string(data) != sudoRule {
			t.Fatal("syntax check did not consume the actual candidate", err)
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("sudoers was published before syntax acceptance")
		}
		return nil
	}
	if err := a.prepareSudo(context.Background(), true); err != nil || checked != 1 {
		t.Fatal("sudo allow installation", err)
	}
	if data, err := readOwned(path, 0440, 4096); err != nil || string(data) != sudoRule {
		t.Fatal("wrong installed sudo rule", err)
	}
	if err := a.prepareSudo(context.Background(), false); err != nil {
		t.Fatal("sudo revoke", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("owned sudo entry remained after revoke")
	}
	unowned := []byte("# operator-owned\nother ALL=(root) ALL\n")
	if err := os.WriteFile(path, unowned, 0440); err != nil {
		t.Fatal(err)
	}
	for _, allow := range []bool{false, true} {
		if err := a.prepareSudo(context.Background(), allow); err == nil {
			t.Fatal("unowned sudoers file was overwritten/deleted")
		}
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(unowned, after) {
		t.Fatal("refusal modified operator data")
	}
}

func TestNodeShellMissingPrerequisitesStayNotReadyWithoutAccountChanges(t *testing.T) {
	a := adapterFixture(t)
	a.lookup = func(string) (*user.User, error) {
		t.Fatal("missing host key reached account preparation")
		return nil, nil
	}
	a.run = func(context.Context, string, ...string) error {
		t.Fatal("missing prerequisite mutated OS state")
		return nil
	}
	ready := a.Prepare(context.Background(), false)
	want := "key-unavailable"
	if os.Geteuid() != 0 {
		want = "account-unavailable"
	}
	if ready.Ready || ready.Account != Account || ready.Reason != want || ready.SudoAllowed {
		t.Fatal("missing prerequisites reported usable shell", ready)
	}
	if _, err := a.Open(context.Background(), 80, 24, "alice"); !errors.Is(err, ErrNotReady) {
		t.Fatal("not-ready shell opened", err)
	}
	for _, endpoint := range []string{"host.example:22", "192.0.2.1:22", "0.0.0.0:22", "127.0.0.1:0"} {
		c := a.config
		c.Endpoint = endpoint
		if _, err := New(c); err == nil {
			t.Fatal("non-local endpoint accepted", endpoint)
		}
	}
	for _, name := range []string{"", "alice\nroot", "alice\x00root"} {
		if shellUser(name) {
			t.Fatal("invalid attribution value accepted")
		}
	}
}

func TestNodeShellSudoPublicationDoesNotOverwriteConcurrentOperatorFile(t *testing.T) {
	a := adapterFixture(t)
	path := filepath.Join(a.config.SudoersDir, Account)
	operator := []byte("# operator file appeared during syntax check\n")
	a.run = func(context.Context, string, ...string) error {
		return os.WriteFile(path, operator, 0440)
	}
	if err := a.prepareSudo(context.Background(), true); err == nil {
		t.Fatal("sudo publication overwrote a concurrent operator file")
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(operator, got) {
		t.Fatal("original operator file was replaced", err)
	}
}
