// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/secrets"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/tests/vaultfixture"
)

func TestSecretCommandLineErrorsBeforeLogin(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SFC_WALLET_PASSWORD_FILE", "")
	for _, args := range [][]string{
		{"secret", "show"},
		{"secret", "show", "Bad"},
		{"secret", "init"},
		{"secret", "create", "data", "--parent", "root", "--profile", "values", "--object", "t/data"},
		{"secret", "create", "data", "--profile", "values", "--object", "t/data", "--key", "k"},
		{"secret", "create", "data", "--parent", "root", "--profile", "values", "--object", "t/data", "--key", "bad key"},
		{"secret", "create", "data", "--parent", "root", "--profile", "builtin", "--object", "t/data", "--key", "k"},
		{"secret", "create", "data", "--parent", "root", "--profile", "values", "--key", "k"},
		{"secret", "group", "create", "g"},
		{"secret", "group", "approval-age", "g", "1.5s"},
		{"secret", "group", "reorder", "g"},
		{"secret", "put"},
		{"secret", "put", "data", "bad key"},
		{"secret", "put", "data", "--file", "key"},
		{"secret", "put", "data", "--value", "private"},
		{"secret", "acl", "data"},
		{"secret", "move", "data"},
		{"secret", "profile", "set", "values", "--node", "n"},
		{"secret", "issuer", "enable"},
		{"secret", "approvals", "revoke"},
		{"secret", "write", "abandon"},
		{"secret", "nope"},
	} {
		var out, diagnostic bytes.Buffer
		if code := run(args, &out, &diagnostic); code != 2 {
			t.Errorf("sfcli %s: exit %d, want 2: %s", strings.Join(args, " "), code, diagnostic.String())
		}
		if strings.Contains(diagnostic.String(), "allet") {
			t.Errorf("sfcli %s asked for the wallet: %s", strings.Join(args, " "), diagnostic.String())
		}
	}
}

func TestSecretHelpEveryCommand(t *testing.T) {
	var walk func(path []string, c *cli.Command)
	walk = func(path []string, c *cli.Command) {
		var out, diagnostic bytes.Buffer
		if code := run(append(path, "--help"), &out, &diagnostic); code != 0 || out.Len() == 0 {
			t.Errorf("sfcli %s --help: exit %d %s", strings.Join(path, " "), code, diagnostic.String())
		}
		for _, sub := range c.Sub {
			walk(append(slices.Clone(path), sub.Name), sub)
		}
	}
	for _, name := range []string{"secret"} {
		walk([]string{name}, newRoot(&globals{}).Find(name))
	}
}

func TestRealSecretManagementCLIOriginalWritesAndRecovery(t *testing.T) {
	testRealComposeGroups(t, false, true)
}

type secretManagementFixture struct {
	ctx     context.Context
	home    string
	call    func(int, ...string) []byte
	cmd     func(want int, stdin string, args ...string) []byte
	login   func()
	client  func() (*userauth.Client, userauth.Stored)
	current func() control.Vault
	read    func() state.State
	restart func()
	vault   *vaultfixture.Vault
	peer    sfcp.Peer
	puts    *atomic.Int32
	lose    *atomic.Bool
	issuer  func() ed25519.PrivateKey
}

func testSecretManagementCLI(t *testing.T, f secretManagementFixture) {
	secret := func(want int, stdin string, args ...string) []byte {
		t.Helper()
		return f.cmd(want, stdin, append([]string{"secret"}, args...)...)
	}
	file := func(value []byte) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "value")
		if err := os.WriteFile(path, value, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	// Before init there is no tree: the CLI says so (1), not a revision conflict (3).
	secret(1, "", "profile", "set", "values", "--node", "node-a", "--values", "--all")
	secret(0, "", "init", "cluster-root", "--all")
	secret(0, "", "group", "create", "cli-group", "--parent", "root", "--tenant", "tenant")
	// Reorder sends one moved entry: to the front, then back after another.
	secret(0, "", "group", "create", "cli-order", "--parent", "root", "--tenant", "tenant")
	order := func() []string {
		t.Helper()
		var root secrets.Object
		if err := json.Unmarshal(secret(0, "", "show", "root", "--tenant", "tenant", "-o", "json"), &root); err != nil {
			t.Fatal("show root", err)
		}
		return root.Entries
	}
	ordered := order()
	secret(0, "", "group", "reorder", "root", "cli-order", "--tenant", "tenant")
	if got := order(); got[0] != "cli-order" || len(got) != len(ordered) {
		t.Fatal("reorder to the front", ordered, got)
	}
	secret(3, "", "group", "reorder", "root", "cli-order", "--tenant", "tenant")
	secret(2, "", "group", "reorder", "root", "cli-order", "--after", "cli-order", "--tenant", "tenant")
	secret(0, "", "group", "reorder", "root", "cli-order", "--after", "cli-group", "--tenant", "tenant")
	if got := order(); slices.Index(got, "cli-order") != slices.Index(got, "cli-group")+1 {
		t.Fatal("reorder after", got)
	}
	create := []string{"create", "cli-data", "--tenant", "tenant", "--parent", "cli-group", "--profile", "values", "--object", "tenant/cli-data", "--key", "binary", "--key", "key", "--id", "cli-object"}
	secret(0, "", create...)
	secret(0, "", create...) // the same ID continues the same change
	if list := string(secret(0, "", "list", "--tenant", "tenant")); !strings.Contains(list, "cli-data") || !strings.Contains(list, "binary,key") {
		t.Fatal("list", list)
	}
	var shown secrets.Object
	if err := json.Unmarshal(secret(0, "", "show", "cli-data", "--tenant", "tenant", "-o", "json"), &shown); err != nil || shown.Parent != "cli-group" || shown.Reference.Object != "tenant/cli-data" {
		t.Fatal("show", shown, err)
	}
	c, stored := f.client()
	before := f.read().Object(control.VaultKey).Revision
	plan, err := c.PlanVaultWrite(f.ctx, f.peer, stored.Session, control.VaultWritePlanRequest{Realm: "tenant", ID: "first-cli", Object: "cli-data", Kind: secrets.ValueWrite})
	if err != nil || plan.Receiver == nil || plan.Request.ProviderObject != "tenant/cli-data" || plan.Request.Epoch != 1 || plan.Request.ExpectedProviderRevision != 0 || f.read().Object(control.VaultKey).Revision != before {
		t.Fatal("read-only exact current write plan", err)
	}
	limited := stored.Session
	limited.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read}}}
	limited.Signature = ed25519.Sign(f.issuer(), access.SessionBytes(limited))
	if _, err = c.PlanVaultWrite(f.ctx, f.peer, limited, control.VaultWritePlanRequest{Realm: "tenant", ID: "first-cli", Object: "cli-data", Kind: secrets.ValueWrite}); err == nil {
		t.Fatal("Read scope acquired secret write metadata")
	}
	if _, err = c.PlanVaultWrite(f.ctx, f.peer, limited, control.VaultWritePlanRequest{ID: "cluster-query"}); err == nil {
		t.Fatal("tenant scope acquired cluster Vault")
	}
	private := []byte("private-cli-original-value")
	binary := []byte{'a', 0, '\n', 'b'}
	// Dry run and a missing value send nothing.
	secret(0, "", "put", "cli-data", "--tenant", "tenant", "--file", "binary="+file(binary), "--file", "key="+file(private), "--id", "first-cli", "--dry-run")
	secret(2, "", "put", "cli-data", "--tenant", "tenant", "--id", "first-cli")
	if _, found := f.current().Trees["tenant"].Write("first-cli"); found || f.puts.Load() != 0 {
		t.Fatal("dry run or missing value sent a write")
	}
	secret(0, "", "put", "cli-data", "--tenant", "tenant", "--file", "binary="+file(binary), "--file", "key="+file(private), "--id", "first-cli")
	if f.puts.Load() != 1 {
		t.Fatal("expected exactly one provider PUT")
	}
	// The same ID again continues the finished write and reads no value.
	secret(0, "", "put", "cli-data", "--tenant", "tenant", "--file", "binary=/nonexistent", "--file", "key=/nonexistent", "--id", "first-cli")
	f.cmd(0, "", "op", "show", "first-cli")
	if writes := string(secret(0, "", "write", "list", "--tenant", "tenant")); !strings.Contains(writes, "first-cli") || !strings.Contains(writes, "Published") {
		t.Fatal("write list", writes)
	}
	provider, err := secrets.NewVault(secrets.VaultProfile{ID: "values", Address: f.vault.Address, Mount: "kv", Prefix: "tenant", Token: f.vault.Admin, Roots: f.vault.Roots, Timeout: 2 * time.Second, MaxBytes: 64 << 10})
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	checkValue := func(want []byte) {
		t.Helper()
		object, _ := f.current().Trees["tenant"].Object("cli-data")
		got, e := provider.Fetch(f.ctx, "cli-data", object.Reference)
		if e != nil || !bytes.Equal(got.Values["key"], want) || !bytes.Equal(got.Values["binary"], binary) {
			t.Fatal("actual stored bytes", e)
		}
		for _, v := range got.Values {
			clear(v)
		}
	}
	checkValue(private)
	// A one-key secret takes its value from standard input as raw bytes.
	secret(0, "", "create", "cli-one", "--tenant", "tenant", "--parent", "cli-group", "--profile", "values", "--object", "tenant/cli-one", "--key", "key")
	secret(2, "", "put", "cli-data", "--tenant", "tenant", "--id", "stdin-two") // two keys, one input
	secret(0, string(binary), "put", "cli-one", "--tenant", "tenant", "--id", "stdin-cli")
	if f.puts.Load() != 2 {
		t.Fatal("standard input write")
	}
	one, _ := f.current().Trees["tenant"].Object("cli-one")
	if got, e := provider.Fetch(f.ctx, "cli-one", one.Reference); e != nil || !bytes.Equal(got.Values["key"], binary) {
		t.Fatal("standard input bytes", e)
	}
	secret(0, "", "revoke", "cli-one", "--tenant", "tenant")
	secret(0, "", "retire", "cli-one", "--tenant", "tenant")
	password := []byte("private-cli-group-password")
	secret(0, string(password)+"\n", "group", "password", "cli-group", "--tenant", "tenant", "--profile", "auth", "--id", "password-one")
	first, _ := f.current().Trees["tenant"].Verifier("cli-group")
	secret(0, "", "group", "password", "cli-group", "--tenant", "tenant", "--password-file", file(password), "--id", "password-two")
	second, e := f.current().Trees["tenant"].Verifier("cli-group")
	if e != nil || first.Reference.Revision != 1 || second.Reference.Revision != 2 || first.Receipt == second.Receipt {
		t.Fatal("Group verifier rotation did not use original provider CAS", e)
	}
	auth, e := secrets.NewVault(secrets.VaultProfile{ID: "auth", Address: f.vault.Address, Mount: "kv", Prefix: "groups/tenant", Token: f.vault.Admin, Roots: f.vault.Roots, Timeout: 2 * time.Second, MaxBytes: 64 << 10})
	if e != nil {
		t.Fatal(e)
	}
	defer auth.Close()
	fetched, e := auth.FetchVerifier(f.ctx, "cli-group", second)
	if e != nil {
		t.Fatal(e)
	}
	hash, e := identity.RestorePasswordVerifier(fetched.Values["verifier"])
	if e != nil || !hash.Verify(password) || hash.Verify([]byte("wrong")) {
		t.Fatal("actual Group password verifier", e)
	}
	for _, v := range fetched.Values {
		clear(v)
	}
	if f.puts.Load() != 4 {
		t.Fatal("password writes were duplicated")
	}
	// A lost reply after the value reached the node: the outcome is unknown
	// (exit 4) and the value is never sent again.
	updated := []byte("private-cli-after-lost-response")
	f.lose.Store(true)
	secret(4, "", "put", "cli-data", "--tenant", "tenant", "--file", "binary="+file(binary), "--file", "key="+file(updated), "--id", "unknown-cli")
	old, _ := f.current().Trees["tenant"].Write("unknown-cli")
	if old.Status() != "Unknown" || f.puts.Load() != 5 {
		t.Fatal("lost successful PUT not retained", old.Status())
	}
	i, e := userauth.LoadSecretWrite(f.home, *c, stored.Session, "tenant", "unknown-cli")
	if e != nil || !i.Attempted || i.Pending != nil || i.Sequence != 1 {
		t.Fatal("BEFORE-SEND/public Unknown fact", e)
	}
	f.cmd(0, "", "op", "show", "unknown-cli")
	f.restart()
	f.login()
	f.cmd(0, "", "op", "resume", "unknown-cli")
	recovered, _ := f.current().Trees["tenant"].Write("unknown-cli")
	if recovered.Status() != "Published" || !sameJSON(old.Request, recovered.Request) || old.Journal.LastID != recovered.Journal.LastID || recovered.Observation.ProviderRevision != 2 || f.puts.Load() != 5 {
		t.Fatal("same DB/original readback made another PUT", recovered.Status(), recovered.Observation)
	}
	checkValue(updated)
	// A crash after the local record but before the first send keeps the
	// original tree CAS; the same command with the same ID sends it.
	c, stored = f.client()
	plan, e = c.PlanVaultWrite(f.ctx, f.peer, stored.Session, control.VaultWritePlanRequest{Realm: "tenant", ID: "before-prepare", Object: "cli-data", Kind: secrets.ValueWrite, Keys: []string{"binary", "key"}})
	if e != nil {
		t.Fatal(e)
	}
	window, e := c.Whoami(f.ctx, f.peer, stored.Session)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = userauth.StageSecretWrite(f.home, *c, stored.Session, plan, max(1, window.ModuleEpoch), false); e != nil {
		t.Fatal(e)
	}
	if _, ok := f.current().Trees["tenant"].Write("before-prepare"); ok {
		t.Fatal("staging created metadata")
	}
	secret(0, "", "put", "cli-data", "--tenant", "tenant", "--file", "binary="+file(binary), "--file", "key="+file(private), "--id", "before-prepare")
	if f.puts.Load() != 6 {
		t.Fatal("pre-prepare original resume")
	}
	checkValue(private)
	secret(0, "", "revoke", "cli-data", "--tenant", "tenant")
	secret(0, "", "retire", "cli-data", "--tenant", "tenant")
	shared, _ := state.Encode(f.read())
	for _, v := range [][]byte{private, updated, password} {
		if bytes.Contains(shared, v) {
			t.Fatal("private input in shared FSM")
		}
	}
	err = filepath.WalkDir(filepath.Join(f.home, ".sfc"), func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			raw, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			for _, v := range [][]byte{private, updated, password} {
				if bytes.Contains(raw, v) {
					t.Fatal("private input retained in CLI state", path)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
