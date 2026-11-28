// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/wallet"
)

// Uses the original native Vault/managed cluster. No process here compiles or
// installs the CLI; every file, credential FD and child belongs to this test.
func verifyInitialCredentialCLI(t *testing.T, ctx context.Context, root string, c Client, peer sfcp.Peer, adminSession access.Session, admin *identity.Identity) {
	t.Helper()
	home := filepath.Join(root, "initial-cli-home")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	walletPassword := []byte("rq4-private-native-cli-wallet")
	defer clear(walletPassword)
	disk, err := wallet.OpenDisk(home, true)
	if err != nil {
		t.Fatal(err)
	}
	err = disk.Init(walletPassword)
	closeErr := disk.Close()
	if err != nil || closeErr != nil {
		t.Fatal("owned wallet init", err, closeErr)
	}
	store, err := OpenCredentials(home, walletPassword)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.LoginPrivate(ctx, c, peer, "admin", admin.Private)
	closeErr = store.Close()
	if err != nil || closeErr != nil {
		t.Fatal("real admin wallet login", err, closeErr)
	}
	profile := filepath.Join(root, "initial-cli.yaml")
	configuration := fmt.Sprintf("version: 1\nauth: user\ncluster: '%x'\npeers:\n - {id: %s, key: '%x', endpoint: '%s', voter: true}\n", c.Cluster, peer.ID, peer.Key, peer.Endpoint)
	if err = os.WriteFile(profile, []byte(configuration), 0600); err != nil {
		t.Fatal(err)
	}
	pipe := func(value []byte) *os.File {
		t.Helper()
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write(value); err != nil {
			_ = r.Close()
			_ = w.Close()
			t.Fatal("owned protected input")
		}
		_ = w.Close()
		return r
	}
	call := func(username string, args []string, privateFiles []*os.File, stdin []byte) ([]byte, error) {
		t.Helper()
		password := pipe(walletPassword)
		defer password.Close()
		extra := append(append([]*os.File(nil), privateFiles...), password)
		flags := []string{"--config", profile, "--user", username, "--wallet-password-fd", fmt.Sprint(3 + len(privateFiles)), "--no-input"}
		command := exec.CommandContext(ctx, os.Getenv("SFC_TEST_CLI"), append(flags, args...)...)
		command.Env = append(os.Environ(), "HOME="+home)
		command.ExtraFiles = extra
		command.Stdin = bytes.NewReader(stdin)
		var output, diagnostic bytes.Buffer
		command.Stdout, command.Stderr = &output, &diagnostic
		err := command.Run()
		if err != nil {
			// Diagnose only fixed public error categories, never raw provider,
			// credential, stdout or stderr bytes from a protected-input call.
			for _, category := range []string{ErrPrivateState.Error(), wallet.ErrWallet.Error(), wallet.ErrPending.Error(), wallet.ErrMissing.Error(), identity.ErrCredential.Error(), sfcp.ErrAdmission.Error(), sfcp.ErrFrame.Error(), sfcp.ErrBudget.Error(), sfcp.ErrTruncated.Error(), "user request: denied", "user request: unavailable", "user request: invalid", "context deadline exceeded", "connection refused"} {
				if bytes.Contains(diagnostic.Bytes(), []byte(category)) {
					t.Log("CLI failure category:", category)
				}
			}
			if len(stdin) > 0 {
				// Login stderr has public transport/validation errors. Redact
				// every protected value this child received before recording it.
				public := bytes.Clone(diagnostic.Bytes())
				for _, secret := range [][]byte{walletPassword, stdin} {
					next := bytes.ReplaceAll(public, secret, []byte("<protected-input>"))
					clear(public)
					public = next
				}
				t.Log("protected-login failure:", string(public))
				clear(public)
			}
		}
		// Never copy private stdout/stderr into a failure message. Assertions
		// below inspect only public metadata or token absence.
		return output.Bytes(), err
	}
	create := func(id, username string) uint64 {
		t.Helper()
		raw, err := control.ChangeBytes("put-user", adminSession.User, 0, access.User{ID: id, Username: username, Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		var change control.Change
		if json.Unmarshal(raw, &change) != nil {
			t.Fatal("account intent")
		}
		op, err := c.Prepare(ctx, peer, adminSession, "cli-create-"+id, change)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = StageOperation(root, c, op); err != nil {
			t.Fatal(err)
		}
		reply, err := c.Operation(ctx, peer, op, false)
		if err != nil || reply.Result == nil || reply.Result.Code != state.Applied {
			t.Fatal("native initial account", err)
		}
		if err = RecordOperationResult(root, c, adminSession, op, *reply.Result); err != nil {
			t.Fatal(err)
		}
		detail, err := c.UserCredentials(ctx, peer, adminSession, username)
		if err != nil {
			t.Fatal(err)
		}
		return detail.Revision
	}
	password := []byte("rq4-cli-first-password-private")
	defer clear(password)
	revision := create("cli-user", "cli.user")
	arguments := []string{"manage", "user", "issue-initial", "cli.user", "--method", "password", "--credential", "first-password", "--credential-profile", "system", "--expected-revision", fmt.Sprint(revision), "--request-id", "cli-initial-password"}
	input := pipe(password)
	output, err := call("admin", append(append([]string(nil), arguments...), "--password-fd", "3"), []*os.File{input}, nil)
	_ = input.Close()
	if err != nil {
		t.Fatal("actual CLI initial password", err)
	}
	if bytes.Contains(output, password) {
		t.Fatal("password in CLI public response")
	}
	output, err = call("cli.user", []string{"login", "--username", "cli.user", "--method", "password", "--credential", "first-password", "--password-stdin"}, nil, password)
	if err != nil || bytes.Contains(output, password) {
		t.Fatal("actual CLI first password login", err)
	}
	if _, err = call("cli.user", []string{"manage", "self-credentials"}, nil, nil); err != nil {
		t.Fatal("new user's own credential query", err)
	}
	// Restore the exact retained public operation without reading a password.
	if _, err = call("admin", append(append([]string(nil), arguments...), "--resume-original"), nil, nil); err != nil {
		t.Fatal("original CLI credential result", err)
	}
	revision = create("cli-token", "cli.token")
	arguments = []string{"manage", "user", "issue-initial", "cli.token", "--method", "token", "--credential", "first-token", "--credential-profile", "system", "--expected-revision", fmt.Sprint(revision), "--request-id", "cli-initial-token"}
	file, err := os.OpenFile(filepath.Join(root, "initial-token-private"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	output, err = call("admin", append(append([]string(nil), arguments...), "--token-output-fd", "3"), []*os.File{file}, nil)
	if err != nil {
		t.Fatal("actual CLI initial token", err)
	}
	raw := make([]byte, 44)
	n, err := file.ReadAt(raw, 0)
	if n != 43 {
		clear(raw)
		t.Fatal("protected token delivery length")
	}
	raw = raw[:n]
	defer clear(raw)
	if bytes.Contains(output, raw) {
		t.Fatal("token entered public CLI output")
	}
	output, err = call("cli.token", []string{"login", "--username", "cli.token", "--method", "token", "--credential", "first-token", "--token-stdin"}, nil, raw)
	if err != nil || bytes.Contains(output, raw) {
		t.Fatal("actual CLI first token login", err)
	}
	if _, err = call("cli.token", []string{"login", "--username", "cli.token", "--method", "token", "--credential", "first-token", "--token-stdin"}, nil, raw); err == nil {
		t.Fatal("CLI one-time token reused")
	}
	output, err = call("admin", append(append([]string(nil), arguments...), "--resume-original"), nil, nil)
	if err != nil || bytes.Contains(output, raw) {
		t.Fatal("public original result exposed/reissued token", err)
	}
}
