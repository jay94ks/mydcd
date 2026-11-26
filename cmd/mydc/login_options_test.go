// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cliprofile"
	"github.com/jay94ks/mydcd/internal/config"
)

func TestLoginOptionsSelectionAndMethodContracts(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		args                  []string
		account               accountOptions
		method                access.Method
		key, file, credential string
		enroll                bool
	}{
		{name: "named-private-key", args: []string{"login", "--user", "alice", "--method", "private-key", "--key", "laptop"}, method: access.PrivateKey, key: "laptop"},
		{name: "file-private-key", args: []string{"login", "--username", "alice", "--method", "private-key", "--key-file", "/missing/key.pem"}, method: access.PrivateKey, file: "/missing/key.pem"},
		{name: "global-user-and-profile-key", args: []string{"login", "--method", "private-key"}, account: accountOptions{User: "alice", Target: cliprofile.Selection{WalletKey: "profile-key"}}, method: access.PrivateKey, key: "profile-key"},
		{name: "explicit-key-overrides-profile", args: []string{"login", "--user", "alice", "--method", "private-key", "--key", "other"}, account: accountOptions{Target: cliprofile.Selection{WalletKey: "profile-key"}}, method: access.PrivateKey, key: "other"},
		{name: "matching-aliases", args: []string{"login", "--user", "alice", "--username", "alice", "--method", "password", "--credential", "password-one", "--password-stdin"}, account: accountOptions{User: "alice", Target: cliprofile.Selection{WalletKey: "unused"}}, method: access.Password, credential: "password-one"},
		{name: "token", args: []string{"login", "--user", "alice", "--method", "token", "--token-stdin", "--credential", "robot"}, method: access.Token, credential: "robot"},
		{name: "password-prompt", args: []string{"login", "--user", "alice", "--method", "password"}, method: access.Password},
		{name: "enroll-explicit-key", args: []string{"enroll-admin", "--user", "alice", "--key", "laptop", "--user-id", "alice-id", "--request-id", "original"}, key: "laptop", enroll: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := tc.account
			got, err := parseLoginOptions(tc.args, tc.account, io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			if got.username != "alice" || got.method != tc.method || got.keyName != tc.key || got.keyFile != tc.file || got.credentialID != tc.credential {
				t.Fatalf("unexpected selection: %+v", got)
			}
			if tc.enroll && (got.userID != "alice-id" || got.requestID != "original") {
				t.Fatal("enrollment identity changed")
			}
			if !reflect.DeepEqual(before, tc.account) {
				t.Fatal("parser mutated caller account")
			}
		})
	}
}

func TestLoginOptionsRejectBeforeWalletFilesOrDescriptors(t *testing.T) {
	cases := [][]string{
		{"login"},
		{"login", "--user", "alice", "--method", "unsupported"},
		{"login", "--user", "alice", "--username", "bob", "--method", "password"},
		{"login", "--user", "bob", "--method", "password"},
		{"login", "--user", "alice", "--method", "private-key"},
		{"login", "--user", "alice", "--method", "private-key", "--key", "a", "--key-file", "/missing/key"},
		{"login", "--user", "alice", "--method", "private-key", "--key", "a", "--credential", "key"},
		{"login", "--user", "alice", "--method", "private-key", "--key", "a", "--password-stdin"},
		{"login", "--user", "alice", "--method", "password", "--key-file", "/missing/key"},
		{"login", "--user", "alice", "--method", "password", "--token-stdin"},
		{"login", "--user", "alice", "--method", "token", "--password-stdin"},
		{"login", "--user", "alice", "--method", "token", "--key", "key"},
		{"login", "--user", "alice", "--user", "alice", "--method", "password"},
		{"login", "--user", "alice", "--method", "password", "--method", "password"},
		{"login", "--user", "alice", "--method", "password", "extra"},
		{"login", "--user", "bad\nname", "--method", "password"},
		{"login", "--user", "alice", "--method", "private-key", "--key", "../escape"},
		{"login", "--user", "alice", "--method", "password", "--unknown"},
		{"enroll-admin", "--user", "alice", "--key", "key", "--user-id", "id"},
		{"enroll-admin", "--user", "alice", "--key", "key", "--request-id", "original"},
		{"enroll-admin", "--user", "alice", "--user-id", "id", "--request-id", "original"},
		{"enroll-admin", "--user", "alice", "--key", "key", "--user-id", "id", "--request-id", "original", "--method", "private-key"},
	}
	for i, args := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			home := t.TempDir()
			inputPath := filepath.Join(t.TempDir(), "protected-input")
			if err := os.WriteFile(inputPath, []byte("not-consumed"), 0600); err != nil {
				t.Fatal(err)
			}
			f, err := os.Open(inputPath)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			account := accountOptions{User: "alice", NoInput: true}
			if err = account.Password.Set(fmt.Sprint(f.Fd())); err != nil {
				t.Fatal(err)
			}
			before := account
			if _, err = parseLoginOptions(args, account, io.Discard); err == nil {
				t.Fatal("invalid syntax accepted")
			}
			var out, diag bytes.Buffer
			if code := runUserWithAccount(args, config.Client{}, home, "", time.Second, account, &out, &diag); code != 2 {
				t.Fatalf("code=%d: %s", code, diag.String())
			}
			if offset, err := f.Seek(0, io.SeekCurrent); err != nil || offset != 0 {
				t.Fatal("credential input consumed", offset, err)
			}
			entries, err := os.ReadDir(home)
			if err != nil || len(entries) != 0 {
				t.Fatal("wallet/profile state created", entries, err)
			}
			if out.Len() != 0 || !reflect.DeepEqual(account, before) {
				t.Fatal("invalid login changed output/account")
			}
		})
	}
}

func TestLoginOptionsAccountFlagsRemainOwned(t *testing.T) {
	account := accountOptions{User: "alice"}
	got, err := parseLoginOptions([]string{"login", "--method", "password", "--wallet-password-fd", "9", "--no-input"}, account, io.Discard)
	if err != nil || !got.account.NoInput || got.account.Password.String() != "9" || account.NoInput || account.Password.set {
		t.Fatal(got, err)
	}
	account = got.account
	if _, err = parseLoginOptions([]string{"login", "--method", "password", "--wallet-password-fd", "10"}, account, io.Discard); !errors.Is(err, errLoginFlags) {
		t.Fatal("duplicate global/subcommand wallet descriptor accepted", err)
	}
	if _, err = parseLoginOptions([]string{"enroll-admin", "--user", "alice", "--user-id", "id", "--request-id", "original"}, accountOptions{Target: cliprofile.Selection{WalletKey: "not-enrollment-default"}}, io.Discard); err == nil {
		t.Fatal("enrollment borrowed login profile key")
	}
}

func TestLoginApprovalKeyRequiresExplicitPasswordOrTokenSelection(t *testing.T) {
	for _, method := range []string{"password", "token"} {
		got, err := parseLoginOptions([]string{"login", "--user", "alice", "--method", method, "--approval-key", "user-laptop"}, accountOptions{Target: cliprofile.Selection{WalletKey: "other-profile-key"}}, io.Discard)
		if err != nil || got.approvalKey != "user-laptop" || got.keyName != "" {
			t.Fatal("explicit approval changed authentication selection", got, err)
		}
		got, err = parseLoginOptions([]string{"login", "--user", "alice", "--method", method}, accountOptions{Target: cliprofile.Selection{WalletKey: "not-an-approval-default"}}, io.Discard)
		if err != nil || got.approvalKey != "" {
			t.Fatal("approval key was implicitly selected", got, err)
		}
	}
	for _, args := range [][]string{
		{"login", "--user", "alice", "--method", "private-key", "--key", "key", "--approval-key", "other"},
		{"login", "--user", "alice", "--method", "password", "--approval-key", ""},
		{"login", "--user", "alice", "--method", "password", "--approval-key", "../escape"},
		{"login", "--user", "alice", "--method", "password", "--approval-key", "a", "--approval-key", "b"},
		{"enroll-admin", "--user", "alice", "--user-id", "id", "--request-id", "original", "--key", "a", "--approval-key", "b"},
	} {
		if _, err := parseLoginOptions(args, accountOptions{}, io.Discard); err == nil {
			t.Fatal("invalid approval selection accepted", args)
		}
	}
}
