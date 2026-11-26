// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/userauth"
	"github.com/jay94ks/mydcd/internal/wallet"
)

// Existing CLI scenarios use the same real encrypted account store as the
// product. This does not create a latest-login default or a plaintext session.
// fixtureWalletPasswordPhrase is the password of every fixture wallet.
const fixtureWalletPasswordPhrase = "CLI boundary fixture wallet passphrase"

// fixtureWalletPasswordFile writes the fixture wallet password to a 0600
// file for MYDC_WALLET_PASSWORD_FILE, as scripts pass it to new commands.
func fixtureWalletPasswordFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wallet-password")
	if err := os.WriteFile(path, []byte(fixtureWalletPasswordPhrase+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func fixtureWallet(t *testing.T, home string) (func([]string, io.Writer, io.Writer) int, func(userauth.Client, string) (userauth.Stored, error)) {
	t.Helper()
	password := []byte(fixtureWalletPasswordPhrase)
	disk, err := wallet.OpenDisk(home, true)
	if err != nil {
		t.Fatal(err)
	}
	if err = disk.Init(password); err != nil {
		_ = disk.Close()
		t.Fatal(err)
	}
	if err = disk.Close(); err != nil {
		t.Fatal(err)
	}
	invoke := func(args []string, out, diagnostic io.Writer) int {
		t.Helper()
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		_, err = w.Write(password)
		_ = w.Close()
		if err != nil {
			t.Fatal(err)
		}
		prefix := []string{"--wallet-password-fd", fmt.Sprint(r.Fd()), "--no-input"}
		if len(args) >= 2 && args[0] == "wallet" {
			// Wallet options belong after its subcommand, unlike global
			// account options on login/manage commands.
			command := append([]string{}, args[:2]...)
			command = append(command, prefix...)
			command = append(command, args[2:]...)
			return run(command, out, diagnostic)
		}
		return run(append(prefix, args...), out, diagnostic)
	}
	load := func(client userauth.Client, username string) (userauth.Stored, error) {
		credentials, err := userauth.OpenCredentials(home, password)
		if err != nil {
			return userauth.Stored{}, err
		}
		defer credentials.Close()
		return credentials.Load(client, username)
	}
	return invoke, load
}

func fixtureStageLogout(t *testing.T, home, username string, client userauth.Client, op control.UserOperation) error {
	t.Helper()
	credentials, err := userauth.OpenCredentials(home, []byte("CLI boundary fixture wallet passphrase"))
	if err != nil {
		return err
	}
	defer credentials.Close()
	client.Credentials, client.Username = credentials, username
	return userauth.StageLogout(home, client, op)
}

func fixtureSaveSession(t *testing.T, home, username string, client userauth.Client, session access.Session) error {
	t.Helper()
	credentials, err := userauth.OpenCredentials(home, []byte("CLI boundary fixture wallet passphrase"))
	if err != nil {
		return err
	}
	defer credentials.Close()
	client.Credentials, client.Username = credentials, username
	return userauth.Save(home, client, session, "")
}
