// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/userauth"
	"github.com/jay94ks/mydcd/internal/wallet"
)

// U0 final native CLI boundary. Rollback closes this one local runtime/client
// flow and removes only t.TempDir roots. Network/workload/Ingress are disabled;
// no Docker, system socket, routing/firewall or retained E4 state is touched.
func TestU0CLIWalletLoginCoexistingUsersAndExplicitSelection(t *testing.T) {
	root, home := t.TempDir(), t.TempDir()
	unixRoot, err := os.MkdirTemp("", "mydc-u0-cli-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(unixRoot); err != nil {
			t.Error(err)
		}
	})
	t.Setenv("HOME", home)
	key := func(name string) *identity.Identity {
		t.Helper()
		id, err := identity.Create(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { clear(id.Private) })
		return id
	}
	operator, alice := key("operator"), key("alice")
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	fixture := newManagedNode(t, ctx, root, "node", operator)
	address, cluster, node := fixture.Address, fixture.Cluster, fixture.Node()
	fixture.EnrollAdmin(access.User{ID: "sys", Username: "operator", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: operator.Public, Enabled: true}}})
	for id, item := range map[string]struct {
		action  string
		payload any
	}{
		"u0-account-alice":  {"put-user", access.User{ID: "alice", Username: "dev.alice", Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: alice.Public, Enabled: true}}}},
		"u0-profile-tenant": {"create-tenant", control.TenantID{ID: "actual-tenant"}},
	} {
		if result := fixture.Change(id, item.action, 0, item.payload); result.Code != state.Applied {
			t.Fatal(id, result)
		}
	}
	clientFile := filepath.Join(root, "client.yaml")
	clientText := fmt.Sprintf("version: 1\nauth: user\ncluster: '%x'\npeers:\n  - {id: node, key: '%s', endpoint: '%s', voter: true}\n", cluster, node.Actor(), address)
	if err := os.WriteFile(clientFile, []byte(clientText), 0600); err != nil {
		t.Fatal(err)
	}
	password := []byte("U0 native CLI wallet passphrase")
	disk, err := wallet.OpenDisk(home, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := disk.Init(password); err != nil {
		t.Fatal(err)
	}
	if err := disk.Close(); err != nil {
		t.Fatal(err)
	}
	// Retain one actual pre-wallet login. The first CLI read must migrate its
	// SAME signer and verify its username over the real pinned user handler.
	legacySelf, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(legacySelf.Private)
	peer := mydcp.Peer{ID: "node", Endpoint: address, Policy: mydcp.Policy{Key: mydcp.Identity(node.Public), Respond: true}}
	legacy := userauth.Client{Cluster: cluster, Self: legacySelf, Peers: []mydcp.Peer{peer}}
	legacy.Mesh, err = mydcp.NewTransport(legacySelf, cluster, func(key mydcp.Identity) (mydcp.Peer, bool) { return peer, key == peer.Key })
	if err != nil {
		t.Fatal(err)
	}
	originalSession, loginErr := legacy.Login(ctx, peer, "operator", operator.Private)
	closeErr := legacy.Mesh.Close()
	if loginErr != nil || closeErr != nil {
		t.Fatal(loginErr, closeErr)
	}
	if err := userauth.Save(home, legacy, originalSession, ""); err != nil {
		t.Fatal(err)
	}
	passfile := filepath.Join(root, "protected-wallet-input")
	if err := os.WriteFile(passfile, password, 0600); err != nil {
		t.Fatal(err)
	}
	clientArgs := []string{"--config", clientFile}
	invoke := func(want int, username string, args ...string) (string, string) {
		t.Helper()
		input, err := os.Open(passfile)
		if err != nil {
			t.Fatal(err)
		}
		defer input.Close()
		prefix := append([]string{}, clientArgs...)
		prefix = append(prefix, "--wallet-password-fd", fmt.Sprint(input.Fd()), "--no-input")
		if username != "" {
			prefix = append(prefix, "--user", username)
		}
		var out, diagnostic bytes.Buffer
		if code := run(append(prefix, args...), &out, &diagnostic); code != want {
			t.Fatalf("%s %v code=%d want=%d: %s", username, args, code, want, diagnostic.String())
		}
		if bytes.Contains(out.Bytes(), password) || bytes.Contains(diagnostic.Bytes(), password) {
			t.Fatal("private wallet password output")
		}
		return out.String(), diagnostic.String()
	}
	if out, _ := invoke(0, "", "whoami"); !strings.Contains(out, "sys") {
		t.Fatal("sole original login was not imported through actual whoami", out)
	}
	invoke(0, "operator", "login", "--method", "private-key", "--key-file", filepath.Join(root, "operator", "key.pem"))
	if out, _ := invoke(0, "", "whoami"); !strings.Contains(out, "sys") {
		t.Fatal("single stored account was not selected", out)
	}
	var registered, registrationError bytes.Buffer
	if code := run([]string{"context", "add", "production", "mydcp://" + address, "--key", hex.EncodeToString(node.Public[:])}, &registered, &registrationError); code != 0 {
		t.Fatalf("actual public discovery/profile registration: %d %s", code, registrationError.String())
	}
	clientArgs = []string{"--cluster", "production"}
	if out, _ := invoke(0, "", "whoami"); !strings.Contains(out, "sys") {
		t.Fatal("profile registration replaced original account scope", out)
	}
	if code := run([]string{"context", "set", "production", "--tenant", "actual-tenant"}, &registered, &registrationError); code != 0 {
		t.Fatal(registrationError.String())
	}
	clientArgs = nil // Default cluster and tenant must resolve to the same IDs.
	invoke(2, "operator", "compose", "ps", "--tenant", "foreign")
	invoke(0, "dev.alice", "login", "--method", "private-key", "--key-file", filepath.Join(root, "alice", "key.pem"))
	if out, why := invoke(2, "", "whoami"); out != "" || !strings.Contains(why, "--user") || !strings.Contains(why, "operator") || !strings.Contains(why, "dev.alice") {
		t.Fatal("ambiguous login selected silently", out, why)
	}
	invoke(2, "missing", "whoami")
	invoke(2, "operator", "login", "--username", "dev.alice", "--method", "private-key", "--key-file", filepath.Join(root, "alice", "key.pem"))
	if out, _ := invoke(0, "operator", "whoami"); !strings.Contains(out, "sys") {
		t.Fatal("wrong explicit account", out)
	}
	if out, _ := invoke(0, "dev.alice", "whoami"); !strings.Contains(out, "alice") {
		t.Fatal("wrong explicit account", out)
	}
	invoke(0, "dev.alice", "logout")
	if out, _ := invoke(0, "", "whoami"); !strings.Contains(out, "sys") {
		t.Fatal("logout removed the other account", out)
	}
	metadataCount := 0
	if err := filepath.WalkDir(filepath.Join(home, ".mydc", "sessions"), func(name string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Name() != "session.json" {
			return nil
		}
		metadataCount++
		raw, err := os.ReadFile(name)
		defer clear(raw)
		if err != nil {
			return err
		}
		if bytes.Contains(raw, []byte(`"Seed"`)) {
			t.Fatal("original signer remained in plaintext")
		}
		return nil
	}); err != nil || metadataCount != 1 {
		t.Fatal("original reference changed or vanished", metadataCount, err)
	}
}
