// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cli"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/membership"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/nodestorage"
)

// newCLICluster is a single-node managed cluster with the system
// administrator "operator" logged in. It returns a runner for new-frame
// commands, which read the current context and MYDC_WALLET_PASSWORD_FILE.
func newCLICluster(t *testing.T, ctx context.Context) (*managedNode, func(want int, args ...string) (string, string)) {
	t.Helper()
	root, home := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	invoke, _ := fixtureWallet(t, home)
	admin, err := identity.Create(filepath.Join(root, "admin"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(admin.Private) })
	m := newManagedNode(t, ctx, root, "node-a", admin)
	m.EnrollAdmin(access.User{ID: "sys", Username: "operator", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: admin.Public, Enabled: true}}})
	m.SaveContext(home, "lab", "operator")
	profile := filepath.Join(root, "client.yaml")
	if err = os.WriteFile(profile, []byte(m.ClientProfile()), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, diagnostic bytes.Buffer
	if code := invoke([]string{"--config", profile, "login", "--username", "operator", "--method", "private-key", "--key-file", filepath.Join(root, "admin", "key.pem")}, &out, &diagnostic); code != 0 {
		t.Fatal("login", code, diagnostic.String())
	}
	t.Setenv("MYDC_WALLET_PASSWORD_FILE", fixtureWalletPasswordFile(t))
	t.Setenv("MYDC_NONINTERACTIVE", "1")
	return m, func(want int, args ...string) (string, string) {
		t.Helper()
		var out, diagnostic bytes.Buffer
		if code := run(args, &out, &diagnostic); code != want {
			t.Fatalf("mydc %v: code %d, want %d\nout: %s\nerr: %s", args, code, want, out.String(), diagnostic.String())
		}
		if strings.Contains(out.String()+diagnostic.String(), "PRIVATE KEY") {
			t.Fatal("private key printed")
		}
		return out.String(), diagnostic.String()
	}
}

func TestNodeAndClusterCommandsAgainstManagedCluster(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	m, mydc := newCLICluster(t, ctx)

	out, _ := mydc(0, "node", "list", "--all", "-o", "json")
	var dir nodeDirectory
	if err := json.Unmarshal([]byte(out), &dir); err != nil || len(dir.Members) != 1 || dir.Members[0].Peer.ID != "node-a" || !dir.Members[0].Peer.Voter {
		t.Fatal("node list", err, out)
	}
	if out, _ = mydc(0, "node", "list", "--all"); !strings.Contains(out, "NODE") || !strings.Contains(out, "node-a") || !strings.Contains(out, "open") {
		t.Fatal("node list table", out)
	}
	// With no tenant on the context, plain list is the cluster view.
	if out, _ = mydc(0, "node", "list"); !strings.Contains(out, "MEMBER") || !strings.Contains(out, "node-a") {
		t.Fatal("node list without a tenant", out)
	}
	if out, _ = mydc(0, "node", "show", "node-a", "-o", "json"); !strings.Contains(out, `"member"`) {
		t.Fatal("node show", out)
	}
	mydc(1, "node", "show", "node-z")

	// Cordon and uncordon read the scheduling revision themselves.
	mydc(2, "node", "cordon", "node-a", "two\nlines")
	mydc(0, "node", "cordon", "node-a", "disk swap", "--id", "cordon-a")
	if out, _ = mydc(0, "node", "list", "--all"); !strings.Contains(out, "cordoned: disk swap") {
		t.Fatal("cordon not shown", out)
	}
	if out, _ = mydc(0, "node", "show", "node-a", "-o", "json"); !strings.Contains(out, `"Reason": "disk swap"`) {
		t.Fatal("cordon reason not shown", out)
	}
	if out, _ = mydc(0, "node", "cordon", "node-a"); !strings.Contains(out, "already cordoned") {
		t.Fatal("second cordon", out)
	}
	mydc(0, "node", "uncordon", "node-a")
	// A stale --if-revision is refused by the server.
	mydc(1, "node", "cordon", "node-a", "--if-revision", "99")
	out, _ = mydc(0, "op", "show", "cordon-a", "-o", "json")
	var op cli.Op
	if err := json.Unmarshal([]byte(out), &op); err != nil || op.State != cli.Done || op.Kind != "change" || op.Summary != "node cordon node-a" {
		t.Fatal("cordon op", err, out)
	}

	// The last voter cannot be demoted or removed; nothing is sent.
	if _, errOut := mydc(3, "node", "remove", "node-a", "--dry-run"); !strings.Contains(errOut, "LAST_VOTER") {
		t.Fatal("remove blocker", errOut)
	}
	mydc(3, "node", "demote", "node-a", "-y")

	// Register a new server and export its invitation.
	joining, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(joining.Private)
	mydc(2, "node", "add", "node-b", "--endpoint", "127.0.0.1:7444", "--public-key", "nothex")
	mydc(0, "node", "add", "node-b", "--endpoint", "127.0.0.1:7444", "--public-key", joining.Actor(), "--id", "add-node-b")
	out, _ = mydc(0, "node", "invite", "node-b")
	if inv, err := membership.DecodeInvitation([]byte(out)); err != nil || inv.Target.ID != "node-b" || inv.JoinID != "add-node-b" {
		t.Fatal("invitation", err, out)
	}

	// Storage directories.
	if r := m.Change("create-shop", "create-tenant", 0, control.TenantID{ID: "shop"}); r.Code != state.Applied {
		t.Fatal("create tenant", r)
	}
	dirPath := t.TempDir()
	mydc(0, "node", "storage", "add", "node-a", "data", "--path", dirPath, "--tenants", "shop")
	out, _ = mydc(0, "node", "storage", "show", "node-a", "data", "-o", "json")
	var root nodestorage.Root
	if err := json.Unmarshal([]byte(out), &root); err != nil || root.Definition.Path != dirPath || len(root.Definition.Tenants) != 1 {
		t.Fatal("storage show", err, out)
	}
	mydc(0, "node", "storage", "set", "node-a", "data", "--no-tenants", "--max-volumes", "4")
	out, _ = mydc(0, "node", "storage", "list", "--all", "-o", "json")
	var list storageList
	if err := json.Unmarshal([]byte(out), &list); err != nil || len(list.Roots) != 1 || len(list.Roots[0].Definition.Tenants) != 0 || list.Roots[0].Definition.MaxVolumes != 4 {
		t.Fatal("storage set", err, out)
	}

	// Shell policy and cluster status are readable.
	if out, _ = mydc(0, "node", "shell", "policy"); !strings.Contains(out, "Shells:") {
		t.Fatal("shell policy", out)
	}
	if out, _ = mydc(0, "cluster", "status", "-o", "json"); !strings.Contains(out, `"Leader"`) {
		t.Fatal("cluster status", out)
	}
	if out, _ = mydc(0, "cluster", "cli-policy"); !strings.Contains(out, "allowed") {
		t.Fatal("cli policy", out)
	}

	// Events show the cordon. The node moves committed events into its event
	// log every two seconds, so the event may come a little after the change.
	for deadline := time.Now().Add(15 * time.Second); ; time.Sleep(500 * time.Millisecond) {
		if out, _ = mydc(0, "events", "--all", "--kind", "node-cordoned", "-o", "json"); strings.Contains(out, "node-cordoned") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("events", out)
		}
	}

	// The op list has every change sent from this computer.
	out, _ = mydc(0, "op", "list")
	for _, want := range []string{"node cordon node-a", "node add node-b", "node storage add node-a data"} {
		if !strings.Contains(out, want) {
			t.Fatal("op list misses", want, out)
		}
	}
}

func TestNodeCommandsCheckArgumentsBeforeLogin(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	for _, args := range [][]string{
		{"node", "show"}, {"node", "show", "Bad"}, {"node", "cordon", "a", "b", "c"}, {"node", "uncordon", "a", "b"},
		{"node", "add", "node-b", "--endpoint", "x", "--public-key", strings.Repeat("a", 64)},
		{"node", "images", "delete", "node-a"}, {"node", "images", "delete", "node-a", "sha256:short"},
		{"node", "storage", "add", "node-a", "data", "--path", "/"},
		{"node", "shell", "grant", "alice"}, {"node", "shell", "policy", "--shell", "on"},
		{"cluster", "reconnect", "node-a", "node-a"}, {"cluster", "compact", "--retain", "5"},
		{"cluster", "cli-policy", "maybe"},
		{"events", "--kind", "invented"}, {"events", "--all", "--app", "shop"},
	} {
		var out, diagnostic bytes.Buffer
		if code := run(args, &out, &diagnostic); code != 2 {
			t.Fatalf("mydc %v: code %d, want 2: %s", args, code, diagnostic.String())
		}
		if strings.Contains(diagnostic.String(), "Wallet password") {
			t.Fatal("asked for the wallet before checking arguments", args)
		}
	}
	for _, args := range [][]string{{"node", "--help"}, {"cluster", "--help"}, {"events", "--help"}, {"node", "storage", "--help"}, {"node", "shell", "--help"}} {
		var out, diagnostic bytes.Buffer
		if code := run(args, &out, &diagnostic); code != 0 || !strings.Contains(out.String(), "Usage: mydc") {
			t.Fatalf("mydc %v: code %d: %s %s", args, code, out.String(), diagnostic.String())
		}
	}
	// Leading new-frame globals still route to the new commands; an old-only
	// option keeps the line on the old code.
	if !newCommand([]string{"cluster", "status"}) || !newCommand([]string{"cluster"}) ||
		!newCommand([]string{"--tenant", "shop", "node", "list"}) || newCommand([]string{"--config", "x", "node", "list"}) {
		t.Fatal("cluster routing")
	}
}
