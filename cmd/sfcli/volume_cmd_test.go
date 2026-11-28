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

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/workload"
)

// cliNode is a managed single-node cluster with a logged-in CLI user, for
// running new-frame commands end to end: the current context is "lab" and
// the wallet password comes from SFC_WALLET_PASSWORD_FILE, as in a script.
type cliNode struct {
	*managedNode
	t    *testing.T
	root string
}

func newCLINode(t *testing.T, tenants ...string) *cliNode {
	t.Helper()
	root := t.TempDir()
	home := filepath.Join(root, "home")
	t.Setenv("HOME", home)
	admin, err := identity.Create(filepath.Join(root, "admin"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(admin.Private) })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	m := newManagedNode(t, ctx, root, "node", admin)
	m.EnrollAdmin(access.User{ID: "admin", Username: "admin", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: admin.Public, Enabled: true}}})
	quota := func(tenant string) {
		limit := tenancy.NodeLimit{Tenant: tenant, Node: "node", Capacity: workload.Resources{CPU: 2e9, Memory: 512 << 20}, Networks: 4, MaxConsumers: 8}
		if r := m.Change("quota-"+tenant, "set-node-quota", 0, limit); r.Code != state.Applied {
			t.Fatal("node quota", tenant, r)
		}
	}
	quota("")
	for _, tenant := range tenants {
		if r := m.Change("tenant-"+tenant, "create-tenant", 0, control.TenantID{ID: tenant}); r.Code != state.Applied {
			t.Fatal("create tenant", tenant, r)
		}
		record, _ := m.Catalog().Tenant(tenant)
		if r := m.Change("nodes-"+tenant, "set-nodes", record.Revision, control.NodeChangeTo(tenant, record.AllowedNodes, []string{"node"})); r.Code != state.Applied {
			t.Fatal("tenant nodes", tenant, r)
		}
		quota(tenant)
	}
	m.SaveContext(home, "lab", "admin")
	profile := filepath.Join(root, "client.yaml")
	if err = os.WriteFile(profile, []byte(m.ClientProfile()), 0o600); err != nil {
		t.Fatal(err)
	}
	invoke, _ := fixtureWallet(t, home)
	var out, diagnostic bytes.Buffer
	if code := invoke([]string{"--config", profile, "login", "--username", "admin", "--method", "private-key", "--key-file", filepath.Join(root, "admin", "key.pem")}, &out, &diagnostic); code != 0 {
		t.Fatal("login", code, diagnostic.String())
	}
	t.Setenv("SFC_WALLET_PASSWORD_FILE", fixtureWalletPasswordFile(t))
	return &cliNode{managedNode: m, t: t, root: root}
}

// run runs one sfcli command line and checks its exit code.
func (n *cliNode) run(want int, args ...string) string {
	n.t.Helper()
	var out, diagnostic bytes.Buffer
	if code := run(args, &out, &diagnostic); code != want {
		n.t.Fatalf("sfcli %s: exit %d, want %d\nstdout: %s\nstderr: %s", strings.Join(args, " "), code, want, out.String(), diagnostic.String())
	}
	return out.String()
}

func (n *cliNode) op(id string) cli.Op {
	n.t.Helper()
	x, err := openOps()
	if err != nil {
		n.t.Fatal(err)
	}
	defer x.Close()
	op, err := x.Get(id)
	if err != nil {
		n.t.Fatal(err)
	}
	return op
}

func (n *cliNode) ops() []cli.Op {
	n.t.Helper()
	x, err := openOps()
	if err != nil {
		n.t.Fatal(err)
	}
	defer x.Close()
	all, err := x.List()
	if err != nil {
		n.t.Fatal(err)
	}
	return all
}

func TestVolumeCommandLineErrorsBeforeLogin(t *testing.T) {
	// No profile, wallet or password: every case must fail on the command
	// line alone (exit 2), before anything asks for the wallet.
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SFC_WALLET_PASSWORD_FILE", "")
	for _, args := range [][]string{
		{"volume", "create", "data", "--node", "n", "--uid", "1", "--gid", "1"},
		{"volume", "create", "shop/data", "--node", "n", "--uid", "0", "--gid", "1"},
		{"volume", "create", "shop/data", "--node", "n", "--uid", "1", "--gid", "1", "--mode", "0777"},
		{"volume", "create", "shop/Data", "--node", "n", "--uid", "1", "--gid", "1"},
		{"volume", "show"},
		{"volume", "show", "../etc"},
		{"volume", "delete", "data"},
		{"volume", "delete", "shop/data", "--retained", "Bad"},
		{"volume", "register", "shop/data", "--node", "n", "--storage", "s", "--root-generation", "1", "--path", "/srv/x"},
		{"volume", "register", "data", "--node", "n", "--storage", "s", "--root-generation", "1", "--path", "relative"},
		{"volume", "unregister", "shop/data"},
		{"volume", "backup", "create", "shop/data"},
		{"volume", "backup", "create", "shop/data", "--max-size", "1"},
		{"volume", "backup", "create", "shop/data", "--max-size", "1GiB", "--name", "Nightly"},
		{"volume", "restore", "shop/data", "b1", "--max-size", "1GiB"},
		{"volume", "restore", "shop/data", "b1", "--to", "shop/new", "--max-size", "2GiB", "--size", "1GiB"},
		{"volume", "move", "shop/data", "-f", "app.yaml"},
		{"volume", "move", "--plan", "plan.json", "shop/data"},
		{"volume", "move", "shop/data", "-f", "app.yaml", "--max-size", "1GiB", "--save-plan", "p.json"},
		{"volume", "files", "ls", "shop/data", "../up/"},
		{"volume", "files", "get", "shop/data", "a.txt", "out"},
		{"volume", "files", "put", "shop/data", "/nonexistent/file", "a.txt"},
		{"volume", "files", "rm", "shop/data", "/abs"},
		{"volume", "files", "grant", "shop/data", "dir", "bob"},
		{"volume", "resize", "shop/data"},
		{"volume", "resize", "shop/data", "--size", "2TiB"},
		{"volume", "backup", "limits", "set", "--max-size", "1GiB"},
		{"volume", "backup", "limits", "set", "--node", "n", "--max-backups", "300"},
		{"volume", "archive", "shop/data", "--name", "Bad"},
		{"volume", "archive", "shop/data", "--max-size", "1"},
		{"volume", "archive", "shop/data", "--store", "Bad"},
		{"volume", "archive", "data"},
		{"volume", "archive", "admin-key", "extra"},
		{"volume", "archive", "show"},
		{"volume", "unarchive"},
		{"volume", "unarchive", "shop/data", "a", "b"},
		{"app", "archive"},
		{"app", "archive", "shop", "--name", "Bad"},
		{"volume", "nope"},
	} {
		var out, diagnostic bytes.Buffer
		code := run(args, &out, &diagnostic)
		if code != 2 && !(code == 1 && len(args) > 2 && args[2] == "put") {
			t.Errorf("sfcli %s: exit %d, want 2: %s", strings.Join(args, " "), code, diagnostic.String())
		}
		if strings.Contains(diagnostic.String(), "allet") {
			t.Errorf("sfcli %s asked for the wallet: %s", strings.Join(args, " "), diagnostic.String())
		}
	}
}

func TestVolumeHelpListsGroup(t *testing.T) {
	var out, diagnostic bytes.Buffer
	if code := run([]string{"volume", "--help"}, &out, &diagnostic); code != 0 {
		t.Fatal(code, diagnostic.String())
	}
	for _, word := range []string{"list", "create", "delete", "register", "backup", "restore", "move", "archive", "unarchive", "files"} {
		if !strings.Contains(out.String(), "\n  "+word) {
			t.Errorf("volume help lacks %s:\n%s", word, out.String())
		}
	}
	out.Reset()
	if code := run([]string{"volume", "backup", "--help"}, &out, &diagnostic); code != 0 || !strings.Contains(out.String(), "limits") {
		t.Fatal(code, out.String())
	}
}

func TestVolumeCommandsAgainstManagedNode(t *testing.T) {
	n := newCLINode(t, "shop")
	if got := strings.TrimSpace(n.run(0, "volume", "list", "--tenant", "shop", "-o", "json")); got != "[]" {
		t.Fatalf("empty list: %s", got)
	}
	n.run(0, "volume", "list", "--all", "-o", "json")
	n.run(0, "volume", "backup", "list", "--tenant", "shop", "-o", "json")
	n.run(0, "volume", "restore", "list", "--tenant", "shop", "-o", "json")
	n.run(0, "volume", "backup", "limits", "--tenant", "shop", "-o", "json")
	n.run(0, "volume", "files", "grants", "--tenant", "shop", "-o", "json")
	n.run(1, "volume", "show", "shop/data", "--tenant", "shop")

	// Dry run and a missing confirmation send nothing and record nothing.
	create := []string{"volume", "create", "shop/data", "--tenant", "shop", "--node", "node", "--uid", "10001", "--gid", "10001"}
	n.run(0, append(create, "--dry-run")...)
	n.run(1, create...)
	if ops := n.ops(); len(ops) != 0 {
		t.Fatalf("recorded without sending: %+v", ops)
	}

	// The change is recorded under its ID before it is sent; the server
	// accepts it and the volume appears in the catalog.
	n.run(0, append(create, "-y", "--no-wait", "--id", "create-data")...)
	op := n.op("create-data")
	if op.Kind != "volume" || op.Tenant != "shop" || op.Summary != "volume create shop/data" || op.State == cli.Failed || op.State == cli.Sending {
		t.Fatalf("op after create: %+v", op)
	}
	var shown control.VolumeView
	if err := json.Unmarshal([]byte(n.run(0, "volume", "show", "shop/data", "--tenant", "shop", "-o", "json")), &shown); err != nil || shown.Scope.App != "shop" || shown.Scope.ID != "data" || shown.Owner.Node != "node" {
		t.Fatalf("shown %+v %v", shown, err)
	}
	var list []control.VolumeView
	if err := json.Unmarshal([]byte(n.run(0, "volume", "list", "--tenant", "shop", "-o", "json")), &list); err != nil || len(list) != 1 {
		t.Fatalf("list %+v %v", list, err)
	}
	if table := n.run(0, "volume", "list", "--tenant", "shop"); !strings.Contains(table, "shop/data") || !strings.Contains(table, "NODE") {
		t.Fatalf("table:\n%s", table)
	}

	// Running the same command with the same ID continues that operation;
	// the ID cannot be reused for another change.
	n.run(0, append(create, "-y", "--no-wait", "--id", "create-data")...)
	n.run(1, "volume", "create", "shop/other", "--tenant", "shop", "--node", "node", "--uid", "10001", "--gid", "10001", "-y", "--no-wait", "--id", "create-data")

	// op show asks the server again with the same ID.
	var settled cli.Op
	if err := json.Unmarshal([]byte(n.run(0, "op", "show", "create-data", "-o", "json")), &settled); err != nil || settled.ID != "create-data" || settled.State == cli.Failed {
		t.Fatalf("op show %+v %v", settled, err)
	}

	// A second create of the same volume is refused by the server (exit 3)
	// and the op records the rejection.
	n.run(3, append(create, "-y", "--no-wait", "--id", "create-again")...)
	if op := n.op("create-again"); op.State != cli.Failed || op.Detail == "" {
		t.Fatalf("rejected op: %+v", op)
	}

	// Backups of a volume that is not ready are refused before sending.
	n.run(1, "volume", "backup", "create", "shop/missing", "--tenant", "shop", "--max-size", "1MiB", "-y")
	n.run(1, "volume", "backup", "show", "shop/data", "none", "--tenant", "shop")

	// Backup space limits: set for the tenant, shown back, then changed in
	// place with only one option (the rest keep their values).
	n.run(0, "volume", "backup", "limits", "set", "--tenant", "shop", "--node", "node", "--max-size", "1GiB", "--max-backups", "4", "--staging-size", "512MiB", "--staging-backups", "2", "-y", "--id", "limit-1")
	n.run(0, "volume", "backup", "limits", "set", "--tenant", "shop", "--node", "node", "--max-backups", "5", "-y", "--id", "limit-2")
	var limits []control.PublicBackupLimit
	if err := json.Unmarshal([]byte(n.run(0, "volume", "backup", "limits", "--tenant", "shop", "-o", "json")), &limits); err != nil || len(limits) != 1 || limits[0].Bytes != 1<<30 || limits[0].Count != 5 || limits[0].StagingCount != 2 {
		t.Fatalf("limits %+v %v", limits, err)
	}
	if op := n.op("limit-2"); op.State != cli.Done || op.Summary != "volume backup limits set --node node --tenant shop" {
		t.Fatalf("limit op %+v", op)
	}
	n.run(2, "volume", "backup", "limits", "set", "--tenant", "shop", "--max-size", "1GiB")
	n.run(2, "volume", "resize", "shop/data", "--tenant", "shop")

	// Archives: an empty list, then the administrator's key from a key
	// file. Only its public half is sent and shown.
	if got := strings.TrimSpace(n.run(0, "volume", "archive", "list", "--tenant", "shop", "-o", "json")); got != "[]" {
		t.Fatalf("empty archive list: %s", got)
	}
	keyFile := filepath.Join(n.root, "archive.key")
	n.run(0, "cluster", "backup", "keygen", "--out", keyFile)
	n.run(0, "volume", "archive", "admin-key", "--key-file", keyFile, "-y", "--id", "archive-key")
	var keys archiveKeysView
	if err := json.Unmarshal([]byte(n.run(0, "volume", "archive", "admin-key", "-o", "json")), &keys); err != nil || len(keys.Admin) != 64 || keys.Revision != 1 {
		t.Fatalf("archive keys %+v %v", keys, err)
	}
	if raw, _ := os.ReadFile(keyFile); strings.Contains(keys.Admin, strings.TrimSpace(string(raw))) {
		t.Fatal("the key file's secret was sent")
	}
	n.run(0, "volume", "archive", "admin-key", "--key-file", keyFile, "-y", "--id", "archive-key-again") // already set: nothing sent
	n.run(1, "volume", "unarchive", "shop/data", "--tenant", "shop", "-y")                               // no archive
	n.run(1, "app", "archive", "none", "--tenant", "shop", "-y")                                         // no volume

	// Delete cancels a pending creation or deletes the volume.
	n.run(0, "volume", "delete", "shop/data", "--tenant", "shop", "-y", "--no-wait", "--id", "delete-data")
	if op := n.op("delete-data"); op.Kind != "volume" || op.State == cli.Failed {
		t.Fatalf("delete op %+v", op)
	}
}

func TestVolumeHelpEveryCommand(t *testing.T) {
	// A subcommand inherits its parents' options; registering one twice
	// panics, so every command's help is built once here.
	var walk func(path []string, c *cli.Command)
	walk = func(path []string, c *cli.Command) {
		var out, diagnostic bytes.Buffer
		if code := run(append(path, "--help"), &out, &diagnostic); code != 0 || out.Len() == 0 {
			t.Errorf("sfcli %s --help: exit %d %s", strings.Join(path, " "), code, diagnostic.String())
		}
		for _, sub := range c.Sub {
			walk(append(append([]string{}, path...), sub.Name), sub)
		}
	}
	walk([]string{"volume"}, newRoot(&globals{}).Find("volume"))
}

// Once a server has volume budgets, create needs --size, and a --size needs
// both the tenant and the cluster budget. The CLI says so before sending
// instead of the server's bare "revision differs".
func TestVolumeCreateFollowsVolumeBudgets(t *testing.T) {
	n := newCLINode(t, "shop")
	base := []string{"volume", "create", "shop/a", "--tenant", "shop", "--node", "node", "--uid", "10001", "--gid", "10001", "-y", "--no-wait"}
	sized := append(append([]string{}, base...), "--size", "256MiB")
	expectRefusal := func(args []string, want string) {
		t.Helper()
		var out, diagnostic bytes.Buffer
		if code := run(args, &out, &diagnostic); code != 1 || !strings.Contains(diagnostic.String(), want) {
			t.Fatalf("sfcli %s: exit %d\n%s", strings.Join(args, " "), code, diagnostic.String())
		}
	}
	expectRefusal(append(sized, "--id", "c1"), "tenant shop has no volume budget on node")
	n.run(0, "volume", "backup", "limits", "set", "--tenant", "shop", "--node", "node", "--max-size", "1GiB", "--max-backups", "4", "--volume-size", "2GiB", "--volumes", "4", "-y", "--id", "budget-tenant")
	expectRefusal(append(sized, "--id", "c2"), "no cluster volume budget")
	expectRefusal(append(base, "--id", "c3"), "needs --size")
	n.run(0, "volume", "backup", "limits", "set", "--all", "--node", "node", "--max-size", "1GiB", "--max-backups", "4", "--volume-size", "4GiB", "--volumes", "8", "-y", "--id", "budget-cluster")
	n.run(0, append(sized, "--id", "c4")...)
	if op := n.op("c4"); op.State == cli.Failed {
		t.Fatalf("sized create under budgets: %+v", op)
	}
	if ops := n.ops(); len(ops) != 3 {
		t.Fatalf("refused creates were recorded: %+v", ops)
	}
}
