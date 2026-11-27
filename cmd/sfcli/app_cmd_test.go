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

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/workload"
)

func TestAppCheckIsLocal(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	file := filepath.Join(t.TempDir(), "app.yaml")
	if err := os.WriteFile(file, appComposeDocument(2), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, e := sfcli(t, "app", "check", "-f", file); code != 0 || !strings.Contains(out, "app: 2 service(s)") {
		t.Fatal(code, out, e)
	}
	code, out, e := sfcli(t, "app", "check", "-f", file, "-o", "json")
	var v map[string]any
	if code != 0 || json.Unmarshal([]byte(out), &v) != nil {
		t.Fatal(code, out, e)
	}
	bad := filepath.Join(t.TempDir(), "app.yaml")
	if err := os.WriteFile(bad, []byte("name: app\nservices: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := sfcli(t, "app", "check", "-f", bad); code == 0 {
		t.Fatal("invalid app.yaml accepted")
	}
}

func TestComposeCommandPointsToApp(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if _, _, e := sfcli(t, "compose", "ps"); !strings.Contains(e, "sfcli app") {
		t.Fatal(e)
	}
}

func TestAppCommandsAgainstManagedNode(t *testing.T) {
	root, home := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	operator, err := identity.Create(filepath.Join(root, "operator"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(operator.Private)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	fixture := newManagedNode(t, ctx, root, "node-a", operator)
	fixture.EnrollAdmin(access.User{ID: "sys", Username: "operator", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: operator.Public, Enabled: true}}})
	must := func(r state.Result) {
		t.Helper()
		if r.Code != state.Applied {
			t.Fatal(r)
		}
	}
	must(fixture.Change("tenant", "create-tenant", 0, control.TenantID{ID: "tenant"}))
	tenant, _ := fixture.Catalog().Tenant("tenant")
	must(fixture.Change("nodes", "set-nodes", tenant.Revision, control.NodeChangeTo("tenant", tenant.AllowedNodes, []string{"node-a"})))
	for i, scope := range []string{"", "tenant"} {
		// The tenant's limit allows no connections: the deploy stays planned
		// and 'op show' says why.
		must(fixture.Change("quota"+string(rune('0'+i)), "set-node-quota", 0, tenancy.NodeLimit{Tenant: scope, Node: "node-a", Capacity: workload.Resources{CPU: 4e9, Memory: 1 << 30}, Networks: 4, MaxConsumers: map[string]int{"": 64}[scope]}))
	}
	v, err := fixture.Runtime.Engine().Read(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	resources, err := fixture.Policy.Resources(v.State)
	if err != nil {
		t.Fatal(err)
	}
	must(fixture.Change("shared-lan", "create-tun-network", resources.Networks.Revision(), composeFixtureNetwork()))

	secret := filepath.Join(root, "wallet-password")
	if err := os.WriteFile(secret, []byte("wallet secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SFC_WALLET_PASSWORD_FILE", secret)
	file := filepath.Join(root, "app.yaml")
	if err := os.WriteFile(file, appComposeDocument(1), 0o600); err != nil {
		t.Fatal(err)
	}
	ok := func(args ...string) string {
		t.Helper()
		code, out, e := sfcli(t, args...)
		if code != 0 {
			t.Fatal(args, code, out, e)
		}
		return out
	}
	ok("key", "import", "ops", filepath.Join(root, "operator", "key.pem"))
	ok("context", "add", "prod", "sfcp://"+fixture.Address, "--key", hex.EncodeToString(fixture.Node().Public[:]), "--user", "operator", "--tenant", "tenant", "--wallet-key", "ops")
	ok("login")

	if out := ok("app", "list"); !strings.Contains(out, "(none)") {
		t.Fatal(out)
	}
	var diff control.AppDiff
	plan := filepath.Join(root, "plan.json")
	if out := ok("app", "diff", "-f", file, "--save", plan, "-o", "json"); json.Unmarshal([]byte(out), &diff) != nil || diff.App != "app" || len(diff.Changes) == 0 {
		t.Fatal(out)
	}
	if _, err := os.Stat(plan); err != nil {
		t.Fatal("plan not saved", err)
	}
	var deployed struct {
		ID    string `json:"id"`
		State string `json:"state"`
	}
	out := ok("app", "deploy", "--plan", plan, "--no-wait", "--id", "first-deploy", "-o", "json")
	if json.Unmarshal([]byte(out), &deployed) != nil || deployed.ID != "first-deploy" || deployed.State != "accepted" {
		t.Fatal(out)
	}
	if out := ok("op", "show", "first-deploy", "-o", "json"); !strings.Contains(out, `"kind": "app-deploy"`) || !strings.Contains(out, `"state": "accepted"`) {
		t.Fatal(out)
	}
	if out := ok("op", "show", "first-deploy"); !strings.Contains(out, "allows no connections") || !strings.Contains(out, "no packet queue") || !strings.Contains(out, " on node-a ") || !strings.Contains(out, "node-a") {
		t.Fatal("planned deploy without its reason", out)
	}
	// Running the same ID again finishes the same deployment, never a new one.
	if out := ok("app", "deploy", "--plan", plan, "--no-wait", "--id", "first-deploy"); !strings.Contains(out, "first-deploy") {
		t.Fatal(out)
	}
	// A new deploy while that one is unfinished is refused at its accept step,
	// and the command says so instead of ending silently.
	if code, _, e := sfcli(t, "app", "deploy", "-f", file, "--no-wait", "--id", "second-deploy"); code != 3 || !strings.Contains(e, "the server refused the accept step") {
		t.Fatal("refused deploy without its step", code, e)
	}
	// The descriptor reaches the deploy flow, which checks it against the app.
	if code, _, e := sfcli(t, "app", "deploy", "-f", file, "--no-wait", "--id", "third-deploy", "--group-password-fd", "tenant/unused=9"); code != 2 || !strings.Contains(e, "unrequired Group tenant/unused") {
		t.Fatal("descriptor not passed on", code, e)
	}
	if code, _, e := sfcli(t, "app", "deploy", "-f", file, "--group-password-fd", "tenant/unused=1"); code != 2 || !strings.Contains(e, "REALM/GROUP=FD") {
		t.Fatal("bad descriptor accepted", code, e)
	}
	if out := ok("app", "list"); !strings.Contains(out, "app") || !strings.Contains(out, "planned") {
		t.Fatal(out)
	}
	if out := ok("app", "show", "app"); !strings.Contains(out, "first-deploy") {
		t.Fatal(out)
	}
	if code, _, e := sfcli(t, "app", "show", "missing"); code == 0 {
		t.Fatal("missing app shown", e)
	}
	if out := ok("app", "history", "app"); !strings.Contains(out, "REVISION") {
		t.Fatal(out)
	}
	if out := ok("app", "source", "app"); !strings.Contains(out, "name: app") {
		t.Fatal(out)
	}
	if code, _, _ := sfcli(t, "app", "logs", "app"); code != 2 {
		t.Fatal("logs without a service", code)
	}
	// clear-logs is one request with each server's answer, no operation.
	if code, _, e := sfcli(t, "app", "clear-logs", "app", "web"); code == 0 || !strings.Contains(e, "-y") {
		t.Fatal("clear-logs without confirmation", code, e)
	}
	if code, _, e := sfcli(t, "app", "clear-logs", "app", "--instance", "workload/task/x"); code != 2 || !strings.Contains(e, "--instance goes with SERVICE") {
		t.Fatal("instance without service", code, e)
	}
	{
		code, out, e := sfcli(t, "app", "clear-logs", "app", "-y", "-o", "json")
		var cleared control.LogsClearReply
		if json.Unmarshal([]byte(out), &cleared) != nil || len(cleared.Nodes) != 1 || cleared.Nodes[0].Node != "node-a" {
			t.Fatal("clear-logs reply", code, out, e)
		}
		t.Log("clear-logs answer", cleared.Nodes[0].Code, code)
		if cleared.Nodes[0].Code == "ok" && code != 0 || cleared.Nodes[0].Code != "ok" && (code != 1 || !strings.Contains(e, "0 of 1 servers cleared")) {
			t.Fatal("clear-logs exit", code, out, e)
		}
	}
	// The first 'cd set' turns CD on for an app deployed without it.
	cdFile := filepath.Join(root, "cd.yaml")
	if err := os.WriteFile(cdFile, []byte("version: 1\nrepository: https://git.sfc.test/team/app.git\nbranch: main\npath: app.yaml\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, e := sfcli(t, "cd", "show", "app"); code == 0 || !strings.Contains(e, "has no CD policy") {
		t.Fatal("app without CD shown as CD", code, e)
	}
	ok("cd", "set", "app", "-f", cdFile, "--id", "first-cd", "-y")
	if out := ok("cd", "show", "app"); !strings.Contains(out, "git.sfc.test/team/app.git") {
		t.Fatal("first cd set did not turn CD on", out)
	}
	// Down needs confirmation; without a terminal -y gives it.
	if code, _, e := sfcli(t, "app", "down", "app", "--no-wait"); code == 0 || !strings.Contains(e, "-y") {
		t.Fatal(code, e)
	}
	if out := ok("app", "down", "app", "-y", "--no-wait", "--id", "first-down"); !strings.Contains(out, "first-down") {
		t.Fatal(out)
	}
	if out := ok("op", "show", "first-down", "-o", "json"); !strings.Contains(out, `"kind": "app-down"`) {
		t.Fatal(out)
	}
	if strings.Contains(out, "wallet secret") {
		t.Fatal("password printed")
	}
}
