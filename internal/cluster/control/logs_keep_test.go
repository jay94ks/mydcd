// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
)

func standaloneLogsFixture(t *testing.T, lifetime, raw string) (*backupCoreFixture, string) {
	t.Helper()
	f := managedDNSTaskCoreFixture(t)
	catalog, _ := f.p.Catalog(f.s)
	ctx, err := f.p.AppPlanning(f.s, "admin", "tenant")
	if err != nil {
		t.Fatal(err)
	}
	ctx.Deployment = "deploy"
	rawDoc := []byte(raw)
	b, err := deployment.CompileStandaloneDocument(rawDoc, "debug", catalog, ctx, "shell")
	if err != nil {
		t.Fatal(err)
	}
	scope := b.Scope()
	d := StandaloneDefinition{Name: "debug", Lifetime: lifetime, Mode: "shell"}
	m, err := d.metadata("tenant", "admin", "node-a", 2)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(AppBegin{Standalone: &d, Tenant: "tenant", App: scope.App, Deployment: "deploy", Upload: "mock-upload", Operation: "run-standalone"})
	origin := UserOperation{Schema: 1, Session: f.session, At: 2, Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(AppsKey).Revision, RequestID: "standalone-original", Change: Change{Schema: 1, Principal: "admin", Action: "standalone-up", Payload: payload}}
	origin.Signature = ed25519.Sign(f.admin, OperationBytes(origin))
	cmd, err := origin.Command()
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := deployment.NewInventory(f.p.Cluster, "tenant", scope.App, "deploy")
	if err == nil {
		ctx.Project = scope.App
		inventory, err = inventory.Begin(inventory.Revision(), catalog, ctx, b, "run-standalone", cmd.Actor, cmd.Epoch, false)
	}
	if err != nil {
		t.Fatal(err)
	}
	apps, _ := f.p.Apps(f.s)
	apps.entries[appKey("tenant", scope.App)] = appEntry{Standalone: &m, Origin: origin, Inventory: inventory}
	writes, code := f.p.appsCheckpoint(f.s, apps)
	if code != state.Applied {
		t.Fatal(code)
	}
	f.s, _, err = state.ApplyReduced(f.s, f.s.Index()+1, state.Command{Kind: state.Module, Actor: "anchor", Epoch: f.s.ModuleEpoch(), RequestID: "fixture-standalone", Key: AppsKey, Expected: f.s.Object(AppsKey).Revision, Value: "fixture"}, nil, func(state.State, state.Command) (map[string][]byte, state.Code) { return writes, state.Applied })
	if err != nil {
		t.Fatal(err)
	}
	return f, scope.App
}

func TestLogKeepsServiceOverAppFromCurrentDocument(t *testing.T) {
	doc := func(app, service string) string {
		return fmt.Sprintf("services:\n  debug:\n    image: docker.io/library/php@sha256:%s\n    cpus: '0.1'\n    mem_limit: 16m\n    networks: {lan: {ipv4_address: 10.80.1.40, aliases: [debug]}}\n    dns: [10.80.1.1]\n    x-sfc: {node: node-a%s}\nnetworks:\n  lan: {external: true, name: services}\n%s", string(bytes.Repeat([]byte{'a'}, 64)), service, app)
	}
	for _, c := range []struct{ app, service, want string }{
		{"", "", ""},
		{"x-sfc: {logs: {keep: forever}}\n", "", "forever"},
		{"x-sfc: {logs: {keep: forever}}\n", ", logs: {keep: 3d}", "3d"},
	} {
		f, scope := standaloneLogsFixture(t, "temp", doc(c.app, c.service))
		keep, err := f.p.LogKeeps(f.s)
		if err != nil {
			t.Fatal(err)
		}
		if got := keep("tenant", scope, "debug"); got != c.want {
			t.Fatalf("%+v: got %q", c, got)
		}
		if got := keep("tenant", "other-app", "debug"); got != "" {
			t.Fatal("unknown app", got)
		}
	}
}
