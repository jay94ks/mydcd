// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/network/services"
)

// Replace only the declared, not-yet-dispatched input of the existing fixture.
// All command preparation, Task admission, DNS publication, binding and pin
// below use the existing product reducers. No native readiness is claimed.
func standaloneDNSProjectionFixture(t *testing.T, aliases string, dns bool) (*backupCoreFixture, string, string) {
	t.Helper()
	f, scope := standaloneCoreFixture(t, "temp")
	apps, _ := f.p.Apps(f.s)
	entry := apps.entries[appKey("tenant", scope)]
	execution, _ := entry.Inventory.Execution()
	raw := execution.Blueprint().OriginalDocument().Body
	if aliases == "" {
		raw = bytes.Replace(raw, []byte(", aliases: [debug]"), nil, 1)
	} else {
		raw = bytes.Replace(raw, []byte("aliases: [debug]"), []byte("aliases: ["+aliases+"]"), 1)
	}
	if !dns {
		raw = bytes.Replace(raw, []byte("    dns: [10.80.1.1]\n"), nil, 1)
		sources, _ := f.p.ManagedDNS(f.s)
		definition := sources[services.ManagedDNSKey("tenant", "services")].Definition
		definition.Policy.Enabled = false
		managedDNSChange(t, f, "standalone-no-dns-policy", "configure-network-dns", f.s.Object(services.ManagedDNSKey("tenant", "services")).Revision, definition, state.Applied)
		apps, _ = f.p.Apps(f.s)
	}
	catalog, _ := f.p.Catalog(f.s)
	ctx, err := f.p.AppPlanning(f.s, "admin", "tenant")
	if err != nil {
		t.Fatal(err)
	}
	ctx.Project, ctx.Deployment = scope, "deploy"
	b, err := deployment.CompileStandaloneDocument(raw, "debug", catalog, ctx, "shell")
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := deployment.NewInventory(f.p.Cluster, "tenant", scope, "deploy")
	command, commandErr := entry.Origin.Command()
	if err == nil && commandErr == nil {
		inventory, err = inventory.Begin(inventory.Revision(), catalog, ctx, b, "run-standalone", command.Actor, command.Epoch, false)
	}
	if err != nil || commandErr != nil {
		t.Fatal(err, commandErr)
	}
	entry.Inventory = inventory
	apps.entries[appKey("tenant", scope)] = entry
	checkpointStandaloneDNSFixture(t, f, apps)
	return f, scope, deployment.ResourceKey("task", "tenant", scope, "debug")
}

func checkpointStandaloneDNSFixture(t *testing.T, f *backupCoreFixture, apps Apps) {
	t.Helper()
	writes, code := f.p.appsCheckpoint(f.s, apps)
	if code != state.Applied {
		t.Fatal("declared standalone DNS fixture checkpoint", code)
	}
	next, _, err := state.ApplyReduced(f.s, f.s.Index()+1, state.Command{Kind: state.Module, Actor: "anchor", Epoch: f.s.ModuleEpoch(), RequestID: fmt.Sprintf("standalone-dns-fixture-%d", f.s.Index()), Key: AppsKey, Expected: f.s.Object(AppsKey).Revision, Value: "fixture"}, nil, func(state.State, state.Command) (map[string][]byte, state.Code) { return writes, state.Applied })
	if err != nil {
		t.Fatal(err)
	}
	f.s = next
}

func standaloneDNSRegistrations(t *testing.T, f *backupCoreFixture) []services.DNSRegistration {
	t.Helper()
	projection, err := f.p.ProjectResources(f.s)
	if err != nil {
		t.Fatal(err)
	}
	sources, _ := f.p.ManagedDNS(f.s)
	rows, err := f.p.managedDNSRegistrations(f.s, projection, sources[services.ManagedDNSKey("tenant", "services")].Definition, nil)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestStandaloneManagedDNSDefaultNameCompetesBeforeTaskCollect(t *testing.T) {
	f, scope, task := standaloneDNSProjectionFixture(t, "", true)
	managedDNSTaskCoreSubmit(t, f, scope, deployment.ResourceKey("network-ref", "tenant", scope, "lan/node-a"), true, state.Applied)
	command := managedDNSTaskCoreSubmit(t, f, scope, task, false, state.Applied)
	apps, _ := f.p.Apps(f.s)
	x, _ := apps.Execution("tenant", scope)
	stage, _ := x.Stage(task)
	if stage.Result != nil {
		t.Fatal("fixture erased the original commit/collect gap")
	}
	rows := standaloneDNSRegistrations(t, f)
	if len(rows) != 1 || !reflect.DeepEqual(rows[0].Aliases, []string{"debug"}) {
		t.Fatal("uncollected standalone omitted its default public DNS alias", rows)
	}
	goal, err := deployment.DecodeGoalResources(f.p.Cluster, task, f.s.Object(task))
	var service deployment.ComposeService
	if err != nil || json.Unmarshal(goal.Goal.Config, &service) != nil || len(service.Networks["lan"].Aliases) != 0 {
		t.Fatal("DNS projection rewrote the frozen original Task", err)
	}
	other := managedDNSTaskCoreBegin(t, f, "other", "10.80.1.41", "DEBUG")
	managedDNSTaskCoreSubmit(t, f, "other", deployment.ResourceKey("network-ref", "tenant", "other", "lan/node-a"), true, state.Applied)
	before := f.s.Object(task)
	managedDNSTaskCoreSubmit(t, f, "other", other, false, state.Invalid)
	if f.s.Object(task) != before || f.s.Object(other).Present {
		t.Fatal("default standalone DNS collision changed either original Task")
	}
	result, exists := f.s.LookupResult(command)
	if !exists || result.Code != state.Applied {
		t.Fatal("collision lost the original standalone commit receipt")
	}
}

func TestStandaloneManagedDNSDefaultNameSurvivesPinAndKeptTaskSource(t *testing.T) {
	f, scope, task := standaloneDNSProjectionFixture(t, "", true)
	managedDNSTaskCoreSubmit(t, f, scope, deployment.ResourceKey("network-ref", "tenant", scope, "lan/node-a"), true, state.Applied)
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	command := managedDNSTaskCoreSubmit(t, f, scope, task, true, state.Applied)
	managedDNSTaskCoreProgress(t, f, scope, "bind-inputs", task, nil)
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	// Collect/bind and fresh DNS publication do not finish the accepted app
	// execution. Commit its actual finish report at the same observation time
	// (10), before pin (11) and the later independent Keep acceptance (12).
	managedDNSTaskCoreProgress(t, f, scope, "finish", "", nil)
	before := f.s.Object(task)
	apps, _ := f.p.Apps(f.s)
	entry := apps.entries[appKey("tenant", scope)]
	finished, active := entry.Inventory.Execution()
	if !active || finished.Status() != "Succeeded" {
		t.Fatal("original standalone execution was not finished before Keep")
	}
	inventory, _ := entry.Inventory.Encode()
	pinPayload, err := json.Marshal(StandaloneChange{Tenant: "tenant", Name: "debug", NewName: "kept", Operation: "dns-pin"})
	if err != nil {
		t.Fatal(err)
	}
	pin := UserOperation{Schema: 1, Session: f.session, At: 11, Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(AppsKey).Revision, RequestID: "standalone-dns-pin", Change: Change{Schema: 1, Principal: "admin", Action: "standalone-pin", Expected: entry.Standalone.Revision, Payload: pinPayload}}
	pin.Signature = ed25519.Sign(f.admin, OperationBytes(pin))
	pinCommand, err := pin.Command()
	if err != nil {
		t.Fatal(err)
	}
	applyRestartCore(t, f, pinCommand, state.Applied)
	apps, _ = f.p.Apps(f.s)
	entry = apps.entries[appKey("tenant", scope)]
	after, _ := entry.Inventory.Encode()
	if !bytes.Equal(inventory, after) || f.s.Object(task) != before || entry.Standalone.Name != "kept" {
		t.Fatal("pin replaced original Task or inventory")
	}
	rows := standaloneDNSRegistrations(t, f)
	if len(rows) != 1 || !reflect.DeepEqual(rows[0].Aliases, []string{"debug"}) {
		t.Fatal("pin rebound default alias to mutable public name", rows)
	}
	// Model the later accepted up with the product Inventory's Keep path. Its
	// new document/public name cannot replace the old Task's binding origin.
	catalog, _ := f.p.Catalog(f.s)
	ctx, err := f.p.AppPlanning(f.s, "admin", "tenant")
	if err != nil {
		t.Fatal(err)
	}
	ctx.Project, ctx.Deployment = scope, "deploy"
	x, _ := entry.Inventory.Execution()
	raw := x.Blueprint().OriginalDocument().Body
	b, err := deployment.CompileStandaloneDocument(raw, "kept", catalog, ctx, "shell")
	if err != nil {
		t.Fatal(err)
	}
	changes, err := entry.Inventory.Changes(b, false)
	if err != nil || !slices.ContainsFunc(changes, func(c deployment.Change) bool { return c.Key == task && c.Action == "Keep" }) {
		t.Fatal("later standalone acceptance did not keep original Task", err)
	}
	payload, _ := json.Marshal(AppBegin{Standalone: &StandaloneDefinition{Name: "kept", Lifetime: "fixed", Mode: "shell", Restart: "on-failure"}, Tenant: "tenant", App: scope, Deployment: "deploy", Upload: "mock-keep-upload", Operation: "run-keep"})
	origin := UserOperation{Schema: 1, Session: f.session, At: 12, Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(AppsKey).Revision, RequestID: "standalone-dns-keep", Change: Change{Schema: 1, Principal: "admin", Action: "standalone-up", Payload: payload}}
	origin.Signature = ed25519.Sign(f.admin, OperationBytes(origin))
	accepted, err := origin.Command()
	if err == nil {
		entry.Inventory, err = entry.Inventory.Begin(entry.Inventory.Revision(), catalog, ctx, b, "run-keep", accepted.Actor, accepted.Epoch, false)
	}
	if err != nil {
		t.Fatal("later Keep acceptance", err)
	}
	entry.Origin = origin
	apps.entries[appKey("tenant", scope)] = entry
	checkpointStandaloneDNSFixture(t, f, apps)
	rows = standaloneDNSRegistrations(t, f)
	if len(rows) != 1 || !reflect.DeepEqual(rows[0].Aliases, []string{"debug"}) || f.s.Object(task) != before {
		t.Fatal("later Keep adopted a new alias or replaced the original Task", rows)
	}
	encoded, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := state.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	f.s = restored
	if rows = standaloneDNSRegistrations(t, f); len(rows) != 1 || !reflect.DeepEqual(rows[0].Aliases, []string{"debug"}) {
		t.Fatal("restored original Task lost its alias")
	}
	// The retained original reference must not be replaced by a different
	// matching-looking signature, purpose or current acceptance.
	apps, _ = f.p.Apps(f.s)
	goal, _ := deployment.DecodeGoalResources(f.p.Cluster, task, f.s.Object(task))
	for _, mutate := range []func(*AppBindingSource){
		func(s *AppBindingSource) { s.Command[0] ^= 1 },
		func(s *AppBindingSource) { s.Task.Generation++ },
		func(s *AppBindingSource) { s.Origin.Signature = nil },
		func(s *AppBindingSource) {
			s.Origin = origin
			s.Origin.Change.Action = "begin-app"
			s.Origin.Signature = ed25519.Sign(f.admin, OperationBytes(s.Origin))
		},
	} {
		bad := apps
		bad.sources = slices.Clone(apps.sources)
		for i, source := range bad.sources {
			if source.Task.Key == task {
				mutate(&bad.sources[i])
			}
		}
		if _, err := standaloneTaskDNSName(f.s, bad, goal.Goal, command); err == nil {
			t.Fatal("default alias accepted a changed original binding proof")
		}
	}
}

func TestStandaloneManagedDNSExplicitAliasesAndCurrentPolicyRemainAuthoritative(t *testing.T) {
	for _, aliases := range []string{"", "chosen"} {
		t.Run("aliases-"+aliases, func(t *testing.T) {
			f, scope, task := standaloneDNSProjectionFixture(t, aliases, true)
			managedDNSTaskCoreSubmit(t, f, scope, deployment.ResourceKey("network-ref", "tenant", scope, "lan/node-a"), true, state.Applied)
			applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
			managedDNSTaskCoreSubmit(t, f, scope, task, false, state.Applied)
			object := f.s.Object(task)
			ref := deployment.ObjectRef{Key: task, Generation: object.Generation, Revision: object.Revision}
			if _, err := f.p.ManagedTaskDNS(f.s, ref); err == nil {
				t.Fatal("empty earlier DNS view authorized a new standalone Task")
			}
			applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
			rows, err := f.p.ManagedTaskDNS(f.s, ref)
			want := aliases
			if want == "" {
				want = "debug"
			}
			if err != nil || len(rows) != 1 || !slices.ContainsFunc(rows[0].Config.Names, func(n services.DNSName) bool {
				return n.Name == want+".apps.mydc.test." && n.Endpoint == task+"/lan/0" && n.Generation == ref.Generation
			}) {
				t.Fatal("default/explicit alias did not use exact current Task publication", err)
			}
			if aliases != "" && slices.ContainsFunc(rows[0].Config.Names, func(n services.DNSName) bool { return n.Name == "debug.apps.mydc.test." }) {
				t.Fatal("default alias overrode explicit aliases")
			}
			sources, _ := f.p.ManagedDNS(f.s)
			key := services.ManagedDNSKey("tenant", "services")
			definition := sources[key].Definition
			definition.Policy.TTL++
			managedDNSChange(t, f, "standalone-current-dns-policy", "configure-network-dns", f.s.Object(key).Revision, definition, state.Applied)
			if _, err := f.p.ManagedTaskDNS(f.s, ref); err == nil {
				t.Fatal("default alias bypassed current managed DNS policy")
			}
		})
	}
}

func TestStandaloneDefaultNameDoesNotRequireDNSOnNonDNSNetwork(t *testing.T) {
	f, scope, task := standaloneDNSProjectionFixture(t, "", false)
	managedDNSTaskCoreSubmit(t, f, scope, deployment.ResourceKey("network-ref", "tenant", scope, "lan/node-a"), true, state.Applied)
	managedDNSTaskCoreSubmit(t, f, scope, task, false, state.Applied)
	object := f.s.Object(task)
	rows, err := f.p.ManagedTaskDNS(f.s, deployment.ObjectRef{Key: task, Generation: object.Generation, Revision: object.Revision})
	if err != nil || len(rows) != 0 || strings.Contains(object.Value, `"Aliases"`) {
		t.Fatal("default standalone name imposed DNS or changed original Task bytes", err)
	}
}
