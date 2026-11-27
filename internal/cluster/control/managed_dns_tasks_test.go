// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"slices"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/workload"
)

// The accepted app graph and native observations are explicit Mock fixtures.
// All admission/projection/Task requirements use the actual product FSM/core.
func managedDNSTaskCoreFixture(t *testing.T) *backupCoreFixture {
	t.Helper()
	f, _, _ := managedDNSProjectionFixture(t)
	f.session.Scopes[0].Actions = append(f.session.Scopes[0].Actions, access.Deploy)
	f.session.Signature = ed25519.Sign(f.node, access.SessionBytes(f.session))
	for _, scope := range []string{"", "tenant"} {
		resources, _ := f.p.Resources(f.s)
		limit, _ := resources.Quotas.Limit(scope, "node-a")
		expected := limit.Revision
		limit.Revision = 0
		limit.Capacity = workload.Resources{CPU: 4e9, Memory: 256 << 20}
		f.apply("dns-task-quota-"+scope, "set-node-quota", expected, limit, state.Applied)
	}
	return f
}

func managedDNSTaskCoreBegin(t *testing.T, f *backupCoreFixture, app, address, alias string, configure ...func(*deployment.Compose, *deployment.PlanningContext)) string {
	t.Helper()
	raw := fmt.Sprintf("name: %s\nservices:\n  web:\n    image: docker.io/library/php@sha256:%s\n    cpus: '0.1'\n    mem_limit: 16m\n    networks: {lan: {ipv4_address: %s, aliases: [%s]}}\n    dns: [10.80.1.1]\n    x-sfc: {node: node-a}\nnetworks:\n  lan: {external: true, name: services}\n", app, string(bytes.Repeat([]byte{'a'}, 64)), address, alias)
	input, err := deployment.ParseApp([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	catalog, _ := f.p.Catalog(f.s)
	planning, err := f.p.AppPlanning(f.s, "admin", "tenant")
	if err != nil {
		t.Fatal(err)
	}
	// Use the product planning capability. Injecting this accepted graph is
	// still a pure-core fixture, not evidence of actual DNS/native readiness.
	planning.Project, planning.Deployment = app, "deploy"
	if len(configure) > 1 {
		t.Fatal("one explicit planning fixture modifier required")
	}
	if len(configure) == 1 {
		configure[0](&input, &planning)
	}
	blueprint, err := deployment.CompileApp(input, catalog, planning)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(AppBegin{Tenant: "tenant", App: app, Deployment: "deploy", Upload: "mock-upload", Operation: "run-" + app})
	origin := UserOperation{Schema: 1, Session: f.session, At: 2, Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(AppsKey).Revision, RequestID: "accept-" + app, Change: Change{Schema: 1, Principal: "admin", Action: "begin-app", Payload: payload}}
	origin.Signature = ed25519.Sign(f.admin, OperationBytes(origin))
	command, err := origin.Command()
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := deployment.NewInventory(f.p.Cluster, "tenant", app, "deploy")
	if err == nil {
		inventory, err = inventory.Begin(inventory.Revision(), catalog, planning, blueprint, "run-"+app, command.Actor, command.Epoch, false)
	}
	if err != nil {
		t.Fatal(err)
	}
	apps, _ := f.p.Apps(f.s)
	apps.entries[appKey("tenant", app)] = appEntry{Inventory: inventory, Origin: origin}
	writes, code := f.p.appsCheckpoint(f.s, apps)
	if code != state.Applied {
		t.Fatal(code)
	}
	// The acceptance is fixture input, not a transport/CLI/native success.
	f.s, _, err = state.ApplyReduced(f.s, f.s.Index()+1, state.Command{Kind: state.Module, Actor: "anchor", Epoch: f.s.ModuleEpoch(), RequestID: "mock-accept-" + app, Key: AppsKey, Expected: f.s.Object(AppsKey).Revision, Value: "mock"}, nil, func(state.State, state.Command) (map[string][]byte, state.Code) { return writes, state.Applied })
	if err != nil {
		t.Fatal(err)
	}
	return deployment.ResourceKey("task", "tenant", app, "web")
}

func managedDNSTaskCoreProgress(t *testing.T, f *backupCoreFixture, app, action, key string, observation *deployment.Observation) {
	t.Helper()
	apps, _ := f.p.Apps(f.s)
	i, _ := apps.Inventory("tenant", app)
	execution, found := apps.Execution("tenant", app)
	if !found {
		t.Fatal("missing original app execution", app)
	}
	r := AppProgress{Schema: 1, Cluster: f.p.Cluster, Reporter: [32]byte(f.node.Public().(ed25519.PublicKey)), Tenant: "tenant", App: app, Operation: execution.ActiveOperation(), Key: key, Action: action, Observation: observation, Expected: i.Revision(), At: 10, Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(AppsKey).Revision, RequestID: fmt.Sprintf("dns-task-%d-%s", f.s.Index(), action)}
	if StageReport(r.Action) {
		r.Stage = f.p.StageDigest(f.s, r.Tenant, r.App, r.Key)
	}
	r.Signature = ed25519.Sign(f.node, AppProgressBytes(r))
	cmd, err := r.Command()
	if err != nil {
		t.Fatal(err)
	}
	var result state.Result
	f.s, result, err = state.ApplyTransactional(f.s, f.s.Index()+1, cmd, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
	if err != nil || result.Code != state.Applied {
		t.Fatal("mock progress", app, action, key, result, err)
	}
}

func managedDNSTaskCoreSubmit(t *testing.T, f *backupCoreFixture, app, key string, collect bool, want state.Code) state.Command {
	t.Helper()
	managedDNSTaskCoreProgress(t, f, app, "prepare", key, nil)
	managedDNSTaskCoreProgress(t, f, app, "send", key, nil)
	apps, _ := f.p.Apps(f.s)
	execution, _ := apps.Execution("tenant", app)
	stage, _ := execution.Stage(key)
	if stage.Command == nil {
		t.Fatal("missing original dispatch")
	}
	cmd := *stage.Command
	var result state.Result
	var err error
	validate := func(before, after state.State, command state.Command) error {
		validationErr := f.p.ValidateManaged(before, after, command)
		if validationErr != nil && want == state.Applied {
			_, goalErr := deployment.DecodeGoalResources(f.p.Cluster, key, after.Object(key))
			projection, projectionErr := f.p.ProjectResources(after)
			apps, appsErr := f.p.readOnlyApps(after)
			t.Log("original mutation validation", validationErr, "goal", goalErr, "projection", projectionErr, "apps", appsErr)
			if projectionErr == nil && appsErr == nil {
				t.Log("original mutation references", "commands", f.p.validateAppCommands(after, apps, command), "DNS", f.p.validateManagedTaskDNS(after, projection, command))
			}
		}
		return validationErr
	}
	f.s, result, err = state.ApplyTransactional(f.s, f.s.Index()+1, cmd, validate, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
	if err != nil || result.Code != want {
		t.Fatal("mock original mutation", app, key, result, want, err)
	}
	if collect && result.Code == state.Applied {
		managedDNSTaskCoreProgress(t, f, app, "collect", key, nil)
		inventory, _ := apps.Inventory("tenant", app)
		summary, _ := inventory.Active()
		observation := deployment.Observation{Cluster: f.p.Cluster, Plan: summary.Plan, Operation: execution.ActiveOperation(), Key: key, Native: "mock-native-" + app, Owner: [32]byte(f.node.Public().(ed25519.PublicKey)), Command: state.Digest(cmd), Generation: result.Generation, Revision: result.Revision, Sequence: 1, At: 10, Applied: true, Healthy: true}
		observation.Signature = ed25519.Sign(f.node, deployment.ObservationBytes(observation))
		managedDNSTaskCoreProgress(t, f, app, "observe", key, &observation)
	}
	return cmd
}

func TestManagedDNSTaskCoreNamesCompeteBeforeReceiptCollection(t *testing.T) {
	f := managedDNSTaskCoreFixture(t)
	first := managedDNSTaskCoreBegin(t, f, "first", "10.80.1.10", "shared")
	second := managedDNSTaskCoreBegin(t, f, "second", "10.80.1.11", "SHARED")
	for _, app := range []string{"first", "second"} {
		managedDNSTaskCoreSubmit(t, f, app, deployment.ResourceKey("network-ref", "tenant", app, "lan/node-a"), true, state.Applied)
	}
	command := managedDNSTaskCoreSubmit(t, f, "first", first, false, state.Applied)
	apps, _ := f.p.Apps(f.s)
	execution, _ := apps.Execution("tenant", "first")
	stage, _ := execution.Stage(first)
	if stage.Result != nil {
		t.Fatal("fixture did not preserve the real commit/report gap")
	}
	projection, err := f.p.ProjectResources(f.s)
	if err != nil {
		t.Fatal(err)
	}
	sources, _ := f.p.ManagedDNS(f.s)
	definition := sources[services.ManagedDNSKey("tenant", "services")].Definition
	registrations, err := f.p.managedDNSRegistrations(f.s, projection, definition, nil)
	if err != nil || len(registrations) != 1 || registrations[0].App != "first" {
		t.Fatal("committed original Task was omitted before collect", registrations, err)
	}
	before := f.s.Object(first)
	managedDNSTaskCoreSubmit(t, f, "second", second, false, state.Invalid)
	if f.s.Object(second).Present || f.s.Object(first) != before {
		t.Fatal("name conflict changed an original Task")
	}
	projection, err = f.p.ProjectResources(f.s)
	if err != nil {
		t.Fatal(err)
	}
	if _, held := projection.Addresses.Allocation(second + "/lan/0"); held {
		t.Fatal("rejected name conflict leaked an address reservation")
	}
	result, found := f.s.LookupResult(command)
	if !found || result.Code != state.Applied {
		t.Fatal("second conflict lost the original accepted receipt")
	}
}

func TestManagedDNSTaskCoreRequiresItsExactPublishedAddressAndCurrentSource(t *testing.T) {
	f := managedDNSTaskCoreFixture(t)
	task := managedDNSTaskCoreBegin(t, f, "first", "10.80.1.10", "shared")
	managedDNSTaskCoreSubmit(t, f, "first", deployment.ResourceKey("network-ref", "tenant", "first", "lan/node-a"), true, state.Applied)
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	managedDNSTaskCoreSubmit(t, f, "first", task, false, state.Applied)
	o := f.s.Object(task)
	ref := deployment.ObjectRef{Key: task, Generation: o.Generation, Revision: o.Revision}
	if _, err := f.p.ManagedTaskDNS(f.s, ref); err == nil {
		t.Fatal("earlier empty shared view authorized a newly committed Task")
	}
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	rows, err := f.p.ManagedTaskDNS(f.s, ref)
	if err != nil || len(rows) != 1 || rows[0].Managed == nil || rows[0].Managed.Node != "node-a" {
		t.Fatal("exact Task material", len(rows), err)
	}
	for _, name := range []string{"web.first.apps.sfc.test.", "shared.apps.sfc.test."} {
		found := false
		for _, actual := range rows[0].Config.Names {
			found = found || actual.Name == name && actual.Endpoint == task+"/lan/0" && actual.Generation == ref.Generation
		}
		if !found {
			t.Fatal("missing original Task name/address", name)
		}
	}
	for _, mutate := range []func(*deployment.ObjectRef){func(r *deployment.ObjectRef) { r.Generation++ }, func(r *deployment.ObjectRef) { r.Revision++ }, func(r *deployment.ObjectRef) { r.Key = deployment.ResourceKey("task", "tenant", "other", "web") }} {
		bad := ref
		mutate(&bad)
		if _, err := f.p.ManagedTaskDNS(f.s, bad); err == nil {
			t.Fatal("foreign/stale Task reference authorized DNS")
		}
	}
	sources, _ := f.p.ManagedDNS(f.s)
	key := services.ManagedDNSKey("tenant", "services")
	definition := sources[key].Definition
	definition.Policy.TTL++
	managedDNSChange(t, f, "task-dns-ttl", "configure-network-dns", f.s.Object(key).Revision, definition, state.Applied)
	if _, err := f.p.ManagedTaskDNS(f.s, ref); err == nil {
		t.Fatal("old view authorized Task after policy replacement")
	}
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	if _, err := f.p.ManagedTaskDNS(f.s, ref); err != nil {
		t.Fatal("fresh current policy/view did not restore exact requirement", err)
	}
}

func TestNetworkDNSNamesReadsServedNamesWithAddresses(t *testing.T) {
	f := managedDNSTaskCoreFixture(t)
	task := managedDNSTaskCoreBegin(t, f, "first", "10.80.1.10", "shared")
	managedDNSTaskCoreSubmit(t, f, "first", deployment.ResourceKey("network-ref", "tenant", "first", "lan/node-a"), true, state.Applied)
	managedDNSTaskCoreSubmit(t, f, "first", task, false, state.Applied)
	now := f.session.IssuedAt + 1
	got, err := f.p.NetworkDNSNames(f.s, f.session, now, "tenant", NetworkDNSNamesQuery{Network: "services"})
	if err != nil || !got.Managed || got.Zone != "apps.sfc.test." || len(got.Names) != 2 {
		t.Fatalf("names = %+v, %v", got, err)
	}
	for _, n := range got.Names {
		if n.App != "first" || n.Service != "web" || n.Family != "ipv4" || n.Address != "10.80.1.10" || n.Name != "shared.apps.sfc.test." && n.Name != "web.first.apps.sfc.test." {
			t.Fatalf("row = %+v", n)
		}
	}
	if none, err := f.p.NetworkDNSNames(f.s, f.session, now, "tenant", NetworkDNSNamesQuery{Network: "other"}); err != nil || none.Managed || len(none.Names) != 0 {
		t.Fatalf("unmanaged network = %+v, %v", none, err)
	}
	if _, err := f.p.NetworkDNSNames(f.s, f.session, now, "elsewhere", NetworkDNSNamesQuery{Network: "services"}); err == nil {
		t.Fatal("names read without Read on the tenant")
	}
	if _, err := f.p.NetworkDNSNames(f.s, f.session, now, "tenant", NetworkDNSNamesQuery{Network: "Bad Name"}); err == nil {
		t.Fatal("invalid network accepted")
	}
}

func TestNetworkDNSNamesReadsHandRecords(t *testing.T) {
	f := managedDNSTaskCoreFixture(t)
	task := managedDNSTaskCoreBegin(t, f, "first", "10.80.1.10", "shared")
	managedDNSTaskCoreSubmit(t, f, "first", deployment.ResourceKey("network-ref", "tenant", "first", "lan/node-a"), true, state.Applied)
	managedDNSTaskCoreSubmit(t, f, "first", task, false, state.Applied)
	key := services.ManagedDNSKey("tenant", "services")
	sources, err := f.p.ManagedDNS(f.s)
	if err != nil {
		t.Fatal(err)
	}
	definition := sources[key].Definition
	definition.Policy.Records = []services.DNSRecord{{Name: "www.apps.sfc.test.", Type: "CNAME", Value: "shared.apps.sfc.test."}, {Name: "x.apps.sfc.test.", Type: "A", Value: "2001:db8::1"}}
	managedDNSChange(t, f, "dns-records-bad", "configure-network-dns", f.s.Object(key).Revision, definition, state.ConditionFailed)
	definition.Policy.Records = []services.DNSRecord{
		{Name: "www.apps.sfc.test.", Type: "CNAME", Value: "shared.apps.sfc.test."},
		{Name: "shared.apps.sfc.test.", Type: "A", Value: "192.0.2.9"}, // the app's alias
	}
	managedDNSChange(t, f, "dns-records", "configure-network-dns", f.s.Object(key).Revision, definition, state.Applied)
	got, err := f.p.NetworkDNSNames(f.s, f.session, f.session.IssuedAt+1, "tenant", NetworkDNSNamesQuery{Network: "services"})
	if err != nil || len(got.Names) != 2 || len(got.Records) != 2 {
		t.Fatalf("names = %+v, %v", got, err)
	}
	want := []NetworkDNSRecord{{Name: "shared.apps.sfc.test.", Type: "A", Value: "192.0.2.9"}, {Name: "www.apps.sfc.test.", Type: "CNAME", Value: "shared.apps.sfc.test.", Served: true}}
	if !slices.Equal(got.Records, want) {
		t.Fatalf("records = %+v", got.Records)
	}
}
