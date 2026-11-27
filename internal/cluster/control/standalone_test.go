// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/deployment"
	"testing"
)

// This is a declared input fixture. Acceptance/projection/retirement use the
// same product Inventory and reducers; it claims no Docker/transport success.
func standaloneCoreFixture(t *testing.T, lifetime string) (*backupCoreFixture, string) {
	t.Helper()
	f := managedDNSTaskCoreFixture(t)
	catalog, _ := f.p.Catalog(f.s)
	ctx, err := f.p.AppPlanning(f.s, "admin", "tenant")
	if err != nil {
		t.Fatal(err)
	}
	ctx.Deployment = "deploy"
	raw := []byte(fmt.Sprintf("services:\n  debug:\n    image: docker.io/library/php@sha256:%s\n    cpus: '0.1'\n    mem_limit: 16m\n    networks: {lan: {ipv4_address: 10.80.1.40, aliases: [debug]}}\n    dns: [10.80.1.1]\n    x-sfc: {node: node-a}\nnetworks:\n  lan: {external: true, name: services}\n", string(bytes.Repeat([]byte{'a'}, 64))))
	b, err := deployment.CompileStandaloneDocument(raw, "debug", catalog, ctx, "shell")
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
func standaloneReportCore(t *testing.T, f *backupCoreFixture, scope, action, reason string, at int64) StandalonePolicyReport {
	t.Helper()
	a, err := f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	e := a.entries[appKey("tenant", scope)]
	q := StandalonePolicyReport{Schema: 1, Kind: "standalone-policy", Cluster: f.p.Cluster, Reporter: [32]byte(f.node.Public().(ed25519.PublicKey)), Registration: appRegistrationDigest(e.Origin), Authorization: appRegistrationDigest(standalonePolicyOrigin(e)), Tenant: "tenant", App: scope, Action: action, Reason: reason, At: at, RootRevision: f.s.Object(AppsKey).Revision, Expected: e.Standalone.Revision, Epoch: f.s.ModuleEpoch()}
	q.Signature = ed25519.Sign(f.node, StandalonePolicyBytes(q))
	return q
}
func TestStandaloneAcceptedExpirationSurvivesUserRevisionWithoutForgedSession(t *testing.T) {
	f, scope := standaloneCoreFixture(t, "temp")
	c, _ := f.p.Catalog(f.s)
	u, _ := c.User("admin")
	u.Username = "rotated-account"
	expected := u.Revision
	f.apply("change-user-revision", "put-user", expected, accountFields(u), state.Applied)
	q := standaloneReportCore(t, f, scope, "expire", "ttl", 3602)
	cmd, err := q.Command()
	if err != nil {
		t.Fatal(err)
	}
	applyRestartCore(t, f, cmd, state.Applied)
	apps, err := f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	e := apps.entries[appKey("tenant", scope)]
	r, ok := e.Inventory.Retirement()
	if !ok || e.Down != nil || e.Standalone.Cleanup == nil || r.ID != standalonePolicyID(q) || r.Actor != e.Origin.Session.User || f.p.authorizeAppRemoval(f.s, e) != nil {
		t.Fatal("expiration did not retain original cleanup provenance")
	}
	if apps.StandaloneActivationAllowed("tenant", scope, 3602) {
		t.Fatal("expired workload remained startable")
	}
	raw, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := state.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.p.Apps(restored); err != nil {
		t.Fatal("cleanup snapshot lost original policy", err)
	}
	applyRestartCore(t, f, cmd, state.Applied)
}

// Exercise the actual app-command/FSM entrance, not only cleanup provenance.
// Native observations are declared Mock facts; this proves no Docker closure.
func TestStandaloneAcceptedCleanupAdmitsOnlyDispatchedOriginalNodeRemoval(t *testing.T) {
	f, scope := standaloneCoreFixture(t, "temp")
	managedDNSTaskCoreSubmit(t, f, scope, deployment.ResourceKey("network-ref", "tenant", scope, "lan/node-a"), true, state.Applied)
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	key := deployment.ResourceKey("task", "tenant", scope, "debug")
	start := managedDNSTaskCoreSubmit(t, f, scope, key, true, state.Applied)
	catalog, _ := f.p.Catalog(f.s)
	u, _ := catalog.User("admin")
	u.Username = "rotated-account"
	expected := u.Revision
	f.apply("cleanup-revoked-user", "put-user", expected, accountFields(u), state.Applied)
	q := standaloneReportCore(t, f, scope, "expire", "ttl", 3602)
	report, err := q.Command()
	if err != nil {
		t.Fatal(err)
	}
	applyRestartCore(t, f, report, state.Applied)
	apps, _ := f.p.Apps(f.s)
	i, _ := apps.Inventory("tenant", scope)
	retirement, ok := i.Retirement()
	m, found := i.Removal(key, "drain")
	if !ok || !found || f.p.AdmitAppMutation(f.s, m.Command) {
		t.Fatal("undispatched policy command admitted or missing original removal")
	}
	r := AppProgress{Schema: 1, Cluster: f.p.Cluster, Reporter: q.Reporter, Tenant: "tenant", App: scope, Operation: retirement.ID, Key: key, Action: "retire-send", Retire: &AppRetirementProgress{Phase: "drain"}, Expected: i.Revision(), At: 3603, Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(AppsKey).Revision, RequestID: "cleanup-original-send"}
	r.Signature = ed25519.Sign(f.node, AppProgressBytes(r))
	report, err = r.Command()
	if err != nil {
		t.Fatal(err)
	}
	applyRestartCore(t, f, report, state.Applied)
	apps, _ = f.p.Apps(f.s)
	i, _ = apps.Inventory("tenant", scope)
	m, _ = i.Removal(key, "drain")
	cmd := m.Command
	if cmd.Actor != "node/"+fmt.Sprintf("%x", q.Reporter) || !f.p.AdmitAppMutation(f.s, cmd) {
		t.Fatal("accepted exact node cleanup refused", cmd)
	}
	raw, err := state.EncodeCommand(cmd)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := f.p.ResolveAppCommand(f.s, "app-command", q.Reporter, raw)
	if err != nil || resolved != cmd {
		t.Fatal("actual dispatch entrance refused original node cleanup", err)
	}
	if _, err = f.p.ResolveAppCommand(f.s, "app-command", sha256.Sum256([]byte("foreign-owner")), raw); err == nil {
		t.Fatal("unregistered RPC caller admitted")
	}
	for _, change := range []func(*state.Command){
		func(c *state.Command) { c.Actor = "node/foreign" },
		func(c *state.Command) { c.Actor = start.Actor },
		func(c *state.Command) { c.Key += "-other" },
		func(c *state.Command) { c.Value = start.Value },
		func(c *state.Command) { c.Epoch++ },
		func(c *state.Command) { c.RequestID += "-new" },
		func(c *state.Command) { c.Expected++ },
	} {
		changed := cmd
		change(&changed)
		if f.p.AdmitAppMutation(f.s, changed) {
			t.Fatal("changed command adopted accepted cleanup", changed)
		}
	}
	start.Actor = cmd.Actor
	if f.p.AdmitAppMutation(f.s, start) {
		t.Fatal("cleanup granted node start authority")
	}
	entry := apps.entries[appKey("tenant", scope)]
	metadata := *entry.Standalone
	metadata.Cleanup = nil
	entry.Standalone = &metadata
	apps.entries[appKey("tenant", scope)] = entry
	if f.p.admitAppRemoval(f.s, apps, cmd) {
		t.Fatal("node command admitted without signed cleanup provenance")
	}
	applyRestartCore(t, f, cmd, state.Applied)
	if !f.s.Object(key).Present || f.s.Object(key).Value == start.Value {
		t.Fatal("original drain was not applied")
	}
	apps, _ = f.p.Apps(f.s)
	i, _ = apps.Inventory("tenant", scope)
	r.Action, r.RequestID = "retire-collect", "cleanup-original-collect"
	r.Expected, r.RootRevision, r.At = i.Revision(), f.s.Object(AppsKey).Revision, 3604
	r.Signature = ed25519.Sign(f.node, AppProgressBytes(r))
	report, err = r.Command()
	if err != nil {
		t.Fatal(err)
	}
	applyRestartCore(t, f, report, state.Applied)
	if f.p.AdmitAppMutation(f.s, cmd) {
		t.Fatal("settled command admitted for fresh mutation")
	}
}
func TestStandaloneExpirationRejectsEarlyTTLWrongOwnerAndNewSource(t *testing.T) {
	f, scope := standaloneCoreFixture(t, "temp")
	for _, q := range []StandalonePolicyReport{standaloneReportCore(t, f, scope, "expire", "ttl", 3601), standaloneReportCore(t, f, scope, "expire", "disconnected", 200), standaloneReportCore(t, f, scope, "restart", "", 20)} {
		if f.p.CheckStandalonePolicy(f.s, q) {
			t.Fatal("unaccepted policy effect admitted")
		}
	}
	q := standaloneReportCore(t, f, scope, "expire", "ttl", 3602)
	q.Registration = sha256.Sum256([]byte("another-origin"))
	q.Signature = ed25519.Sign(f.node, StandalonePolicyBytes(q))
	if f.p.CheckStandalonePolicy(f.s, q) {
		t.Fatal("replacement acceptance adopted")
	}
}

func TestStandaloneRemoveBeforePreparationClosesOnlyUnsubmittedInventory(t *testing.T) {
	for _, dispatched := range []bool{false, true} {
		t.Run(fmt.Sprint(dispatched), func(t *testing.T) {
			f, scope := standaloneCoreFixture(t, "temp")
			key := deployment.ResourceKey("network-ref", "tenant", scope, "lan/node-a")
			if dispatched {
				managedDNSTaskCoreProgress(t, f, scope, "prepare", key, nil)
				managedDNSTaskCoreProgress(t, f, scope, "send", key, nil)
			}
			payload, _ := json.Marshal(StandaloneChange{Tenant: "tenant", Name: "debug", Operation: "remove-before-prepare"})
			op := UserOperation{Schema: 1, Session: f.session, At: 20, Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(AppsKey).Revision, RequestID: "original-remove", Change: Change{Schema: 1, Principal: "admin", Action: "standalone-remove", Expected: 1, Payload: payload}}
			op.Signature = ed25519.Sign(f.admin, OperationBytes(op))
			cmd, err := op.Command()
			if err != nil {
				t.Fatal(err)
			}
			applyRestartCore(t, f, cmd, state.Applied)
			a, _ := f.p.Apps(f.s)
			i, _ := a.Inventory("tenant", scope)
			r, ok := i.Retirement()
			if !ok || len(i.Claims()) != 0 || len(r.Targets) != 0 {
				t.Fatal("original empty retirement was not retained")
			}
			report := AppProgress{Schema: 1, Cluster: f.p.Cluster, Reporter: [32]byte(f.node.Public().(ed25519.PublicKey)), Tenant: "tenant", App: scope, Operation: r.ID, Action: "retire-finish", Retire: &AppRetirementProgress{}, Expected: i.Revision(), At: 21, Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(AppsKey).Revision, RequestID: "original-empty-finish"}
			report.Signature = ed25519.Sign(f.node, AppProgressBytes(report))
			cmd, err = report.Command()
			if err != nil {
				t.Fatal(err)
			}
			want := state.Applied
			if dispatched {
				want = state.ConditionFailed
			}
			applyRestartCore(t, f, cmd, want)
			a, _ = f.p.Apps(f.s)
			i, _ = a.Inventory("tenant", scope)
			if i.Quiescent() == dispatched {
				t.Fatal("unfinished original dispatch was confused with no submission")
			}
			if dispatched {
				x, _ := i.Execution()
				s, _ := x.Stage(key)
				if s.Command == nil || s.Result != nil || s.Journal.Pending == nil {
					t.Fatal("unknown original command/receipt reference was discarded")
				}
			}
		})
	}
}
func TestStandalonePinPreservesInventoryAndInternalScope(t *testing.T) {
	f, scope := standaloneCoreFixture(t, "temp")
	a, _ := f.p.Apps(f.s)
	before, _ := a.Inventory("tenant", scope)
	original, _ := before.Encode()
	payload, _ := json.Marshal(StandaloneChange{Tenant: "tenant", Name: "debug", NewName: "kept", Operation: "pin-original"})
	op := UserOperation{Schema: 1, Session: f.session, At: 10, Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(AppsKey).Revision, RequestID: "pin-request", Change: Change{Schema: 1, Principal: "admin", Action: "standalone-pin", Expected: 1, Payload: payload}}
	op.Signature = ed25519.Sign(f.admin, OperationBytes(op))
	cmd, err := op.Command()
	if err != nil {
		t.Fatal(err)
	}
	applyRestartCore(t, f, cmd, state.Applied)
	a, err = f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := a.StandaloneScope("tenant", "kept")
	if !ok || got != scope {
		t.Fatal("public rename changed native owner scope")
	}
	after, _ := a.Inventory("tenant", scope)
	encoded, _ := after.Encode()
	if !bytes.Equal(original, encoded) {
		t.Fatal("pin changed Task/writable-layer inventory")
	}
	m := a.entries[appKey("tenant", scope)].Standalone
	if m.Lifetime != "fixed" || m.ExpiresAt != 0 || m.GraceSeconds != 0 || m.Restart != "on-failure" {
		t.Fatal("pin retained temporary policy")
	}
	target := containerops.Target{Tenant: "tenant", App: scope, Service: "debug", Instance: "original-task", Standalone: "debug"}
	selection, err := f.p.ContainerSessionSelection(f.s, target)
	if err != nil || selection.Standalone != "kept" || selection.App != "" || selection.Service != target.Service || selection.Instance != target.Instance || !selection.Valid() {
		t.Fatal("session lost standalone kind or exact Task after public rename", selection, err)
	}
	target.Tenant = "foreign"
	if _, err = f.p.ContainerSessionSelection(f.s, target); err == nil {
		t.Fatal("foreign tenant reused original standalone scope")
	}
}
func TestStandaloneLifetimeDefaultsAndSeparateQuotas(t *testing.T) {
	m, err := (StandaloneDefinition{Name: "debug"}).metadata("tenant", "user", "node", 100)
	if err != nil || m.ExpiresAt != 3700 || m.GraceSeconds != 600 || m.Restart != "no" {
		t.Fatal(m, err)
	}
	for _, d := range []StandaloneDefinition{{Name: "debug", TTLSeconds: 86401}, {Name: "debug", TTLSeconds: -1}, {Name: "debug", Lifetime: "fixed", TTLSeconds: 1}, {Name: "debug", Lifetime: "temp", Restart: "always"}} {
		if _, err := d.metadata("tenant", "user", "node", 100); err == nil {
			t.Fatal("invalid lifetime admitted", d)
		}
	}
}

func TestStandaloneConnectionGraceRequiresAnActualDisconnect(t *testing.T) {
	f, scope := standaloneCoreFixture(t, "temp")
	sample := func(at int64, count int, disconnected int64) {
		q := standaloneReportCore(t, f, scope, "connections", "", at)
		q.Connections = count
		q.DisconnectedAt = disconnected
		q.Signature = ed25519.Sign(f.node, StandalonePolicyBytes(q))
		cmd, err := q.Command()
		if err != nil {
			t.Fatal(err)
		}
		applyRestartCore(t, f, cmd, state.Applied)
	}
	sample(10, 0, 0)
	q := standaloneReportCore(t, f, scope, "expire", "disconnected", 700)
	if f.p.CheckStandalonePolicy(f.s, q) {
		t.Fatal("never-attached entrypoint used disconnection grace")
	}
	// A complete quick attach/detach between heartbeat samples carries the
	// owner's positive disconnect timestamp, rather than losing that event.
	sample(20, 0, 19)
	q = standaloneReportCore(t, f, scope, "expire", "disconnected", 618)
	if f.p.CheckStandalonePolicy(f.s, q) {
		t.Fatal("grace shortened")
	}
	q = standaloneReportCore(t, f, scope, "expire", "disconnected", 619)
	if !f.p.CheckStandalonePolicy(f.s, q) {
		t.Fatal("original disconnect was not consumed")
	}
	sample(30, 1, 0)
	q = standaloneReportCore(t, f, scope, "expire", "disconnected", 700)
	if f.p.CheckStandalonePolicy(f.s, q) {
		t.Fatal("reconnection did not cancel grace")
	}
}

// Counting consumes declared accepted metadata and actual product inventories;
// these cases do not claim admission, Docker creation, or native retirement.
func TestStandaloneQuotaCountsUserTenantAndNodeIndependently(t *testing.T) {
	makeApps := func(tenant, creator, node, lifetime string, count int) Apps {
		a := Apps{entries: map[string]appEntry{}}
		for i := 0; i < count; i++ {
			name := fmt.Sprintf("quota-%d", i)
			m, err := (StandaloneDefinition{Name: name, Lifetime: lifetime}).metadata(tenant, creator, node, 2)
			if err != nil {
				t.Fatal(err)
			}
			inventory, err := deployment.NewInventory([32]byte{1}, tenant, m.Scope, "deploy")
			if err != nil {
				t.Fatal(err)
			}
			a.entries[appKey(tenant, m.Scope)] = appEntry{Standalone: &m, Inventory: inventory}
		}
		return a
	}
	check := func(a Apps, tenant, user, node, lifetime, want string) {
		t.Helper()
		err := standaloneQuota(a, tenant, user, node, lifetime)
		var input *deployment.InputError
		if want == "" && err != nil || want != "" && (!errors.As(err, &input) || input.Code != want) {
			t.Fatal("independent quota result", tenant, user, node, lifetime, want, err)
		}
	}
	a := makeApps("tenant", "creator", "node-a", "temp", StandaloneTempLimitUser-1)
	check(a, "tenant", "creator", "node-a", "temp", "")
	a = makeApps("tenant", "creator", "node-a", "temp", StandaloneTempLimitUser)
	check(a, "tenant", "creator", "node-a", "temp", "STANDALONE_USER_LIMIT")
	check(a, "tenant", "other", "node-a", "temp", "")
	check(a, "tenant", "creator", "node-a", "fixed", "")
	a = makeApps("tenant", "creator", "node-a", "fixed", StandaloneLimitTenant)
	check(a, "tenant", "other", "node-b", "temp", "STANDALONE_TENANT_LIMIT")
	check(a, "foreign", "other", "node-b", "temp", "")
	a = makeApps("foreign", "creator", "node-a", "fixed", StandaloneLimitNode)
	check(a, "tenant", "other", "node-a", "fixed", "STANDALONE_NODE_LIMIT")
	check(a, "tenant", "other", "node-b", "fixed", "")
	for key, e := range a.entries {
		e.Standalone = nil // Ordinary apps do not consume standalone count quotas.
		a.entries[key] = e
	}
	check(a, "foreign", "creator", "node-a", "temp", "")
}
