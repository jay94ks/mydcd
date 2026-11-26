// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/containerops"
	"github.com/jay94ks/mydcd/internal/deployment"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"

	"gopkg.in/yaml.v3"
)

func signedStandaloneCAS(t *testing.T, f *backupCoreFixture, action, id string, expected, root uint64, payload any, targeted bool) (UserOperation, state.Command) {
	t.Helper()
	raw, err := ChangeBytes(action, "admin", expected, payload)
	if err != nil {
		t.Fatal(err)
	}
	var change Change
	if err = json.Unmarshal(raw, &change); err != nil {
		t.Fatal(err)
	}
	op := UserOperation{Schema: 1, Session: f.session, At: 11, Epoch: f.s.ModuleEpoch(), RootRevision: root, RequestID: id, Change: change}
	op.Signature = ed25519.Sign(f.admin, OperationBytes(op))
	command, err := op.Command()
	if err != nil {
		t.Fatal(err)
	}
	return op, command
}

func standaloneCASConnections(t *testing.T, f *backupCoreFixture, scope string, at int64) {
	t.Helper()
	report := standaloneReportCore(t, f, scope, "connections", "", at)
	report.Connections = 1
	report.Signature = ed25519.Sign(f.node, StandalonePolicyBytes(report))
	command, err := report.Command()
	if err != nil {
		t.Fatal(err)
	}
	applyRestartCore(t, f, command, state.Applied)
}

func standaloneCASNativeObservation(t *testing.T, f *backupCoreFixture, scope, task string, at uint64) {
	t.Helper()
	apps, _ := f.p.Apps(f.s)
	inventory, _ := apps.Inventory("tenant", scope)
	execution, _ := inventory.Execution()
	stage, _ := execution.Stage(task)
	observation := *stage.Observation
	observation.At, observation.Sequence = at, observation.Sequence+1
	observation.Signature = ed25519.Sign(f.node, deployment.ObservationBytes(observation))
	report := AppProgress{Schema: 1, Cluster: f.p.Cluster, Reporter: observation.Owner, Tenant: "tenant", App: scope, Operation: execution.ActiveOperation(), Key: task, Action: "observe", Observation: &observation, Expected: inventory.Revision(), At: at, Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(AppsKey).Revision, RequestID: fmt.Sprintf("standalone-native-observation-%d", at)}
	report.Signature = ed25519.Sign(f.node, AppProgressBytes(report))
	command, err := report.Command()
	if err != nil {
		t.Fatal(err)
	}
	applyRestartCore(t, f, command, state.Applied)
}

func TestStandaloneManagementCASPreservesOriginalAcrossConnectionAndUnrelatedReports(t *testing.T) {
	for _, action := range []string{"standalone-pin", "standalone-remove"} {
		t.Run(action, func(t *testing.T) {
			f, scope := standaloneCoreFixture(t, "temp")
			apps, _ := f.p.Apps(f.s)
			entry := apps.entries[appKey("tenant", scope)]
			target := entry.standaloneTarget()
			root, expected := f.s.Object(AppsKey).Revision, entry.Standalone.Revision
			q := StandaloneChange{Tenant: "tenant", Name: "debug", Operation: "same-original", Target: &target}
			op, command := signedStandaloneCAS(t, f, action, "original-management", expected, root, q, true)
			legacy := q
			legacy.Target = nil
			_, strict := signedStandaloneCAS(t, f, action, "legacy-root", expected, root, legacy, false)
			standaloneCASConnections(t, f, scope, 12)
			apps, _ = f.p.Apps(f.s)
			advanced := apps.entries[appKey("tenant", scope)]
			if advanced.Standalone.Revision <= expected || advanced.standaloneTarget() != target {
				t.Fatal("connection observation changed management intent or failed to advance its revision")
			}
			applyDownCAS(t, f, strict, state.ConditionFailed)
			_, strictMetadata := signedStandaloneCAS(t, f, action, "legacy-metadata", expected, f.s.Object(AppsKey).Revision, legacy, false)
			applyDownCAS(t, f, strictMetadata, state.ConditionFailed)
			managedDNSTaskCoreBegin(t, f, "unrelated", "10.80.1.41", "unrelated")
			result := applyDownCAS(t, f, command, state.Applied)
			apps, err := f.p.Apps(f.s)
			entry = apps.entries[appKey("tenant", scope)]
			stored := entry.Down
			if action == "standalone-pin" {
				stored = entry.Standalone.LastChange
			}
			original, _ := json.Marshal(op)
			retained, _ := json.Marshal(stored)
			if err != nil || command.Kind != state.ModuleAppCAS || !bytes.Equal(original, retained) || entry.standaloneTarget() == target {
				t.Fatal("accepted management intent lost its original operation or failed to advance target", err)
			}
			raw, err := state.Encode(f.s)
			if err != nil {
				t.Fatal(err)
			}
			f.s, err = state.Decode(raw)
			if err != nil || applyDownCAS(t, f, command, state.Applied) != result {
				t.Fatal("snapshot/replay replaced original standalone receipt", err)
			}
		})
	}
}

func TestStandaloneManagementCASRejectsStaleIntentFutureCoordinatesAndCurrentRevocation(t *testing.T) {
	for _, mode := range []string{"target", "future-metadata", "future-root", "foreign", "pin-intent", "cleanup", "credential"} {
		t.Run(mode, func(t *testing.T) {
			f, scope := standaloneCoreFixture(t, "temp")
			apps, _ := f.p.Apps(f.s)
			entry := apps.entries[appKey("tenant", scope)]
			target := entry.standaloneTarget()
			q := StandaloneChange{Tenant: "tenant", Name: "debug", Operation: "refused-remove", Target: &target}
			root, expected, want := f.s.Object(AppsKey).Revision, entry.Standalone.Revision, state.ConditionFailed
			switch mode {
			case "target":
				target[0] ^= 1
			case "future-metadata":
				expected += 100
			case "future-root":
				root += 100
			case "foreign":
				q.Tenant = "foreign"
				f.session.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read, access.Deploy}}}
				f.session.Signature = ed25519.Sign(f.node, access.SessionBytes(f.session))
				want = state.Forbidden
			}
			_, command := signedStandaloneCAS(t, f, "standalone-remove", "stale-management", expected, root, q, true)
			switch mode {
			case "pin-intent":
				_, pin := signedStandaloneCAS(t, f, "standalone-pin", "competing-pin", expected, root, StandaloneChange{Tenant: "tenant", Name: "debug", Operation: "pin-first", Target: &target}, true)
				applyDownCAS(t, f, pin, state.Applied)
			case "cleanup":
				report := standaloneReportCore(t, f, scope, "expire", "ttl", 3602)
				cleanup, err := report.Command()
				if err != nil {
					t.Fatal(err)
				}
				applyRestartCore(t, f, cleanup, state.Applied)
			case "credential":
				catalog, _ := f.p.Catalog(f.s)
				account, _ := catalog.User("admin")
				expected := account.Revision
				account.Revision = 0
				// Preserve a usable account credential while revoking the exact
				// key in the already signed original operation/session.
				recovery := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{144}, ed25519.SeedSize))
				account.Credentials = append(account.Credentials, access.Credential{ID: "recovery-key", Method: access.PrivateKey, PublicKey: [32]byte(recovery.Public().(ed25519.PublicKey)), Enabled: true})
				clear(recovery)
				account.Credentials[0].Enabled = false
				f.apply("disable-original-credential", "put-user", expected, account, state.Applied)
				want = state.Forbidden
			}
			before := f.s.Object(AppsKey)
			applyDownCAS(t, f, command, want)
			if f.s.Object(AppsKey) != before {
				t.Fatal("refused standalone management changed its shared source")
			}
		})
	}
}

// The same accepted Inventory, Task mutation, binding, signed owner observation
// and finish boundary used by app tests supplies a real core control target.
// These are declared adapter facts; no Docker or transport pass is claimed.
func standaloneNativeCASFixture(t *testing.T) (*backupCoreFixture, string, string) {
	t.Helper()
	f, scope := standaloneCoreFixture(t, "temp")
	managedDNSTaskCoreSubmit(t, f, scope, deployment.ResourceKey("network-ref", "tenant", scope, "lan/node-a"), true, state.Applied)
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	task := deployment.ResourceKey("task", "tenant", scope, "debug")
	managedDNSTaskCoreSubmit(t, f, scope, task, true, state.Applied)
	managedDNSTaskCoreProgress(t, f, scope, "bind-inputs", task, nil)
	apps, _ := f.p.Apps(f.s)
	execution, _ := apps.Execution("tenant", scope)
	stage, _ := execution.Stage(task)
	observation := *stage.Observation
	boot := sha256.Sum256([]byte("standalone-cas-owner-boot"))
	observation.OwnerBoot, observation.LogDriver, observation.StartedAt = hex.EncodeToString(boot[:]), "local", 2_000_000_000
	observation.Sequence++
	observation.Signature = ed25519.Sign(f.node, deployment.ObservationBytes(observation))
	managedDNSTaskCoreProgress(t, f, scope, "observe", task, &observation)
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	managedDNSTaskCoreProgress(t, f, scope, "finish", "", nil)
	return f, scope, task
}

func uploadStandaloneCASPlan(t *testing.T, f *backupCoreFixture, scope, name, upload string, changeDefinition bool) AppBegin {
	t.Helper()
	apps, _ := f.p.Apps(f.s)
	entry := apps.entries[appKey("tenant", scope)]
	execution, _ := entry.Inventory.Execution()
	document := execution.Blueprint().OriginalDocument()
	raw := document.Body
	if changeDefinition {
		input, err := deployment.ParseStandalone(raw)
		if err != nil {
			t.Fatal(err)
		}
		service := input.Services["debug"]
		service.Environment = deployment.Environment{"DEFINITION": upload}
		input.Services["debug"] = service
		raw, err = yaml.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
	}
	planning, err := f.p.AppPlanning(f.s, "admin", "tenant")
	if err != nil {
		t.Fatal(err)
	}
	planning.Project, planning.Deployment = scope, "deploy"
	catalog, _ := f.p.Catalog(f.s)
	plan, err := deployment.CompileStandaloneDocument(raw, name, catalog, planning, "shell")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := plan.Encode()
	if err != nil {
		t.Fatal(err)
	}
	f.apply(upload+"-begin", "begin-app-upload", 0, AppUploadBegin{Tenant: "tenant", App: scope, Deployment: "deploy", ID: upload, Length: len(encoded), Digest: sha256.Sum256(encoded)}, state.Applied)
	for index, start := 0, 0; start < len(encoded); index, start = index+1, start+deployment.ArtifactPartBytes {
		f.apply(fmt.Sprintf("%s-part-%d", upload, index), "put-app-part", uint64(index+1), AppUploadPart{Tenant: "tenant", ID: upload, Index: index, Data: encoded[start:min(len(encoded), start+deployment.ArtifactPartBytes)]}, state.Applied)
	}
	target := entry.standaloneTarget()
	return AppBegin{Standalone: &StandaloneDefinition{Name: name, Lifetime: "temp", Mode: "shell"}, Target: &target, Tenant: "tenant", App: scope, Deployment: "deploy", Upload: upload, Operation: upload}
}

func TestStandaloneUpCASUsesSameTargetForKeepAndRejectsCompetingDefinition(t *testing.T) {
	for _, compete := range []bool{false, true} {
		t.Run(fmt.Sprintf("competing-definition-%t", compete), func(t *testing.T) {
			f, scope, task := standaloneNativeCASFixture(t)
			q := uploadStandaloneCASPlan(t, f, scope, "debug", "keep-original", false)
			var other AppBegin
			if compete {
				other = uploadStandaloneCASPlan(t, f, scope, "debug", "definition-first", true)
			}
			apps, _ := f.p.Apps(f.s)
			entry := apps.entries[appKey("tenant", scope)]
			view, _, err := f.p.StandalonePage(f.s, f.session, 11, "tenant", "debug", "")
			if err != nil || len(view) != 1 || view[0].Target != *q.Target || view[0].Workload.BeginTarget == nil || *view[0].Workload.BeginTarget != *q.Target {
				t.Fatal("standalone page and existing compose begin consumer disagree", err)
			}
			root, expected := f.s.Object(AppsKey).Revision, entry.Inventory.Revision()
			op, command := signedStandaloneCAS(t, f, "standalone-up", "keep-original", expected, root, q, true)
			standaloneCASConnections(t, f, scope, 12)
			before := f.s.Object(task)
			if compete {
				apps, _ = f.p.Apps(f.s)
				bindings := apps.bindings.Live()
				if len(bindings) != 1 {
					t.Fatal("missing original standalone binding")
				}
				digest := bindings[0].Digest()
				source, found := apps.BindingSource(digest)
				if !found || source.Task.Key != task {
					t.Fatal("missing original standalone binding source")
				}
				originalSource, _ := json.Marshal(source)
				_, first := signedStandaloneCAS(t, f, "standalone-up", "definition-first", expected, root, other, true)
				applyDownCAS(t, f, first, state.Applied)
				apps, _ = f.p.Apps(f.s)
				entry = apps.entries[appKey("tenant", scope)]
				execution, active := entry.Inventory.Execution()
				replacement, replacing := execution.Replacement()
				retirement, retiring := entry.Inventory.Retirement()
				if !active || !replacing || replacement.Phase != "retiring" || replacement.Node != "node-a" || replacement.Waves != 1 || !retiring || !retirement.KeepExecution || retirement.Down {
					t.Fatal("same-node standalone definition change did not start original replacement retirement", replacement, retirement)
				}
				selected := false
				for _, target := range retirement.Targets {
					if target.Original.Step.Key == task {
						selected = true
						if target.Closed || target.Original.Result.Generation != before.Generation || target.Original.Result.Revision != before.Revision {
							t.Fatal("replacement lost original Task or fabricated its closure")
						}
					}
				}
				source, found = apps.BindingSource(digest)
				retainedSource, _ := json.Marshal(source)
				if !selected || !found || !bytes.Equal(originalSource, retainedSource) || len(apps.bindings.Live()) != 1 {
					t.Fatal("replacement released or adopted original Task binding before positive closure")
				}
				applyDownCAS(t, f, command, state.ConditionFailed)
			} else {
				result := applyDownCAS(t, f, command, state.Applied)
				apps, _ = f.p.Apps(f.s)
				entry = apps.entries[appKey("tenant", scope)]
				original, _ := json.Marshal(op)
				retained, _ := json.Marshal(entry.Origin)
				if !bytes.Equal(original, retained) || entry.standaloneTarget() == *q.Target || applyDownCAS(t, f, command, state.Applied) != result {
					t.Fatal("Keep replaced its original signed acceptance/result")
				}
			}
			if f.s.Object(task) != before {
				t.Fatal("up acceptance wrote or adopted a native Task directly")
			}
		})
	}
}

func TestStandaloneUpCreateCASPreservesAbsence(t *testing.T) {
	for _, targeted := range []bool{true} {
		t.Run(fmt.Sprintf("targeted-%t", targeted), func(t *testing.T) {
			f, scope := standaloneCoreFixture(t, "temp")
			q := uploadStandaloneCASPlan(t, f, scope, "debug", "create-original", false)
			// The declared fixture inventory supplied compiler input only. Remove
			// it before ANY Goal dispatch; the actual creation below consumes the
			// completed upload through the original typed reducer's absence gate.
			apps, _ := f.p.Apps(f.s)
			delete(apps.entries, appKey("tenant", scope))
			checkpointStandaloneDNSFixture(t, f, apps)
			absence := AppCreateTarget(f.p.Cluster, q.Tenant, q.App, q.Deployment)
			q.Target = &absence
			op, command := signedStandaloneCAS(t, f, "standalone-up", "create-original", 0, f.s.Object(AppsKey).Revision, q, targeted)
			managedDNSTaskCoreBegin(t, f, "unrelated", "10.80.1.41", "unrelated")
			result := applyDownCAS(t, f, command, state.Applied)
			apps, err := f.p.Apps(f.s)
			entry, found := apps.entries[appKey("tenant", scope)]
			if err != nil || !found || entry.Standalone == nil || entry.Standalone.Scope != scope || StandaloneCASAllowed(entry.Origin.Change) != targeted || entry.Origin.RequestID != op.RequestID {
				t.Fatal("standalone create lost original owner kind/acceptance", err)
			}
			raw, err := state.Encode(f.s)
			if err != nil {
				t.Fatal(err)
			}
			f.s, err = state.Decode(raw)
			if err != nil || applyDownCAS(t, f, command, state.Applied) != result {
				t.Fatal("standalone create original receipt changed across restore", err)
			}
		})
	}
}

func TestStandaloneControlCASPreservesExactNativeAcrossConnectionReports(t *testing.T) {
	for _, action := range []string{"standalone-stop", "standalone-start", "standalone-restart"} {
		t.Run(action, func(t *testing.T) {
			f, scope, task := standaloneNativeCASFixture(t)
			selection := containerops.Selection{Standalone: "debug"}
			plan, err := f.p.PlanTaskControl(f.s, f.session, 11, "tenant", selection, action)
			if err != nil || !plan.Valid() || plan.ManagementTarget == nil {
				t.Fatal("new standalone control plan", err)
			}
			q := TaskRestartChange{Standalone: "debug", Tenant: "tenant", Operation: "control-original", Target: plan.Target, ManagementTarget: plan.ManagementTarget}
			op, command := signedStandaloneCAS(t, f, action, "control-original", plan.StandaloneRevision, f.s.Object(AppsKey).Revision, q, true)
			legacyPlan := plan
			legacyPlan.ManagementTarget = nil
			legacyPlan.Target = taskRestartTarget(legacyPlan)
			legacy := q
			legacy.ManagementTarget, legacy.Target = nil, legacyPlan.Target
			_, strict := signedStandaloneCAS(t, f, action, "legacy-control", plan.StandaloneRevision, f.s.Object(AppsKey).Revision, legacy, false)
			standaloneCASConnections(t, f, scope, 12)
			standaloneCASNativeObservation(t, f, scope, task, 13)
			if _, err := f.p.PlanTaskControl(f.s, f.session, op.At, "tenant", selection, action); err == nil {
				t.Fatal("ordinary planning accepted an observation from after its query time")
			}
			fresh, err := f.p.PlanTaskControl(f.s, f.session, 14, "tenant", selection, action)
			if err != nil || fresh.Target != plan.Target || fresh.StandaloneRevision <= plan.StandaloneRevision {
				t.Fatal("connection report changed the new control hash", err)
			}
			applyDownCAS(t, f, strict, state.ConditionFailed)
			before := f.s.Object(task)
			result := applyDownCAS(t, f, command, state.Applied)
			apps, err := f.p.Apps(f.s)
			row, found := apps.TaskRestart("tenant", scope, q.Operation)
			if err != nil || !found || row.Plan.Container != plan.Container || row.Plan.OwnerBoot != plan.OwnerBoot || row.Plan.StandaloneRevision != op.Change.Expected || StandaloneCASAllowed(row.Origin.Change) != true || f.s.Object(task) != before {
				t.Fatal("new standalone control replaced original coordinates/native", err)
			}
			raw, err := state.Encode(f.s)
			if err != nil {
				t.Fatal(err)
			}
			f.s, err = state.Decode(raw)
			if err != nil || applyDownCAS(t, f, command, state.Applied) != result {
				t.Fatal("new control original plan/receipt did not restore", err)
			}
		})
	}
}

func TestStandaloneControlCASRejectsForeignManagementNativeAndFutureOrdinals(t *testing.T) {
	for _, mode := range []string{"management", "native", "started", "boot", "future-metadata", "future-root", "pin-intent", "credential", "stale-observation"} {
		t.Run(mode, func(t *testing.T) {
			f, scope, _ := standaloneNativeCASFixture(t)
			plan, err := f.p.PlanTaskControl(f.s, f.session, 11, "tenant", containerops.Selection{Standalone: "debug"}, "standalone-restart")
			if err != nil {
				t.Fatal(err)
			}
			root, expected, want := f.s.Object(AppsKey).Revision, plan.StandaloneRevision, state.ConditionFailed
			switch mode {
			case "management":
				management := *plan.ManagementTarget
				management[0] ^= 1
				plan.ManagementTarget = &management
			case "native":
				plan.Container.NativeID = "foreign-native"
			case "started":
				plan.Container.StartedAt = "1970-01-01T00:00:03Z"
			case "boot":
				plan.OwnerBoot = "foreign-boot"
			case "future-metadata":
				expected += 100
			case "future-root":
				root += 100
			}
			plan.Target = taskRestartTarget(plan)
			q := TaskRestartChange{Standalone: "debug", Tenant: "tenant", Operation: "refused-control", Target: plan.Target, ManagementTarget: plan.ManagementTarget}
			op, command := signedStandaloneCAS(t, f, "standalone-restart", "refused-control", expected, root, q, true)
			if mode == "stale-observation" {
				f.s = expireAll(t, f.p, f.s, f.node, 1000)
				op.At = 1000
				op.Signature = ed25519.Sign(f.admin, OperationBytes(op))
				command, err = op.Command()
				if err != nil {
					t.Fatal(err)
				}
			}
			if mode == "pin-intent" {
				apps, _ := f.p.Apps(f.s)
				entry := apps.entries[appKey("tenant", scope)]
				target := entry.standaloneTarget()
				_, pin := signedStandaloneCAS(t, f, "standalone-pin", "native-competing-pin", expected, root, StandaloneChange{Tenant: "tenant", Name: "debug", Operation: "pin-first", Target: &target}, true)
				applyDownCAS(t, f, pin, state.Applied)
			}
			if mode == "credential" {
				catalog, _ := f.p.Catalog(f.s)
				account, _ := catalog.User("admin")
				expected := account.Revision
				account.Revision = 0
				recovery := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{144}, ed25519.SeedSize))
				account.Credentials = append(account.Credentials, access.Credential{ID: "recovery-key", Method: access.PrivateKey, PublicKey: [32]byte(recovery.Public().(ed25519.PublicKey)), Enabled: true})
				clear(recovery)
				account.Credentials[0].Enabled = false
				f.apply("control-revoke-credential", "put-user", expected, account, state.Applied)
				want = state.Forbidden
			}
			before := f.s.Object(AppsKey)
			applyDownCAS(t, f, command, want)
			if f.s.Object(AppsKey) != before {
				t.Fatal("refused control changed native ownership or accepted intent")
			}
		})
	}
}

func TestStandaloneLegacyControlKeepsHistoricalPlanHashAndReceipt(t *testing.T) {
	f, scope, _ := standaloneNativeCASFixture(t)
	plan, err := f.p.PlanTaskControl(f.s, f.session, 11, "tenant", containerops.Selection{Standalone: "debug"}, "standalone-stop")
	if err != nil {
		t.Fatal(err)
	}
	plan.ManagementTarget = nil
	plan.Target = taskRestartTarget(plan)
	// Exact pre-extension JSON layout, including its optional legacy ordinal.
	old := struct {
		Action                                              checker.ContainerAction `json:",omitempty"`
		StandaloneRevision                                  uint64                  `json:",omitempty"`
		Schema                                              uint8
		Tenant, App                                         string
		InventoryRevision                                   uint64
		Target                                              [32]byte
		Registration                                        [32]byte
		Container                                           containerops.Target
		OwnerBoot                                           string
		StopGraceSeconds                                    int
		PreserveNative, PreserveWritableLayer, PreserveLogs bool
	}{plan.Action, plan.StandaloneRevision, plan.Schema, plan.Tenant, plan.App, 0, [32]byte{}, plan.Registration, plan.Container, plan.OwnerBoot, plan.StopGraceSeconds, plan.PreserveNative, plan.PreserveWritableLayer, plan.PreserveLogs}
	raw, _ := json.Marshal(old)
	if plan.Target != sha256.Sum256(append([]byte("mydc-task-restart-target-1\x00"), raw...)) {
		t.Fatal("nil management target changed the historical standalone hash")
	}
	q := TaskRestartChange{Standalone: "debug", Tenant: "tenant", Operation: "legacy-stop", Target: plan.Target}
	_, command := signedStandaloneCAS(t, f, "standalone-stop", "legacy-stop", plan.StandaloneRevision, f.s.Object(AppsKey).Revision, q, false)
	result := applyDownCAS(t, f, command, state.Applied)
	apps, err := f.p.Apps(f.s)
	row, found := apps.TaskRestart("tenant", scope, q.Operation)
	if err != nil || !found || row.Plan.ManagementTarget != nil || StandaloneCASAllowed(row.Origin.Change) || row.Plan.Target != plan.Target {
		t.Fatal("legacy control silently selected the new plan", err)
	}
	encoded, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	f.s, err = state.Decode(encoded)
	if err != nil || applyDownCAS(t, f, command, state.Applied) != result {
		t.Fatal("legacy control receipt changed after restore", err)
	}
}

func TestStandaloneTargetTracksAcceptedControlsAndNotTheirProgress(t *testing.T) {
	for _, kind := range []string{"restart", "clear"} {
		t.Run(kind, func(t *testing.T) {
			f, scope, _ := standaloneNativeCASFixture(t)
			apps, _ := f.p.Apps(f.s)
			entry := apps.entries[appKey("tenant", scope)]
			before := entry.standaloneTarget()
			_, staleRemove := signedStandaloneCAS(t, f, "standalone-remove", "before-control", entry.Standalone.Revision, f.s.Object(AppsKey).Revision, StandaloneChange{Tenant: "tenant", Name: "debug", Operation: "stale-remove", Target: &before}, true)
			selection := containerops.Selection{Standalone: "debug"}
			if kind == "restart" {
				plan, err := f.p.PlanTaskControl(f.s, f.session, 11, "tenant", selection, "standalone-restart")
				if err != nil {
					t.Fatal(err)
				}
				q := TaskRestartChange{Standalone: "debug", Tenant: "tenant", Operation: "accepted-restart", Target: plan.Target, ManagementTarget: plan.ManagementTarget}
				_, command := signedStandaloneCAS(t, f, "standalone-restart", "accepted-restart", plan.StandaloneRevision, f.s.Object(AppsKey).Revision, q, true)
				applyDownCAS(t, f, command, state.Applied)
			} else {
				plan, err := f.p.PlanAppLogClear(f.s, f.session, 11, "tenant", selection)
				if err != nil {
					t.Fatal(err)
				}
				q := AppLogClear{Standalone: "debug", Tenant: "tenant", App: scope, Operation: "accepted-clear", Target: plan.Target, Recreate: true}
				_, command := signedStandaloneCAS(t, f, "standalone-clear-logs", "accepted-clear", plan.InventoryRevision, f.s.Object(AppsKey).Revision, q, false)
				applyDownCAS(t, f, command, state.Applied)
			}
			apps, _ = f.p.Apps(f.s)
			entry = apps.entries[appKey("tenant", scope)]
			accepted := entry.standaloneTarget()
			if accepted == before {
				t.Fatal("accepted native intent did not invalidate earlier management target")
			}
			applyDownCAS(t, f, staleRemove, state.ConditionFailed)
			// Isolate the actual hash projection's progress exclusions. These
			// copies are not forged reducer reports or claimed native outcomes.
			if kind == "restart" {
				row := entry.TaskRestarts[0]
				row.Revision++
				row.At++
				control, err := row.InitialControl()
				if err != nil {
					t.Fatal(err)
				}
				row.Control = &control
				entry.TaskRestarts = []TaskRestartRecord{row}
			} else {
				pending := *entry.PendingSync
				recreation := *pending.Recreate
				recreation.Closure[0] ^= 1
				pending.Recreate = &recreation
				entry.PendingSync = &pending
				if entry.standaloneTarget() != accepted {
					t.Fatal("clear closure progress changed accepted management intent")
				}
				entry.PendingSync, entry.Sync = nil, &pending
				entry.LogClears = []AppLogClearRecord{{Origin: entry.Origin, Source: pending, Status: "succeeded", Replacements: []AppLogClearImpact{{NativeID: "reported-replacement"}}}}
			}
			if entry.standaloneTarget() != accepted {
				t.Fatal("native progress or pending-to-history movement changed target")
			}
		})
	}
}
