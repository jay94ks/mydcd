// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/deployment"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
	"strings"
	"testing"
	"time"
)

func restartCoreFixture(t *testing.T) (*backupCoreFixture, deployment.Observation, containerops.Selection) {
	t.Helper()
	f, o, selection := logClearPlanFixture(t, "local")
	boot := sha256.Sum256([]byte("restart-owner-boot"))
	o.OwnerBoot = hex.EncodeToString(boot[:])
	o.Sequence++
	o.Signature = ed25519.Sign(f.node, deployment.ObservationBytes(o))
	managedDNSTaskCoreProgress(t, f, "source-app", "observe", o.Key, &o)
	return f, o, selection
}
func applyRestartCore(t *testing.T, f *backupCoreFixture, cmd state.Command, want state.Code) {
	t.Helper()
	next, result, err := state.ApplyTransactional(f.s, f.s.Index()+1, cmd, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
	if err != nil || result.Code != want {
		t.Fatal("restart core", result, want, err)
	}
	f.s = next
}
func acceptRestartCore(t *testing.T, f *backupCoreFixture, plan TaskRestartPlan) state.Command {
	t.Helper()
	q := TaskRestartChange{Tenant: "tenant", App: "source-app", Operation: "restart-web", Target: plan.Target}
	q.Selection.Service = "web"
	raw, _ := json.Marshal(q)
	op := UserOperation{Schema: 1, Session: f.session, At: 10, Epoch: f.s.ModuleEpoch(), RequestID: "restart-web", RootRevision: f.s.Object(AppsKey).Revision, Change: Change{Schema: 1, Principal: "admin", Action: "restart-task", Expected: plan.InventoryRevision, Payload: raw}}
	op.Signature = ed25519.Sign(f.admin, OperationBytes(op))
	cmd, err := op.Command()
	if err != nil {
		t.Fatal(err)
	}
	applyRestartCore(t, f, cmd, state.Applied)
	return cmd
}
func restartReportCore(t *testing.T, f *backupCoreFixture, row TaskRestartRecord, c checker.ContainerControl) state.Command {
	t.Helper()
	r := TaskRestartReport{Schema: 1, Kind: "task-restart", Cluster: f.p.Cluster, Reporter: row.Plan.Container.Owner, Tenant: "tenant", App: "source-app", Operation: "restart-web", Expected: row.Revision, RootRevision: f.s.Object(AppsKey).Revision, Epoch: f.s.ModuleEpoch(), At: 10, Control: c}
	r.Signature = ed25519.Sign(f.node, TaskRestartReportBytes(r))
	cmd, err := r.Command()
	if err != nil {
		t.Fatal(err)
	}
	return cmd
}

func TestUserTaskRestartPinsNativeAndPreservesOriginalAcrossHealthReports(t *testing.T) {
	f, old, selection := restartCoreFixture(t)
	plan, err := f.p.PlanTaskRestart(f.s, f.session, 10, "tenant", selection)
	if err != nil || !plan.Valid() {
		t.Fatal("restart plan", err)
	}
	old.Sequence++
	old.Signature = ed25519.Sign(f.node, deployment.ObservationBytes(old))
	managedDNSTaskCoreProgress(t, f, "source-app", "observe", old.Key, &old)
	newer, err := f.p.PlanTaskRestart(f.s, f.session, 10, "tenant", selection)
	if err != nil || newer.Target != plan.Target || newer.InventoryRevision <= plan.InventoryRevision {
		t.Fatal("health changed exact intent", err)
	}
	activityBefore, err := f.p.NodeActivity(f.s, old.Owner)
	if err != nil {
		t.Fatal(err)
	}
	original := acceptRestartCore(t, f, plan)
	activityPending, err := f.p.NodeActivity(f.s, old.Owner)
	if err != nil || activityPending.Resources != activityBefore.Resources+1 {
		t.Fatal("pending control omitted from node closure", err)
	}
	targets, err := f.p.tenantInventory(f.s, "tenant", true)
	if err != nil {
		t.Fatal(err)
	}
	pinned := false
	for _, target := range targets {
		if target.Kind == "app-operation" && target.Owner == old.Owner && strings.Contains(target.Key, "/restart/") {
			pinned = true
		}
	}
	if !pinned {
		t.Fatal("tenant close omitted original restart owner")
	}

	apps, err := f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	row, ok := apps.TaskRestart("tenant", "source-app", "restart-web")
	if !ok {
		t.Fatal("original absent")
	}
	before, _ := apps.Inventory("tenant", "source-app")
	initial, err := row.InitialControl()
	if err != nil {
		t.Fatal(err)
	}
	permit, err := f.p.TaskRestartPermit(f.s, old.Owner, restartRequestCore(row))
	if err != nil || !permit.Allowed {
		t.Fatal("current accepted grant", err)
	}
	if _, err = f.p.PlanTaskRestart(f.s, f.session, 10, "tenant", selection); err == nil {
		t.Fatal("concurrent restart admitted")
	}
	applyRestartCore(t, f, original, state.Applied) // retained result, no new target
	// Owner-signed new instance with a user reference needs the committed receipt.
	completed := initial
	completed.Phase = checker.ControlCompleted
	next := old
	next.Sequence++
	next.StartedAt = 4 * int64(time.Second)
	next.Restart = &deployment.TaskRestart{User: &deployment.UserRestart{Operation: "restart-web", Request: initial.RequestDigest}, Control: completed}
	next.Signature = ed25519.Sign(f.node, deployment.ObservationBytes(next))
	e, _ := apps.Execution("tenant", "source-app")
	report := AppProgress{Schema: 1, Cluster: f.p.Cluster, Reporter: old.Owner, Tenant: "tenant", App: "source-app", Operation: e.ActiveOperation(), Key: old.Key, Action: "observe", Expected: before.Revision(), At: 10, Observation: &next, Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(AppsKey).Revision, RequestID: "user-restart-instance"}
	report.Signature = ed25519.Sign(f.node, AppProgressBytes(report))
	forged, err := report.Command()
	if err != nil {
		t.Fatal(err)
	}
	if f.p.AdmitModule(f.s, forged) {
		t.Fatal("node alone manufactured user restart proof")
	}
	applyRestartCore(t, f, restartReportCore(t, f, row, completed), state.Applied)
	activityDone, err := f.p.NodeActivity(f.s, old.Owner)
	if err != nil || activityDone.Resources != activityBefore.Resources {
		t.Fatal("completed control still pins node", err)
	}
	apps, err = f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := apps.Inventory("tenant", "source-app")
	if after.Revision() != before.Revision() {
		t.Fatal("progress mirror changed app version/goal")
	}
	row, _ = apps.TaskRestart("tenant", "source-app", "restart-web")
	report.RootRevision = f.s.Object(AppsKey).Revision
	report.Signature = ed25519.Sign(f.node, AppProgressBytes(report))
	accepted, err := report.Command()
	if err != nil {
		t.Fatal(err)
	}
	applyRestartCore(t, f, accepted, state.Applied)
	apps, err = f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	current, _ := apps.Execution("tenant", "source-app")
	stage, _ := current.Stage(old.Key)
	if stage.Observation == nil || stage.Observation.StartedAt != next.StartedAt || stage.Observation.Native != old.Native || stage.Observation.Restart.User == nil {
		t.Fatal("original authorized instance not published")
	}
	// A terminal owner receipt cannot regress and a restore validates the same grant.
	applyRestartCore(t, f, restartReportCore(t, f, row, initial), state.ConditionFailed)
	encoded, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := state.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.p.Apps(restored); err != nil {
		t.Fatal("restored user restart relationship", err)
	}
}
func restartRequestCore(row TaskRestartRecord) TaskRestartPermitRequest {
	initial, _ := row.InitialControl()
	return TaskRestartPermitRequest{Tenant: "tenant", App: "source-app", Operation: "restart-web", Request: initial.RequestDigest}
}
func TestUserTaskRestartPlanRejectsStaleFactAndUnregisteredNativeChange(t *testing.T) {
	f, o, selection := restartCoreFixture(t)
	if _, err := f.p.PlanTaskRestart(expireAll(t, f.p, f.s, f.node, 41), f.session, 41, "tenant", selection); err == nil {
		t.Fatal("stale fact accepted")
	}
	selection.Instance = "foreign-native"
	if _, err := f.p.PlanTaskRestart(f.s, f.session, 10, "tenant", selection); err == nil {
		t.Fatal("caller native accepted")
	}
	selection.Instance = ""
	plan, err := f.p.PlanTaskRestart(f.s, f.session, 10, "tenant", selection)
	if err != nil {
		t.Fatal(err)
	}
	o.Sequence++
	o.StartedAt = 2 * int64(time.Second)
	o.Signature = ed25519.Sign(f.node, deployment.ObservationBytes(o))
	// Read-only observations of an external restart do not authorize this control.
	if plan.Container.StartedAt == time.Unix(0, o.StartedAt).UTC().Format(time.RFC3339Nano) {
		t.Fatal("test requires changed lifetime")
	}
	changed := plan
	changed.Container.NativeID = "other"
	if changed.Valid() {
		t.Fatal("plan target accepted different native")
	}
}
