// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
)

func beginCASFixture(t *testing.T) (*backupCoreFixture, AppBegin, uint64) {
	t.Helper()
	f, _ := downCASFixture(t)
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	managedDNSTaskCoreSubmit(t, f, "first", deployment.ResourceKey("task", "tenant", "first", "web"), true, state.Applied)
	managedDNSTaskCoreProgress(t, f, "first", "finish", "", nil)
	apps, err := f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	e, _ := apps.Execution("tenant", "first")
	encoded, err := e.Blueprint().Encode()
	if err != nil {
		t.Fatal(err)
	}
	var original struct{ Input deployment.Compose }
	if json.Unmarshal(encoded, &original) != nil {
		t.Fatal("original app input")
	}
	context, err := f.p.AppPlanning(f.s, "admin", "tenant")
	if err != nil {
		t.Fatal(err)
	}
	catalog, _ := f.p.Catalog(f.s)
	plan, err := deployment.CompileApp(original.Input, catalog, context)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := plan.Encode()
	if err != nil {
		t.Fatal(err)
	}
	f.apply("replacement-upload", "begin-app-upload", 0, AppUploadBegin{Tenant: "tenant", App: "first", Deployment: "deploy", ID: "replacement", Length: len(raw), Digest: sha256.Sum256(raw)}, state.Applied)
	for index, start := 0, 0; start < len(raw); index, start = index+1, start+deployment.ArtifactPartBytes {
		f.apply(fmt.Sprintf("replacement-part-%d", index), "put-app-part", uint64(index+1), AppUploadPart{Tenant: "tenant", ID: "replacement", Index: index, Data: raw[start:min(len(raw), start+deployment.ArtifactPartBytes)]}, state.Applied)
	}
	apps, _ = f.p.Apps(f.s)
	entry := apps.entries[appKey("tenant", "first")]
	target := entry.beginTarget()
	return f, AppBegin{Target: &target, Tenant: "tenant", App: "first", Deployment: "deploy", Upload: "replacement", Operation: "replacement"}, entry.Inventory.Revision()
}

func signedBeginCAS(t *testing.T, f *backupCoreFixture, id string, expected, root uint64, q AppBegin) (UserOperation, state.Command) {
	t.Helper()
	raw, _ := ChangeBytes("begin-app", "admin", expected, q)
	var change Change
	if json.Unmarshal(raw, &change) != nil {
		t.Fatal("begin change")
	}
	op := UserOperation{Schema: 1, Session: f.session, At: 11, Epoch: f.s.ModuleEpoch(), RequestID: id, RootRevision: root, Change: change}
	op.Signature = ed25519.Sign(f.admin, OperationBytes(op))
	command, err := op.Command()
	if err != nil {
		t.Fatal(err)
	}
	return op, command
}

func TestAppBeginTargetCASPreservesFrozenOperationAcrossHealthAndUploads(t *testing.T) {
	f, q, revision := beginCASFixture(t)
	root := f.s.Object(AppsKey).Revision
	original, command := signedBeginCAS(t, f, "accept-replacement", revision, root, q)
	legacy := q
	legacy.Target = nil
	_, strict := signedBeginCAS(t, f, "legacy-root", revision, root, legacy)
	if command.Kind != state.ModuleAppCAS || strict.Kind != state.Module || bytes.Contains(OperationBytes(original), []byte("AppFieldCAS")) {
		t.Fatal("signed mode or legacy kind changed")
	}
	advanceDownCASObservation(t, f)
	applyDownCAS(t, f, strict, state.ConditionFailed)
	_, strictInventory := signedBeginCAS(t, f, "legacy-inventory", revision, f.s.Object(AppsKey).Revision, legacy)
	applyDownCAS(t, f, strictInventory, state.ConditionFailed)
	apps, _ := f.p.Apps(f.s)
	entry := apps.entries[appKey("tenant", "first")]
	if entry.Inventory.Revision() <= revision || entry.beginTarget() != *q.Target {
		t.Fatal("health changed deployment intent")
	}
	result := applyDownCAS(t, f, command, state.Applied)
	encoded, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	f.s, err = state.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if replay := applyDownCAS(t, f, command, state.Applied); replay != result {
		t.Fatal("same original request changed after Snapshot")
	}
	apps, err = f.p.Apps(f.s)
	entry = apps.entries[appKey("tenant", "first")]
	if err != nil || entry.Inventory.Revision() <= revision || entry.beginTarget() == *q.Target || entry.Origin.RequestID != original.RequestID || len(apps.uploads) != 0 {
		t.Fatal("new origin did not replace target or consume its exact upload", err)
	}
}

func TestAppBeginTargetCASRejectsCompetingIntentAndCurrentPermissionLoss(t *testing.T) {
	for _, mode := range []string{"target", "future-inventory", "down", "permission"} {
		t.Run(mode, func(t *testing.T) {
			f, q, revision := beginCASFixture(t)
			want := state.ConditionFailed
			switch mode {
			case "target":
				target := *q.Target
				target[0] ^= 1
				q.Target = &target
			case "future-inventory":
				revision += 100
			case "down":
				apps, _ := f.p.Apps(f.s)
				entry := apps.entries[appKey("tenant", "first")]
				target := entry.downTarget()
				_, stop := signedDownCAS(t, f, "explicit-stop", revision, f.s.Object(AppsKey).Revision, AppDown{Tenant: "tenant", App: "first", Operation: "stop-first", Target: &target}, true)
				applyDownCAS(t, f, stop, state.Applied)
			case "permission":
				f.session.Scopes[0].Actions = []access.Action{access.Read}
				f.session.Signature = ed25519.Sign(f.node, access.SessionBytes(f.session))
				want = state.Forbidden
			}
			_, command := signedBeginCAS(t, f, "refused-replacement", revision, f.s.Object(AppsKey).Revision, q)
			key := deployment.ResourceKey("task", "tenant", "first", "web")
			before := f.s.Object(key)
			applyDownCAS(t, f, command, want)
			if f.s.Object(key) != before {
				t.Fatal("refused replacement changed native source")
			}
		})
	}
}

func createCASFixture(t *testing.T) (*backupCoreFixture, AppBegin) {
	t.Helper()
	f, _ := downCASFixture(t)
	apps, _ := f.p.Apps(f.s)
	execution, _ := apps.Execution("tenant", "first")
	encoded, _ := execution.Blueprint().Encode()
	var original struct{ Input deployment.Compose }
	if err := json.Unmarshal(encoded, &original); err != nil {
		t.Fatal(err)
	}
	original.Input.Name = "new-app"
	service := original.Input.Services["web"]
	attachment := service.Networks["lan"]
	attachment.IPv4, attachment.Aliases = "10.80.1.20", []string{"new-app"}
	service.Networks["lan"] = attachment
	original.Input.Services["web"] = service
	planning, err := f.p.AppPlanning(f.s, "admin", "tenant")
	if err != nil {
		t.Fatal(err)
	}
	planning.Project, planning.Deployment = "new-app", "deploy"
	catalog, _ := f.p.Catalog(f.s)
	plan, err := deployment.CompileApp(original.Input, catalog, planning)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := plan.Encode()
	if err != nil {
		t.Fatal(err)
	}
	// Two independent uploads let the competing-creation case preserve the
	// loser's exact upload while testing absence, rather than a missing upload.
	for _, id := range []string{"new-original", "new-competing"} {
		f.apply(id+"-upload", "begin-app-upload", 0, AppUploadBegin{Tenant: "tenant", App: "new-app", Deployment: "deploy", ID: id, Length: len(raw), Digest: sha256.Sum256(raw)}, state.Applied)
		for index, start := 0, 0; start < len(raw); index, start = index+1, start+deployment.ArtifactPartBytes {
			f.apply(fmt.Sprintf("%s-part-%d", id, index), "put-app-part", uint64(index+1), AppUploadPart{Tenant: "tenant", ID: id, Index: index, Data: raw[start:min(len(raw), start+deployment.ArtifactPartBytes)]}, state.Applied)
		}
	}
	target := AppCreateTarget(f.p.Cluster, "tenant", "new-app", "deploy")
	return f, AppBegin{Target: &target, Tenant: "tenant", App: "new-app", Deployment: "deploy", Upload: "new-original", Operation: "create-original"}
}

func TestAppCreateTargetCASPreservesAbsenceAcrossUnrelatedCheckpoint(t *testing.T) {
	f, q := createCASFixture(t)
	root := f.s.Object(AppsKey).Revision
	op, command := signedBeginCAS(t, f, "new-original-accept", 0, root, q)
	legacy := q
	legacy.Target = nil
	_, strict := signedBeginCAS(t, f, "new-legacy-accept", 0, root, legacy)
	advanceDownCASObservation(t, f)
	if command.Kind != state.ModuleAppCAS || strict.Kind != state.Module || f.s.Object(AppsKey).Revision == root {
		t.Fatal("missing real unrelated checkpoint/CAS distinction")
	}
	applyDownCAS(t, f, strict, state.ConditionFailed)
	result := applyDownCAS(t, f, command, state.Applied)
	raw, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	f.s, err = state.Decode(raw)
	if err != nil || applyDownCAS(t, f, command, state.Applied) != result {
		t.Fatal("same original create result changed after snapshot", err)
	}
	apps, err := f.p.Apps(f.s)
	entry, exists := apps.entries[appKey("tenant", "new-app")]
	if err != nil || !exists || entry.Origin.RequestID != op.RequestID || len(apps.uploads) != 1 || apps.uploads[0].ID != "new-competing" {
		t.Fatal("create did not consume only its exact upload", err)
	}
}

func TestAppCreateTargetCASRejectsScopeCompetitionAndCurrentAuthorityLoss(t *testing.T) {
	for _, mode := range []string{"wrong-target", "wrong-cluster", "future-root", "competing-create", "existing-target-zero", "permission", "placement"} {
		t.Run(mode, func(t *testing.T) {
			f, q := createCASFixture(t)
			root, want := f.s.Object(AppsKey).Revision, state.ConditionFailed
			switch mode {
			case "wrong-target":
				value := *q.Target
				value[0] ^= 1
				q.Target = &value
			case "wrong-cluster":
				value := AppCreateTarget([32]byte{99}, q.Tenant, q.App, q.Deployment)
				q.Target = &value
			case "future-root":
				root += 100
			case "competing-create", "existing-target-zero":
				competing := q
				competing.Upload, competing.Operation = "new-competing", "create-competing"
				_, c := signedBeginCAS(t, f, "competing-accept", 0, root, competing)
				applyDownCAS(t, f, c, state.Applied)
				if mode == "existing-target-zero" {
					apps, _ := f.p.Apps(f.s)
					value := apps.entries[appKey(q.Tenant, q.App)].beginTarget()
					q.Target = &value
				}
			case "permission":
				f.session.Scopes[0].Actions = []access.Action{access.Read}
				f.session.Signature = ed25519.Sign(f.node, access.SessionBytes(f.session))
				want = state.Forbidden
			case "placement":
				catalog, _ := f.p.Catalog(f.s)
				tenant, _ := catalog.Tenant("tenant")
				f.apply("remove-create-placement", "set-nodes", tenant.Revision, NodeChangeTo("tenant", tenant.AllowedNodes, nil), state.Applied)
				want = state.Forbidden
			}
			_, command := signedBeginCAS(t, f, "refused-original-create", 0, root, q)
			before := f.s.Object(AppsKey)
			applyDownCAS(t, f, command, want)
			if f.s.Object(AppsKey) != before {
				t.Fatal("rejected create changed app/upload state")
			}
		})
	}
}
