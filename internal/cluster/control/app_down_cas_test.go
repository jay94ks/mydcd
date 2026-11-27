// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
)

func downCASFixture(t *testing.T) (*backupCoreFixture, AppView) {
	t.Helper()
	f := managedDNSTaskCoreFixture(t)
	managedDNSTaskCoreBegin(t, f, "first", "10.80.1.10", "first")
	managedDNSTaskCoreSubmit(t, f, "first", deployment.ResourceKey("network-ref", "tenant", "first", "lan/node-a"), true, state.Applied)
	a, err := f.p.Apps(f.s)
	catalog, _ := f.p.Catalog(f.s)
	rows, _, pageErr := a.Page(catalog, "admin", "tenant", "")
	if err != nil || pageErr != nil || len(rows) != 1 || rows[0].DownTarget == nil {
		t.Fatal("original accepted target", err)
	}
	return f, rows[0]
}

func signedDownCAS(t *testing.T, f *backupCoreFixture, id string, expected, root uint64, payload AppDown, targeted bool) (UserOperation, state.Command) {
	t.Helper()
	raw, err := ChangeBytes("down-app", "admin", expected, payload)
	if err != nil {
		t.Fatal(err)
	}
	var change Change
	if err = json.Unmarshal(raw, &change); err != nil {
		t.Fatal(err)
	}
	op := UserOperation{Schema: 1, Session: f.session, At: 11, Epoch: f.s.ModuleEpoch(), RequestID: id, RootRevision: root, Change: change}
	op.Signature = ed25519.Sign(f.admin, OperationBytes(op))
	c, err := op.Command()
	if err != nil {
		t.Fatal(err)
	}
	return op, c
}

func applyDownCAS(t *testing.T, f *backupCoreFixture, c state.Command, want state.Code) state.Result {
	t.Helper()
	next, result, err := state.ApplyTransactional(f.s, f.s.Index()+1, c, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
	if err != nil || result.Code != want {
		t.Fatal("original down CAS", c.RequestID, result, want, err)
	}
	f.s = next
	return result
}

func advanceDownCASObservation(t *testing.T, f *backupCoreFixture) {
	t.Helper()
	a, _ := f.p.Apps(f.s)
	e, _ := a.Execution("tenant", "first")
	key := deployment.ResourceKey("network-ref", "tenant", "first", "lan/node-a")
	stage, _ := e.Stage(key)
	o := *stage.Observation
	o.Sequence++
	o.Signature = ed25519.Sign(f.node, deployment.ObservationBytes(o))
	managedDNSTaskCoreProgress(t, f, "first", "observe", key, &o)
}

func TestAppDownCASPreservesTargetAcrossObservationAndUnrelatedRoot(t *testing.T) {
	f, original := downCASFixture(t)
	root := f.s.Object(AppsKey).Revision
	legacyPayload := AppDown{Tenant: "tenant", App: "first", Operation: "legacy-root"}
	_, legacy := signedDownCAS(t, f, "legacy-root", original.Revision, root, legacyPayload, false)
	payload := AppDown{Tenant: "tenant", App: "first", Operation: "original-down", Target: original.DownTarget}
	op, command := signedDownCAS(t, f, "original-down", original.Revision, root, payload, true)
	advanceDownCASObservation(t, f)
	apps, _ := f.p.Apps(f.s)
	advanced, _ := apps.Inventory("tenant", "first")
	if advanced.Revision() <= original.Revision || appDownTarget(apps.entries[appKey("tenant", "first")].Origin) != *original.DownTarget {
		t.Fatal("observation did not advance the inventory while preserving intent")
	}
	applyDownCAS(t, f, legacy, state.ConditionFailed)
	// Even with a current root the legacy exact Inventory CAS remains strict.
	legacyPayload.Operation = "legacy-inventory"
	_, strictInventory := signedDownCAS(t, f, "legacy-inventory", original.Revision, f.s.Object(AppsKey).Revision, legacyPayload, false)
	applyDownCAS(t, f, strictInventory, state.ConditionFailed)
	managedDNSTaskCoreBegin(t, f, "unrelated", "10.80.1.11", "unrelated")
	resources := f.s.Object(ResourcesKey)
	result := applyDownCAS(t, f, command, state.Applied)
	if command.Kind != state.ModuleAppDown || f.s.Object(ResourcesKey) != resources || applyDownCAS(t, f, command, state.Applied) != result {
		t.Fatal("down replaced original result or management network")
	}
	apps, err := f.p.Apps(f.s)
	i, _ := apps.Inventory("tenant", "first")
	r, retiring := i.Retirement()
	if err != nil || !retiring || r.ID != payload.Operation || r.Revision <= op.Change.Expected {
		t.Fatal("retirement lost original target/expected coordinate", r, err)
	}
	originalBytes, _ := json.Marshal(op)
	storedBytes, _ := json.Marshal(apps.entries[appKey("tenant", "first")].Down)
	if !bytes.Equal(originalBytes, storedBytes) {
		t.Fatal("retirement rewrote original signed down")
	}
	encoded, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	f.s, err = state.Decode(encoded)
	if err != nil || applyDownCAS(t, f, command, state.Applied) != result {
		t.Fatal("snapshot lost original down receipt", err)
	}
	wire, err := state.EncodeCommand(command)
	decoded, decodeErr := state.DecodeCommand(wire)
	if err != nil || decodeErr != nil || decoded != command || wire[0] != 1 {
		t.Fatal("schema1 targeted down codec", err, decodeErr)
	}
	conflict := op
	payload.Operation = "replacement-down"
	conflict.Change.Payload, _ = json.Marshal(payload)
	conflict.Signature = ed25519.Sign(f.admin, OperationBytes(conflict))
	changed, err := conflict.Command()
	if err != nil {
		t.Fatal(err)
	}
	applyDownCAS(t, f, changed, state.RequestConflict)
	_, duplicate := signedDownCAS(t, f, "another-down", original.Revision, root, AppDown{Tenant: "tenant", App: "first", Operation: "another-down", Target: original.DownTarget}, true)
	applyDownCAS(t, f, duplicate, state.ConditionFailed)
}

func TestAppDownCASRejectsAnotherTargetFutureCoordinatesAndRevocation(t *testing.T) {
	for _, scenario := range []string{"wrong-target", "another-app", "future-inventory", "future-root", "kind", "namespace", "actor", "epoch", "no-deploy", "signature", "no-admission"} {
		t.Run(scenario, func(t *testing.T) {
			f, original := downCASFixture(t)
			root := f.s.Object(AppsKey).Revision
			payload := AppDown{Tenant: "tenant", App: "first", Operation: "stop", Target: original.DownTarget}
			expected, want := original.Revision, state.ConditionFailed
			switch scenario {
			case "wrong-target":
				target := *payload.Target
				target[0] ^= 1
				payload.Target = &target
			case "another-app":
				managedDNSTaskCoreBegin(t, f, "other", "10.80.1.11", "other")
				payload.App = "other"
			case "future-inventory":
				expected += 100
			case "future-root":
				root = f.s.Index() + 100
			case "no-deploy":
				f.session.Scopes[0].Actions = []access.Action{access.Read}
				f.session.Signature = ed25519.Sign(f.node, access.SessionBytes(f.session))
				want = state.Forbidden
			}
			op, command := signedDownCAS(t, f, "stop", expected, root, payload, true)
			admit := f.p.AdmitModule
			switch scenario {
			case "kind":
				command.Kind, want = state.ModuleUpload, state.Forbidden
			case "namespace":
				command.Key, want = ResourcesKey, state.Forbidden
			case "actor":
				command.Actor, want = "node/fake", state.Forbidden
			case "epoch":
				command.Epoch, want = command.Epoch+1, state.Expired
			case "signature":
				op.Signature[0] ^= 1
				raw, _ := json.Marshal(op)
				command.Value, want = string(raw), state.Forbidden
			case "no-admission":
				admit, want = nil, state.Forbidden
			}
			before := f.s.Object(AppsKey)
			next, result, err := state.ApplyTransactional(f.s, f.s.Index()+1, command, f.p.ValidateManaged, f.p.Reduce, admit, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
			if err != nil || result.Code != want {
				t.Fatal("unadmitted down", result, want, err)
			}
			f.s = next
			if f.s.Object(AppsKey) != before {
				t.Fatal("rejected down changed target or retirement")
			}
		})
	}
}

func TestAppDownCASRejectsReplacedAcceptedOrigin(t *testing.T) {
	f := managedDNSTaskCoreFixture(t)
	managedDNSTaskCoreBegin(t, f, "first", "10.80.1.10", "first")
	a, _ := f.p.Apps(f.s)
	catalog, _ := f.p.Catalog(f.s)
	rows, _, err := a.Page(catalog, "admin", "tenant", "")
	if err != nil || len(rows) != 1 || rows[0].DownTarget == nil {
		t.Fatal("original query target", err)
	}
	original := rows[0]
	_, command := signedDownCAS(t, f, "stop-original", original.Revision, f.s.Object(AppsKey).Revision, AppDown{Tenant: "tenant", App: "first", Operation: "stop-original", Target: original.DownTarget}, true)
	// A replacement accepted origin is explicit Mock input, with no native
	// goal dispatched. Its signed scope/Inventory still pass product checks.
	entry := a.entries[appKey("tenant", "first")]
	entry.Origin.RequestID = "replacement-acceptance"
	entry.Origin.Signature = ed25519.Sign(f.admin, OperationBytes(entry.Origin))
	a.entries[appKey("tenant", "first")] = entry
	writes, code := f.p.appsCheckpoint(f.s, a)
	if code != state.Applied {
		t.Fatal(code)
	}
	f.s, _, err = state.ApplyReduced(f.s, f.s.Index()+1, state.Command{Kind: state.Module, Actor: "anchor", Epoch: f.s.ModuleEpoch(), RequestID: "replacement-fixture", Key: AppsKey, Expected: f.s.Object(AppsKey).Revision, Value: "mock"}, nil, func(state.State, state.Command) (map[string][]byte, state.Code) { return writes, state.Applied })
	updated, decodeErr := f.p.Apps(f.s)
	if err != nil || decodeErr != nil || appDownTarget(updated.entries[appKey("tenant", "first")].Origin) == *original.DownTarget || f.s.Object(AppsKey).Revision <= command.Expected {
		t.Fatal("replacement origin/read point precondition", err, decodeErr)
	}
	before := f.s.Object(AppsKey)
	applyDownCAS(t, f, command, state.ConditionFailed)
	if f.s.Object(AppsKey) != before {
		t.Fatal("old target stopped a replacement acceptance")
	}
}

func TestAppDownAfterRecreationUsesCurrentAcceptedTarget(t *testing.T) {
	f, _ := downCASFixture(t)
	a, _ := f.p.Apps(f.s)
	entry := a.entries[appKey("tenant", "first")]
	entry.Sync = &AppDeliverySync{Recreate: &AppRecreation{}, Plan: [32]byte{1}}
	target := entry.downTarget()
	if target == appDownTarget(entry.Origin) {
		t.Fatal("fixture did not distinguish accepted executions")
	}
	expected := entry.Inventory.Revision()
	op, cmd := signedDownCAS(t, f, "stop-recreated", expected, f.s.Object(AppsKey).Revision, AppDown{Tenant: "tenant", App: "first", Operation: "stop-recreated", Target: &target}, true)
	catalog, _ := f.p.Catalog(f.s)
	var err error
	entry.Inventory, err = entry.Inventory.Retire(expected, catalog, op.Session.User, "stop-recreated", cmd.Actor, cmd.Epoch, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	entry.Down = &op
	if err := f.p.validateAppEntryDown(entry); err != nil {
		t.Fatal("current accepted target rejected", err)
	}
	stale := appDownTarget(entry.Origin)
	bad, _ := signedDownCAS(t, f, "stale-target", expected, f.s.Object(AppsKey).Revision, AppDown{Tenant: "tenant", App: "first", Operation: "stop-recreated", Target: &stale}, true)
	entry.Down = &bad
	if f.p.validateAppEntryDown(entry) == nil {
		t.Fatal("original registration target accepted after recreation")
	}
}
