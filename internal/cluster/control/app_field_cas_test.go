// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
)

// Native facts are signed model inputs; all planning, A1, progress and CAS
// checks are the reusable product core, not evidence of Docker/HTTP success.
func fieldCASFixture(t *testing.T) (*backupCoreFixture, AppCDField) {
	t.Helper()
	f := deliveryControlFixture(t)
	apps, _ := f.p.Apps(f.s)
	e, _ := apps.Execution("tenant", "source-app")
	for _, step := range e.Steps() {
		managedDNSTaskCoreSubmit(t, f, "source-app", step.Key, step.Kind != "delivery", state.Applied)
		if step.Kind == "delivery" {
			managedDNSTaskCoreProgress(t, f, "source-app", "collect", step.Key, nil)
		}
	}
	managedDNSTaskCoreProgress(t, f, "source-app", "finish", "", nil)
	catalog, _ := f.p.Catalog(f.s)
	view, err := f.p.AppDeliveryField(f.s, catalog, "admin", "tenant", AppCDFieldRequest{App: "source-app", Path: []string{"services", "web", "cpus"}})
	if err != nil || view.Target == ([32]byte{}) || len(view.Refs) != 1 {
		t.Fatal("owned field fixture", view, err)
	}
	return f, view
}

func signedFieldCAS(t *testing.T, f *backupCoreFixture, id string, root, expected uint64, q AppOverrideChange, scoped bool, actions ...string) (UserOperation, state.Command) {
	t.Helper()
	action := "override-app"
	if len(actions) > 0 {
		action = actions[0]
	}
	raw, err := ChangeBytes(action, "admin", expected, q)
	if err != nil {
		t.Fatal(err)
	}
	var change Change
	if json.Unmarshal(raw, &change) != nil {
		t.Fatal("change")
	}
	op := UserOperation{Schema: 1, Session: f.session, At: 11, Epoch: f.s.ModuleEpoch(), RequestID: id, RootRevision: root, Change: change}
	op.Signature = ed25519.Sign(f.admin, OperationBytes(op))
	c, err := op.Command()
	if err != nil {
		t.Fatal(err)
	}
	return op, c
}

func fieldCASObservation(t *testing.T, f *backupCoreFixture) {
	t.Helper()
	apps, _ := f.p.Apps(f.s)
	e, _ := apps.Execution("tenant", "source-app")
	key := deployment.ResourceKey("network-ref", "tenant", "source-app", "lan/node-a")
	stage, _ := e.Stage(key)
	o := *stage.Observation
	o.Sequence++
	o.Signature = ed25519.Sign(f.node, deployment.ObservationBytes(o))
	managedDNSTaskCoreProgress(t, f, "source-app", "observe", key, &o)
}

func TestAppFieldCASIgnoresReadBookkeepingAndOtherAppsButPreservesOriginalIntent(t *testing.T) {
	f, view := fieldCASFixture(t)
	root := f.s.Object(AppsKey).Revision
	q := AppOverrideChange{Tenant: "tenant", App: "source-app", Path: view.Path, Value: []byte(`"0.2"`), Refs: view.Refs}
	_, legacy := signedFieldCAS(t, f, "legacy-field", root, view.Revision, q, false)
	q.Target = &view.Target
	op, scoped := signedFieldCAS(t, f, "scoped-field", root, view.Revision, q, true)
	fieldCASObservation(t, f)
	deliveryControlProgress(t, f, AppDeliveryProgress{Action: "fetch"}, state.Applied)
	a, _ := f.p.Apps(f.s)
	d, _ := a.Delivery("tenant", "source-app")
	ticket, _ := d.FetchTicket()
	deliveryControlProgress(t, f, AppDeliveryProgress{Action: "source-error", Ticket: &ticket, Error: "fetch"}, state.Applied)
	managedDNSTaskCoreBegin(t, f, "unrelated-field", "10.80.1.11", "unrelated")
	catalog, _ := f.p.Catalog(f.s)
	after, err := f.p.AppDeliveryField(f.s, catalog, "admin", "tenant", AppCDFieldRequest{App: q.App, Path: q.Path})
	if err != nil || after.Target != view.Target || after.Revision <= view.Revision || f.s.Object(AppsKey).Revision <= root {
		t.Fatal("read bookkeeping changed the intended field target", err)
	}
	applyDownCAS(t, f, legacy, state.ConditionFailed)
	result := applyDownCAS(t, f, scoped, state.Applied)
	wire, err := state.EncodeCommand(scoped)
	decoded, decodeErr := state.DecodeCommand(wire)
	if err != nil || decodeErr != nil || decoded != scoped {
		t.Fatal("scoped field command lost its signed mode/target on wire", err, decodeErr)
	}
	if scoped.Kind != state.ModuleAppCAS || applyDownCAS(t, f, scoped, state.Applied) != result || op.Change.Expected != view.Revision || op.RootRevision != root {
		t.Fatal("scoped field rewrote original coordinates/result")
	}
	encoded, _ := state.Encode(f.s)
	restored, err := state.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	f.s = restored
	if applyDownCAS(t, f, scoped, state.Applied) != result {
		t.Fatal("snapshot lost original result")
	}
	_, stale := signedFieldCAS(t, f, "changed-field", f.s.Object(AppsKey).Revision, view.Revision, q, true)
	applyDownCAS(t, f, stale, state.ConditionFailed)
	catalog, _ = f.p.Catalog(f.s)
	current, err := f.p.AppDeliveryField(f.s, catalog, "admin", "tenant", AppCDFieldRequest{App: q.App, Path: q.Path})
	if err != nil || current.Override == nil {
		t.Fatal("current override", err)
	}
	release := AppOverrideChange{Tenant: "tenant", App: "source-app", Path: view.Path, Revision: current.Override.Revision, Target: &current.Target}
	_, command := signedFieldCAS(t, f, "release-field", f.s.Object(AppsKey).Revision, current.Revision, release, true, "release-app-override")
	fieldCASObservation(t, f)
	applyDownCAS(t, f, command, state.Applied)
}

func TestAppFieldCASRejectsActualPolicyAndOwnershipChanges(t *testing.T) {
	for _, change := range []string{"policy", "pause", "override"} {
		t.Run(change, func(t *testing.T) {
			f, view := fieldCASFixture(t)
			q := AppOverrideChange{Tenant: "tenant", App: "source-app", Path: view.Path, Value: []byte(`"0.2"`), Refs: view.Refs, Target: &view.Target}
			_, original := signedFieldCAS(t, f, "old-field", f.s.Object(AppsKey).Revision, view.Revision, q, true)
			a, _ := f.p.Apps(f.s)
			d, _ := a.Delivery("tenant", "source-app")
			switch change {
			case "policy":
				p := d.Policy()
				p.Poll++
				f.apply("policy", "configure-app-cd", d.Revision(), AppCDChange{Tenant: "tenant", App: "source-app", Policy: &p, PolicyRevision: d.PolicyRevision()}, state.Applied)
			case "pause":
				f.apply("pause", "pause-app-cd", d.Revision(), AppCDChange{Tenant: "tenant", App: "source-app"}, state.Applied)
			case "override":
				_, other := signedFieldCAS(t, f, "other-field", f.s.Object(AppsKey).Revision, view.Revision, q, true)
				applyDownCAS(t, f, other, state.Applied)
			}
			before := f.s.Object(AppsKey)
			applyDownCAS(t, f, original, state.ConditionFailed)
			if f.s.Object(AppsKey) != before {
				t.Fatal("stale field changed the actual replacement")
			}
		})
	}
}

func TestAppFieldCASRejectsFutureRootTargetChangesAndCurrentScopeRevocation(t *testing.T) {
	for _, test := range []string{"future-root", "future-delivery", "wrong-target", "wrong-path", "no-current-cd"} {
		t.Run(test, func(t *testing.T) {
			f, view := fieldCASFixture(t)
			root, expected := f.s.Object(AppsKey).Revision, view.Revision
			q := AppOverrideChange{Tenant: "tenant", App: "source-app", Path: view.Path, Value: []byte(`"0.2"`), Refs: view.Refs, Target: &view.Target}
			want := state.ConditionFailed
			switch test {
			case "future-root":
				root++
			case "future-delivery":
				expected++
			case "wrong-target":
				view.Target[0] ^= 1
			case "wrong-path":
				q.Path = []string{"services", "web", "mem_limit"}
			case "no-current-cd":
				f.session.Scopes[0].Actions = []access.Action{access.Read, access.Deploy}
				f.session.Signature = ed25519.Sign(f.node, access.SessionBytes(f.session))
				want = state.Forbidden
			}
			_, cmd := signedFieldCAS(t, f, "rejected-field", root, expected, q, true)
			before := f.s.Object(AppsKey)
			applyDownCAS(t, f, cmd, want)
			if f.s.Object(AppsKey) != before {
				t.Fatal("rejected field changed apps")
			}
		})
	}
}

func TestAppFieldCASSignedModeIsExactAndLegacyBytesStayUnchanged(t *testing.T) {
	f, view := fieldCASFixture(t)
	q := AppOverrideChange{Tenant: "tenant", App: "source-app", Path: view.Path, Value: []byte(`"0.2"`), Refs: view.Refs, Target: &view.Target}
	op, _ := signedFieldCAS(t, f, "mode", f.s.Object(AppsKey).Revision, view.Revision, q, true)
	for _, mutate := range []func(*UserOperation){
		func(o *UserOperation) { o.Change.Action = "sync-app" },
	} {
		bad := op
		mutate(&bad)
		if _, err := bad.Command(); err == nil {
			t.Fatal("forged scoped field mode")
		}
	}
	q.Target = nil
	legacy, _ := signedFieldCAS(t, f, "legacy", f.s.Object(AppsKey).Revision, view.Revision, q, false)
	var fields map[string]json.RawMessage
	if json.Unmarshal(OperationBytes(legacy)[len("mydc-user-operation-1\x00"):], &fields) != nil || fields["AppFieldCAS"] != nil {
		t.Fatal("legacy signed bytes gained a field")
	}
	var payload map[string]json.RawMessage
	if json.Unmarshal(legacy.Change.Payload, &payload) != nil || payload["Target"] != nil {
		t.Fatal("legacy payload gained a target")
	}
	if legacy.VerifyOriginal(f.p.Cluster) != nil {
		t.Fatal("legacy original signature changed")
	}
}
