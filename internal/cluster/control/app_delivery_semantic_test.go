// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"

	"gopkg.in/yaml.v3"
)

func TestDeliverySemanticSourceKeepsRestoredPolicyTargetButRejectsRealChanges(t *testing.T) {
	for _, mode := range []string{"restored", "paused", "configured", "target-tamper"} {
		t.Run(mode, func(t *testing.T) {
			f := deliveryControlFixture(t)
			apps, _ := f.p.Apps(f.s)
			d, _ := apps.Delivery("tenant", "source-app")
			target, _ := apps.DeliverySourceTarget("tenant", "source-app")
			r := AppDeliveryProgress{Schema: 1, Kind: "app-delivery", Cluster: f.p.Cluster, Reporter: [32]byte(f.node.Public().(ed25519.PublicKey)), Tenant: "tenant", App: "source-app", Action: "fetch", Expected: d.Revision(), RootRevision: f.s.Object(AppsKey).Revision, Epoch: f.s.ModuleEpoch(), At: 10, TargetCAS: true, Target: &target}
			r.Signature = ed25519.Sign(f.node, AppDeliveryProgressBytes(r))
			q := AppCDChange{Tenant: "tenant", App: "source-app"}
			f.apply("pause-semantic", "pause-app-cd", d.Revision(), q, state.Applied)
			apps, _ = f.p.Apps(f.s)
			d, _ = apps.Delivery("tenant", "source-app")
			if mode != "paused" {
				f.apply("resume-semantic", "resume-app-cd", d.Revision(), q, state.Applied)
			}
			if mode == "configured" {
				apps, _ = f.p.Apps(f.s)
				d, _ = apps.Delivery("tenant", "source-app")
				policy := d.Policy()
				policy.Poll++
				f.apply("change-source-policy", "configure-app-cd", d.Revision(), AppCDChange{Tenant: "tenant", App: "source-app", Policy: &policy, PolicyRevision: d.PolicyRevision()}, state.Applied)
			}
			if mode == "target-tamper" {
				changed := target
				changed[0] ^= 1
				r.Target = &changed
			}
			command, err := r.Command()
			if err != nil {
				t.Fatal(err)
			}
			before := f.s.Object(AppsKey)
			next, result, err := state.ApplyTransactional(f.s, f.s.Index()+1, command, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
			want := state.ConditionFailed
			if mode == "restored" {
				want = state.Applied
			}
			if mode == "target-tamper" {
				want = state.Forbidden
			}
			if err != nil || result.Code != want {
				t.Fatal(mode, result, err)
			}
			if want != state.Applied && next.Object(AppsKey) != before {
				t.Fatal("rejected source target changed metadata")
			}
		})
	}
}

func TestDeliverySemanticControllerRebasesAndAcceptsAcrossHealthInOneTransaction(t *testing.T) {
	testDeliverySemanticController(t, false)
}

func TestNodeCLIPolicyKeepsAcceptedAutomaticCDSelectionAndSignedTransition(t *testing.T) {
	testDeliverySemanticController(t, true)
}

func testDeliverySemanticController(t *testing.T, nodeCLIDisabled bool) {
	t.Helper()
	f, _ := fieldCASFixture(t)
	apps, _ := f.p.Apps(f.s)
	d, _ := apps.Delivery("tenant", "source-app")
	policy := d.Policy()
	policy.Sync.Mode = "automatic"
	f.apply("automatic-policy", "configure-app-cd", d.Revision(), AppCDChange{Tenant: "tenant", App: "source-app", Policy: &policy, PolicyRevision: d.PolicyRevision()}, state.Applied)
	if nodeCLIDisabled {
		var err error
		f.session, err = access.ApproveSession(f.session, f.admin)
		if err != nil {
			t.Fatal(err)
		}
		f.apply("node-cli-policy", "set-node-cli-policy", 0, NodeCLIChange{true}, state.Applied)
	}
	body := syncCASBody(t, f)
	input, err := deployment.ParseApp(body)
	if err != nil {
		t.Fatal(err)
	}
	input.Sfc.Delivery = &policy
	web := input.Services["web"]
	web.Environment = map[string]string{"NEXT": "1"}
	input.Services["web"] = web
	body, err = yaml.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	publishSyncCASSource(t, f, "semantic-candidate", body)
	fieldCASObservation(t, f)
	caller := [32]byte(f.node.Public().(ed25519.PublicKey))
	legacy, err := f.p.AppDeliverySyncWork(f.s, caller, AppDeliveryWorkRequest{Tenant: "tenant", App: "source-app", At: 10})
	if err != nil || legacy.Action != "replan" {
		t.Fatal("legacy replan counterexample", legacy, err)
	}
	work, err := f.p.AppDeliverySyncWork(f.s, caller, AppDeliveryWorkRequest{Tenant: "tenant", App: "source-app", At: 10, TargetCAS: true})
	if err != nil || work.Action != "auto-sync" || work.Target == nil || work.Choice == nil {
		t.Fatal("semantic automatic work", work, err)
	}
	r := AppDeliveryProgress{Schema: 1, Kind: "app-delivery", Cluster: f.p.Cluster, Reporter: caller, Tenant: "tenant", App: "source-app", Action: work.Action, Expected: work.Revision, RootRevision: work.RootRevision, Epoch: work.Epoch, At: 10, TargetCAS: true, Target: work.Target, Choice: work.Choice}
	r.Signature = ed25519.Sign(f.node, AppDeliveryProgressBytes(r))
	command, err := r.Command()
	if err != nil {
		t.Fatal(err)
	}
	// The SAME original signed proposal must survive an ordinary health tick.
	fieldCASObservation(t, f)
	var result state.Result
	f.s, result, err = state.ApplyTransactional(f.s, f.s.Index()+1, command, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
	if err != nil || result.Code != state.Applied {
		t.Fatalf("atomic current acceptance result=%+v err=%v", result, err)
	}
	apps, err = f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	entry := apps.entries[appKey("tenant", "source-app")]
	proof := entry.PendingSync
	if proof == nil {
		proof = entry.Sync
	}
	if proof == nil || proof.Choice != *work.Choice || proof.verify(entry.Origin, entry.Inventory.Scope()) != nil {
		t.Fatal("original signed choice lost")
	}
	before, _ := json.Marshal(r)
	after, _ := json.Marshal(proof.Member)
	if string(before) != string(after) {
		t.Fatal("accepted member proposal rewritten")
	}
	transition, retiring := entry.Delivery.Transition()
	if !retiring || transition.Selection.Candidate == proof.Choice.Candidate || transition.Selection.Plan != proof.Plan || transition.Selection.Intent != proof.Intent || f.p.validateAppEntryDown(entry) != nil {
		t.Fatal("rebased transition not bound to original acceptance")
	}
	bad := *proof
	bad.Plan[0] ^= 1
	entry.PendingSync = &bad
	if f.p.validateAppEntryDown(entry) == nil {
		t.Fatal("mismatched accepted plan allowed")
	}
	bad = *proof
	legacyMember := *proof.Member
	legacyMember.Target = nil
	legacyMember.Signature = ed25519.Sign(f.node, AppDeliveryProgressBytes(legacyMember))
	bad.Member = &legacyMember
	entry.PendingSync = &bad
	if bad.verify(entry.Origin, entry.Inventory.Scope()) != nil || f.p.validateAppEntryDown(entry) == nil {
		t.Fatal("legacy exact candidate check lost")
	}
	t.Log("same source/intent rebased and accepted across a healthy observation in one FSM change; native execution remains on the ordinary owner path")
}
