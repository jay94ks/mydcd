// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
)

func TestAppObservationCASMergesOtherStageFactsWithoutRebasingOriginal(t *testing.T) {
	f, _ := fieldCASFixture(t)
	apps, _ := f.p.Apps(f.s)
	i, _ := apps.Inventory("tenant", "source-app")
	e, _ := apps.Execution("tenant", "source-app")
	key := deployment.ResourceKey("task", "tenant", "source-app", "web")
	stage, ok := e.Stage(key)
	if !ok || stage.Observation == nil {
		t.Fatal("missing signed original native fact")
	}
	fact := *stage.Observation
	fact.Sequence++
	fact.Signature = ed25519.Sign(f.node, deployment.ObservationBytes(fact))
	r := AppProgress{Schema: 1, Cluster: f.p.Cluster, Reporter: [32]byte(f.node.Public().(ed25519.PublicKey)), Tenant: "tenant", App: "source-app", Operation: e.ActiveOperation(), Key: key, Action: "observe", Expected: i.Revision(), At: 11, Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(AppsKey).Revision, RequestID: "original-owner-fact", Observation: &fact}
	r.Signature = ed25519.Sign(f.node, AppProgressBytes(r))
	original, err := r.Command()
	if err != nil {
		t.Fatal(err)
	}
	fieldCASObservation(t, f) // Another native stage advances root and Inventory.
	apply := func(t *testing.T, c state.Command, want state.Code) {
		t.Helper()
		var result state.Result
		f.s, result, err = state.ApplyTransactional(f.s, f.s.Index()+1, c, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
		if err != nil || result.Code != want {
			t.Fatal("targeted fact", result, want, err)
		}
	}
	apply(t, original, state.Applied)
	apps, _ = f.p.Apps(f.s)
	after, _ := apps.Execution("tenant", "source-app")
	got, _ := after.Stage(key)
	if got.Command == nil || stage.Command == nil || *got.Command != *stage.Command || got.Observation == nil || got.Observation.Sequence != fact.Sequence || got.Observation.Native != fact.Native {
		t.Fatal("merged fact replaced original command/native")
	}
	// Original report keeps its bounded receipt and immutable command bytes.
	apply(t, original, state.Applied)
	for _, variant := range []string{"operation", "generation", "action", "future"} {
		t.Run(variant, func(t *testing.T) {
			next := r
			observation := fact
			next.Observation = &observation
			next.RequestID += "-" + variant
			switch variant {
			case "operation":
				next.Operation = "other"
			case "generation":
				observation.Generation++
				observation.Signature = ed25519.Sign(f.node, deployment.ObservationBytes(observation))
			case "action":
				next.Action = "prepare"
				next.Observation = nil
			case "future":
				next.RootRevision = f.s.Object(AppsKey).Revision + 100
			}
			next.Signature = ed25519.Sign(f.node, AppProgressBytes(next))
			c, err := next.Command()
			if err != nil {
				t.Fatal(err)
			}
			if variant == "action" {
				c.Target = state.AppObservationTarget
				c.RequestID = state.ReportRequestID(c)
				if f.p.AdmitModule(f.s, c) {
					t.Fatal("observation target authorized prepare")
				}
				return
			}
			want := state.ConditionFailed
			if variant == "future" {
				want = state.Invalid
			}
			apply(t, c, want)
		})
	}
}
