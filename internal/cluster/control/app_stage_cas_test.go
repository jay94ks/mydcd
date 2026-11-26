// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
)

// R14 step 3: a stage report is bound to its own stage record, not to the
// whole app revision, so progress elsewhere in the app does not reject it.
func TestStageReportSurvivesProgressOnAnotherStage(t *testing.T) {
	f := managedDNSTaskCoreFixture(t)
	task := managedDNSTaskCoreBegin(t, f, "first", "10.80.1.10", "shared")
	network := deployment.ResourceKey("network-ref", "tenant", "first", "lan/node-a")
	managedDNSTaskCoreSubmit(t, f, "first", network, true, state.Applied)
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)

	// Both reports are planned on the same view.
	planned := f.s
	a, _ := f.p.Apps(planned)
	i, _ := a.Inventory("tenant", "first")
	e, _ := a.Execution("tenant", "first")
	stage, _ := e.Stage(network)
	report := func(action, key string, at uint64) state.Command {
		r := AppProgress{Schema: 1, Cluster: f.p.Cluster, Reporter: [32]byte(f.node.Public().(ed25519.PublicKey)), Tenant: "tenant", App: "first", Operation: e.ActiveOperation(), Key: key, Action: action, Expected: i.Revision(), At: at, Epoch: planned.ModuleEpoch(), RootRevision: planned.Object(AppsKey).Revision, RequestID: action + "-" + key, Stage: f.p.StageDigest(planned, "tenant", "first", key)}
		if action == "expire-observation" {
			r.ExpireSequence = stage.Observation.Sequence
		}
		r.Signature = ed25519.Sign(f.node, AppProgressBytes(r))
		cmd, err := r.Command()
		if err != nil {
			t.Fatal(err)
		}
		return cmd
	}
	expire := report("expire-observation", network, stage.Observation.At+AppObservationMaxAge+1)
	stalePrepare := report("prepare", task, 20)

	managedDNSTaskCoreProgress(t, f, "first", "prepare", task, nil)
	a, _ = f.p.Apps(f.s)
	if moved, _ := a.Inventory("tenant", "first"); moved.Revision() == i.Revision() {
		t.Fatal("fixture: the task prepare did not move the app revision")
	}

	apply := func(cmd state.Command) state.Result {
		t.Helper()
		var result state.Result
		var err error
		f.s, result, err = state.ApplyTransactional(f.s, f.s.Index()+1, cmd, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	if result := apply(expire); result.Code != state.Applied {
		t.Fatal("a report on an unchanged stage was rejected by progress on another stage", result)
	}
	a, _ = f.p.Apps(f.s)
	e, _ = a.Execution("tenant", "first")
	if got, _ := e.Stage(network); got.Observation == nil || !got.Observation.Expired {
		t.Fatal("expire-observation did not apply")
	}
	if result := apply(stalePrepare); result.Code != state.ConditionFailed {
		t.Fatal("a report planned on a stage that has since changed must be rejected", result)
	}
}
