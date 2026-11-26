// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
)

// Native observations are signed model inputs. The plan, Keep preparation,
// Inventory provenance, DNS and public health use the product cores.
func TestKeptTaskServingUsesCurrentSignedOperationWithoutRewritingClaim(t *testing.T) {
	f := managedDNSTaskCoreFixture(t)
	const app = "kept-replicas"
	var input deployment.Compose
	managedDNSTaskCoreBegin(t, f, app, "10.80.1.2", "replicas", func(c *deployment.Compose, _ *deployment.PlanningContext) {
		service := c.Services["web"]
		service.MyDC.Node, service.MyDC.Nodes, service.MyDC.PerNode = "", []string{"node-a"}, 2
		attachment := service.Networks["lan"]
		attachment.IPv4 = ""
		service.Networks["lan"] = attachment
		c.Services["web"] = service
		input = *c
	})
	managedDNSTaskCoreSubmit(t, f, app, deployment.ResourceKey("network-ref", "tenant", app, "lan/node-a"), true, state.Applied)
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	for _, id := range []string{"web/node-a/r1", "web/node-a/r2"} {
		managedDNSTaskCoreSubmit(t, f, app, deployment.ResourceKey("task", "tenant", app, id), true, state.Applied)
	}
	apps, _ := f.p.Apps(f.s)
	entry := apps.entries[appKey("tenant", app)]
	execution, _ := entry.Inventory.Execution()
	execution, err := execution.Finish(execution.Revision(), 10)
	if err != nil {
		t.Fatal(err)
	}
	entry.Inventory, err = entry.Inventory.Advance(entry.Inventory.Revision(), execution, f.s)
	if err != nil {
		t.Fatal(err)
	}
	catalog, _ := f.p.Catalog(f.s)
	planning, err := f.p.AppPlanning(f.s, "admin", "tenant")
	if err != nil {
		t.Fatal(err)
	}
	planning.Project, planning.Deployment = app, "deploy"
	blueprint, err := deployment.CompileApp(input, catalog, planning)
	if err != nil {
		t.Fatal(err)
	}
	entry.Inventory, err = entry.Inventory.Begin(entry.Inventory.Revision(), catalog, planning, blueprint, "keep-current", "user/admin", f.s.ModuleEpoch(), false)
	if err != nil {
		t.Fatal(err)
	}
	before := entry.Inventory.Claims()
	execution, _ = entry.Inventory.Execution()
	now := uint64(10 + AppObservationMaxAge + 1)
	for _, step := range execution.Steps() {
		execution, _, err = execution.Prepare(catalog, execution.Revision(), step.Key, f.s.Object(step.Key), now)
		if err != nil {
			t.Fatal("Keep prepare", step.Key, err)
		}
		stage, _ := execution.Stage(step.Key)
		if !stage.Noop || stage.Result == nil {
			t.Fatal("unchanged source was mutated", step.Key)
		}
		var native string
		for _, claim := range before {
			if claim.Step.Key == step.Key {
				native = claim.Native
			}
		}
		fact := deployment.Observation{Cluster: f.p.Cluster, Plan: blueprint.Digest(), Operation: execution.ActiveOperation(), Key: step.Key, Native: native, Owner: step.Owner, Command: state.Digest(*stage.Command), Generation: stage.Result.Generation, Revision: stage.Result.Revision, Sequence: 1, At: now, Applied: true, Healthy: true}
		fact.Signature = ed25519.Sign(f.node, deployment.ObservationBytes(fact))
		execution, err = execution.Observe(execution.Revision(), fact, now)
		if err != nil {
			t.Fatal("signed current fact", step.Key, err)
		}
	}
	execution, err = execution.Finish(execution.Revision(), now)
	if err == nil {
		entry.Inventory, err = entry.Inventory.Advance(entry.Inventory.Revision(), execution, f.s)
	}
	if err != nil {
		t.Fatal(err)
	}
	apps.entries[appKey("tenant", app)] = entry
	beforeRaw, _ := json.Marshal(before)
	afterRaw, _ := json.Marshal(entry.Inventory.Claims())
	if !bytes.Equal(beforeRaw, afterRaw) {
		t.Fatal("Keep refreshed original effect provenance")
	}
	rows, _, err := apps.ObservedPage(catalog, "admin", "tenant", "", now)
	if err != nil || len(rows) != 1 || rows[0].Health != "Healthy" {
		t.Fatal("fresh active execution", err, rows)
	}
	if err = f.p.ObserveAppReplicaHealth(f.s, apps, &rows[0], now); err != nil || rows[0].Health != "Healthy" {
		t.Fatal("stale original claim hid current replicas", err, rows[0].Health)
	}
	// readOnlyApps reads the committed input, so use the same candidate core
	// as DNS and the public app page against this explicit new inventory.
	candidates, err := acceptedTaskCandidates(f.s, apps, entry.Inventory.Scope(), entry.Inventory.Claims())
	if err != nil || len(candidates) != 2 {
		t.Fatal(err, len(candidates))
	}
	for _, candidate := range candidates {
		stale := candidate
		if candidate.observation != nil {
			expired := *candidate.observation
			expired.Expired = true
			stale.observation = &expired
		}
		if !taskCandidateAvailable(f.s, candidate, now, true) || taskCandidateAvailable(f.s, stale, now, true) || taskCandidateAvailable(f.s, candidate, now, false) {
			t.Fatal("current fact freshness/member gate", candidate.ref)
		}
	}
	claim := before[len(before)-1]
	stage, _ := execution.Stage(claim.Step.Key)
	if taskClaimObservation(claim, stage) != stage.Observation {
		t.Fatal("exact Keep source not selected")
	}
	for _, change := range []func(*deployment.Claim, *deployment.StageRecord){
		func(c *deployment.Claim, _ *deployment.StageRecord) { c.Native = "different-native" },
		func(c *deployment.Claim, _ *deployment.StageRecord) { c.Removed = true },
		func(c *deployment.Claim, _ *deployment.StageRecord) { c.Retained = true },
		func(c *deployment.Claim, _ *deployment.StageRecord) { c.Result.Generation++ },
		func(c *deployment.Claim, _ *deployment.StageRecord) { c.Result.Revision++ },
		func(c *deployment.Claim, _ *deployment.StageRecord) { c.Command.Value += " " },
		func(c *deployment.Claim, _ *deployment.StageRecord) { c.Step.Owner = [32]byte{99} },
		func(_ *deployment.Claim, s *deployment.StageRecord) { s.Noop = false },
		func(_ *deployment.Claim, s *deployment.StageRecord) { s.Result = nil },
	} {
		badClaim, badStage := claim, stage
		change(&badClaim, &badStage)
		if taskClaimObservation(badClaim, badStage) != badClaim.Observation {
			t.Fatal("unrelated source borrowed current operation facts")
		}
	}
}
