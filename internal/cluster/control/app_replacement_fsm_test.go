// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/schema"
)

// Fake owner facts terminate the original native. Every mutation still passes
// the actual control FSM, projection, original receipt and checkpoint validator.
func TestReplacementFSMAdmitsNewGenerationAfterOriginalPositiveClosure(t *testing.T) {
	f := managedDNSTaskCoreFixture(t)
	const app = "first"
	managedDNSTaskCoreBegin(t, f, app, "10.80.1.2", "web", func(c *deployment.Compose, _ *deployment.PlanningContext) {
		s := c.Services["web"]
		s.Sfc.Node, s.Sfc.Nodes, s.Sfc.PerNode = "", []string{"node-a"}, 2
		a := s.Networks["lan"]
		a.IPv4 = ""
		s.Networks["lan"] = a
		c.Services["web"] = s
	})
	networkKey := deployment.ResourceKey("network-ref", "tenant", app, "lan/node-a")
	managedDNSTaskCoreSubmit(t, f, app, networkKey, true, state.Applied)
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	for _, id := range []string{"web/node-a/r1", "web/node-a/r2"} {
		managedDNSTaskCoreSubmit(t, f, app, deployment.ResourceKey("task", "tenant", app, id), true, state.Applied)
	}
	managedDNSTaskCoreProgress(t, f, app, "finish", "", nil)
	apps, _ := f.p.Apps(f.s)
	e, _ := apps.Execution("tenant", app)
	raw, _ := e.Blueprint().Encode()
	var record struct{ Input deployment.Compose }
	if json.Unmarshal(raw, &record) != nil {
		t.Fatal("original input")
	}
	service := record.Input.Services["web"]
	service.Image = strings.ReplaceAll(service.Image, strings.Repeat("a", 64), strings.Repeat("b", 64))
	record.Input.Services["web"] = service
	catalog, _ := f.p.Catalog(f.s)
	planning, err := f.p.AppPlanning(f.s, "admin", "tenant")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := deployment.CompileApp(record.Input, catalog, planning)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = plan.Encode()
	if err != nil {
		t.Fatal(err)
	}
	f.apply("replacement-upload", "begin-app-upload", 0, AppUploadBegin{Tenant: "tenant", App: app, Deployment: "deploy", ID: "replacement", Length: len(raw), Digest: sha256.Sum256(raw)}, state.Applied)
	for start, index := 0, 0; start < len(raw); start, index = start+deployment.ArtifactPartBytes, index+1 {
		f.apply(fmt.Sprintf("replacement-part-%d", index), "put-app-part", uint64(index+1), AppUploadPart{Tenant: "tenant", ID: "replacement", Index: index, Data: raw[start:min(len(raw), start+deployment.ArtifactPartBytes)]}, state.Applied)
	}
	apps, _ = f.p.Apps(f.s)
	entry := apps.entries[appKey("tenant", app)]
	target := entry.beginTarget()
	f.apply("accept-replacement", "begin-app", entry.Inventory.Revision(), AppBegin{Target: &target, Tenant: "tenant", App: app, Deployment: "deploy", Upload: "replacement", Operation: "rolling"}, state.Applied)
	view := func() (Apps, deployment.Inventory, deployment.Execution) {
		t.Helper()
		a, err := f.p.Apps(f.s)
		if err != nil {
			t.Fatal(err)
		}
		i, _ := a.Inventory("tenant", app)
		x, _ := i.Execution()
		return a, i, x
	}
	report := func(action, key string, detail *AppRetirementProgress, observation *deployment.Observation) {
		t.Helper()
		_, i, x := view()
		operation := x.ActiveOperation()
		if r, ok := i.Retirement(); ok && strings.HasPrefix(action, "retire-") {
			operation = r.ID
		}
		r := AppProgress{Schema: 1, Cluster: f.p.Cluster, Reporter: [32]byte(f.node.Public().(ed25519.PublicKey)), Tenant: "tenant", App: app, Operation: operation, Action: action, Key: key, Expected: i.Revision(), RootRevision: f.s.Object(AppsKey).Revision, Epoch: f.s.ModuleEpoch(), At: 11, RequestID: fmt.Sprintf("replacement-progress-%d", f.s.Index()), Retire: detail, Observation: observation}
		if StageReport(r.Action) {
			r.Stage = f.p.StageDigest(f.s, r.Tenant, r.App, r.Key)
		}
		r.Signature = ed25519.Sign(f.node, AppProgressBytes(r))
		cmd, err := r.Command()
		if err != nil {
			t.Fatal(err)
		}
		var result state.Result
		f.s, result, err = state.ApplyTransactional(f.s, f.s.Index()+1, cmd, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
		if err != nil || result.Code != state.Applied {
			t.Fatal("replacement progress", action, key, result, err)
		}
	}
	_, inventory, _ := view()
	retirement, ok := inventory.Retirement()
	if !ok {
		t.Fatal("original closure not selected")
	}
	for _, target := range retirement.Targets {
		key := target.Original.Step.Key
		if target.Original.Step.Kind != "task" {
			t.Fatal("unexpected native closure", key)
		}
		apply := func(phase string) {
			t.Helper()
			report("retire-send", key, &AppRetirementProgress{Phase: phase}, nil)
			_, i, _ := view()
			m, ok := i.Removal(key, phase)
			if !ok {
				t.Fatal("original removal absent")
			}
			var result state.Result
			f.s, result, err = state.ApplyTransactional(f.s, f.s.Index()+1, m.Command, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
			if err != nil || result.Code != state.Applied {
				t.Fatal("original closure mutation", phase, result, err)
			}
			report("retire-collect", key, &AppRetirementProgress{Phase: phase}, nil)
		}
		apply("drain")
		_, i, _ := view()
		drain, _ := i.Removal(key, "drain")
		gone := ed25519.Sign(f.node, schema.GoneBytes(f.p.Cluster, key, target.Original.Result.Generation, []byte(drain.Command.Value)))
		report("retire-gone", key, &AppRetirementProgress{Gone: gone}, nil)
		apply("proof")
		apply("delete")
		a, _, _ := view()
		allocations, err := a.NetworkRetirementAllocations("tenant", app, key)
		if err != nil {
			t.Fatal(err)
		}
		// No Docker IPAM facts are injected for automatic replica addresses.
		// Match the native collector: only fence allocations actually held.
		if len(allocations) == 0 {
			continue
		}
		report("retire-addresses", key, &AppRetirementProgress{Phase: "fence"}, nil)
		a, _, _ = view()
		var proofs []services.AddressOwnerClose
		for _, allocation := range allocations {
			fence, ok := a.network.Authority.AddressRetirement(allocation)
			if !ok {
				t.Fatal("original address fence missing")
			}
			proof := services.AddressOwnerClose{Cluster: f.p.Cluster, Target: fence.ID, Epoch: fence.Epoch, Owner: [32]byte(f.node.Public().(ed25519.PublicKey)), Boot: [32]byte{1}, At: 11, Native: target.Original.Native, Fenced: true, Stopped: true}
			proof.Signature = ed25519.Sign(f.node, services.AddressOwnerCloseBytes(proof))
			proofs = append(proofs, proof)
		}
		report("retire-addresses", key, &AppRetirementProgress{Phase: "release", Addresses: proofs}, nil)
	}
	report("retire-finish", "", &AppRetirementProgress{}, nil)
	updates, err := f.p.ManagedDNSUpdates(f.s, [32]byte(f.node.Public().(ed25519.PublicKey)))
	if err != nil {
		t.Fatal(err)
	}
	for _, update := range updates {
		update.Signature = ed25519.Sign(f.node, NetworkDNSProgressBytes(update))
		applyDNSCoreReport(t, f, update, state.Applied)
	}
	_, _, e = view()
	for _, step := range e.Steps() {
		report("prepare", step.Key, nil, nil)
		_, _, e = view()
		stage, _ := e.Stage(step.Key)
		if stage.Result == nil {
			report("send", step.Key, nil, nil)
			_, _, e = view()
			stage, _ = e.Stage(step.Key)
			cmd := *stage.Command
			var result state.Result
			f.s, result, err = state.ApplyTransactional(f.s, f.s.Index()+1, cmd, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
			if err != nil || result.Code != state.Applied {
				t.Fatal("new generation mutation after positive closure", step.Key, result, err)
			}
			report("collect", step.Key, nil, nil)
			_, _, e = view()
			stage, _ = e.Stage(step.Key)
		}
		if step.Kind == "task" {
			if stage.Previous == nil || !stage.Previous.Removed || stage.Result.Generation <= stage.Previous.Result.Generation {
				t.Fatal("new source reused original generation")
			}
			base, present, known := e.PreparationBase(step.Key)
			if !known || present || base.Revision != stage.Previous.Removal.Delete.Result.Revision || stage.Command.Expected != base.Revision {
				t.Fatal("replacement did not use the original positive tombstone CAS")
			}
			snapshot, err := state.Encode(f.s)
			if err != nil {
				t.Fatal(err)
			}
			restored, err := state.Decode(snapshot)
			if err != nil {
				t.Fatal(err)
			}
			_, replay, err := state.ApplyTransactional(restored, restored.Index()+1, *stage.Command, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
			if err != nil || replay != *stage.Result {
				t.Fatal("new generation replay lost its original receipt", replay, err)
			}
			return
		}
		o := deployment.Observation{Cluster: f.p.Cluster, Plan: e.Blueprint().Digest(), Operation: e.ActiveOperation(), Key: step.Key, Native: "mock-native-first", Owner: [32]byte(f.node.Public().(ed25519.PublicKey)), Command: state.Digest(*stage.Command), Generation: stage.Result.Generation, Revision: stage.Result.Revision, Sequence: 1, At: 11, Applied: true, Healthy: true}
		o.Signature = ed25519.Sign(f.node, deployment.ObservationBytes(o))
		report("observe", step.Key, nil, &o)
	}
	t.Fatal("new Task mutation was not reached")
}
