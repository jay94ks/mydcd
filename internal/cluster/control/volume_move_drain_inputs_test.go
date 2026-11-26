// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/workload"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

// The original native/healthy observations are explicit algorithm inputs.
// App planning/progress, drain acceptance, each signed child start, current
// permits and input read-sets all consume the existing product core.
func drainInputsCore(t *testing.T, startAll bool) (*backupCoreFixture, []NodeDrainVolumeMove) {
	t.Helper()
	f := managedDNSTaskCoreFixture(t)
	logs := f.scope
	logs.ID = "logs"
	f.apply("drain-inputs-logs", "create-volume", 0, volumeFact(t, logs, "node-a", f.node), state.Applied)
	for _, scope := range []volumes.Scope{f.scope, logs} {
		v := f.view()
		core, found := v.Volume(scope)
		ready, native := v.Native(scope.Tenant, scope.App, scope.ID)
		if !found || !native {
			t.Fatal("missing original source", scope.ID)
		}
		f.apply("drain-inputs-capacity-"+scope.ID, "set-volume-capacity", core.Revision(), VolumeCapacity{Scope: scope, Native: VolumeNativeDigest(ready), Bytes: 65536}, state.Applied)
	}
	for _, tenant := range []string{"", "tenant"} {
		for _, node := range []string{"node-a", "node-b"} {
			f.apply("drain-inputs-storage-"+tenant+node, "set-volume-backup-limit", 0, VolumeBackupLimit{Tenant: tenant, Node: node, Bytes: 1 << 20, Count: 4, StagingBytes: 1 << 20, StagingCount: 4, Original: &OriginalVolumeLimit{Bytes: 1 << 20, Count: 4}}, state.Applied)
			resources, _ := f.p.Resources(f.s)
			limit, _ := resources.Quotas.Limit(tenant, node)
			expected := limit.Revision
			limit.Revision = 0
			limit.Capacity = workload.Resources{CPU: 4e9, Memory: 256 << 20}
			f.apply("drain-inputs-quota-"+tenant+node, "set-node-quota", expected, limit, state.Applied)
		}
	}
	managedDNSTaskCoreBegin(t, f, "app", "10.80.1.10", "source", func(input *deployment.Compose, _ *deployment.PlanningContext) {
		service := input.Services["web"]
		service.Networks["lan"] = deployment.Attachment{} // movable dynamic address; no explicit alias/DNS input
		service.DNS = nil
		service.Volumes = deployment.Mounts{{Type: "volume", Source: "data", Target: "/data"}, {Type: "volume", Source: "logs", Target: "/logs"}}
		input.Services["web"] = service
		input.Volumes = map[string]deployment.ComposeVolume{}
		for _, name := range []string{"data", "logs"} {
			retain := true
			input.Volumes[name] = deployment.ComposeVolume{External: true, MyDC: deployment.VolumeExtension{Node: "node-a", Driver: "local", Access: "single-writer", Retain: &retain, UID: 10001, GID: 10001, Mode: "0750", Capacity: 65536, Quota: "observe"}}
		}
	})
	apps, _ := f.p.Apps(f.s)
	execution, _ := apps.Execution("tenant", "app")
	for _, step := range execution.Steps() {
		if step.Kind != "volume" && step.Kind != "task" {
			managedDNSTaskCoreSubmit(t, f, "app", step.Key, true, state.Applied)
			continue
		}
		cmd := managedDNSTaskCoreSubmit(t, f, "app", step.Key, false, state.Applied)
		managedDNSTaskCoreProgress(t, f, "app", "collect", step.Key, nil)
		if step.Kind == "task" {
			managedDNSTaskCoreProgress(t, f, "app", "bind-inputs", step.Key, nil)
		}
		apps, _ = f.p.Apps(f.s)
		current, _ := apps.Execution("tenant", "app")
		stage, _ := current.Stage(step.Key)
		if stage.Result == nil {
			t.Fatal("missing original result", step.Key)
		}
		native := "mock-native-app"
		if step.Kind == "volume" {
			id, err := deployment.ResourceIDFromKey("volume", "tenant", "app", step.Key)
			if err != nil {
				t.Fatal(err)
			}
			ready, found := f.view().Native("tenant", "app", id)
			if !found {
				t.Fatal("original volume native")
			}
			native = ready.Owner.Native
		}
		observation := deployment.Observation{Cluster: f.p.Cluster, Plan: current.Blueprint().Digest(), Operation: current.ActiveOperation(), Key: step.Key, Native: native, Owner: step.Owner, Command: state.Digest(cmd), Generation: stage.Result.Generation, Revision: stage.Result.Revision, Sequence: 1, At: 10, Applied: true, Healthy: true}
		observation.Signature = ed25519.Sign(f.node, deployment.ObservationBytes(observation))
		managedDNSTaskCoreProgress(t, f, "app", "observe", step.Key, &observation)
	}
	managedDNSTaskCoreProgress(t, f, "app", "finish", "", nil)
	registry := f.view()
	var recipes []VolumeMoveRecipe
	for _, scope := range []volumes.Scope{f.scope, logs} {
		core, _ := registry.Volume(scope)
		ready, _ := registry.Native(scope.Tenant, scope.App, scope.ID)
		if len(core.Consumers()) != 1 || !core.Consumers()[0].Writable {
			t.Fatal("missing original app writer", scope.ID)
		}
		recipes = append(recipes, VolumeMoveRecipe{Schema: 1, NativeBinding: VolumeNativeDigest(ready), Compatibility: [32]byte{7}, Consumer: core.Consumers()[0]})
	}
	plan, err := f.p.PlanNodeDrainWithRecipes(f.s, f.session, 2, NodeDrainQuery{Node: "node-a", Operation: "drain-inputs"}, recipes)
	if err != nil || len(plan.Blockers) != 0 || len(plan.Jobs) != 1 || plan.Jobs[0].Move == nil || len(plan.Jobs[0].AdditionalMoves) != 1 {
		t.Fatal("exact two-volume drain plan", plan.Blockers, err)
	}
	children := drainMoves(plan.Jobs[0])
	f.apply("drain-inputs-original", "drain-node", plan.Expected, NodeDrainChange{At: plan.At, ID: plan.Node, Operation: plan.Operation, AppsRoot: plan.AppsRoot, Plan: plan.Digest, Jobs: plan.Jobs}, state.Applied)
	for i, child := range children {
		if i > 0 && !startAll {
			break
		}
		directory, err := f.p.Members(f.s)
		if err != nil {
			t.Fatal(err)
		}
		report := MemberReport{Schema: 1, Cluster: f.p.Cluster, Reporter: [32]byte(f.node.Public().(ed25519.PublicKey)), Action: "drain-move-start", Node: plan.Node, Operation: plan.Operation, DrainJob: child.Begin.ID, Expected: directory.Revision, Epoch: f.s.ModuleEpoch(), RequestID: "drain-inputs-start-" + child.Begin.Scope.ID, RootRevision: f.s.Object(MembersKey).Revision}
		report.Signature = ed25519.Sign(f.node, MemberReportBytes(report))
		raw, _ := json.Marshal(report)
		cmd, err := f.p.ResolveMemberReport(f.s, report.Reporter, raw)
		if err != nil {
			t.Fatal("original child start", err)
		}
		var result state.Result
		f.s, result, err = state.ApplyTransactional(f.s, f.s.Index()+1, cmd, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
		if err != nil || result.Code != state.Applied {
			t.Fatal("original child start", result, err)
		}
	}
	return f, children
}

func TestDrainMoveInputsPrepareAllSignedGroupTargetsBeforeEitherOwnerCommit(t *testing.T) {
	f, children := drainInputsCore(t, true)
	before, _ := state.Encode(f.s)
	sets := map[string][32]byte{}
	for _, child := range children {
		selection := VolumeMoveSelection{Scope: child.Begin.Scope, ID: child.Begin.ID}
		job, move, found := f.view().Move(selection)
		if !found || move.Phase != volumes.Prepared || move.CommitRevision != 0 || move.Preparation != nil {
			t.Fatal("fixture already committed/prepared native target")
		}
		permit, err := f.p.VolumeMovePermit(f.s, job.Binding.Target.Key, VolumeMovePermitRequest{Selection: selection, Kind: "prepare-inputs"}, 10)
		if err != nil || permit.Inputs == nil {
			t.Fatal("same-group inputs required the other owner to commit first", child.Begin.Scope.ID, err)
		}
		inputs, err := f.p.VolumeMovePreparationInputs(f.s, job.Binding.Target.Key, permit, 10)
		if err != nil {
			t.Fatal("exact local input permit", err)
		}
		seen := map[string]bool{}
		for _, resource := range inputs.Resources {
			if resource.Kind != "volume" {
				continue
			}
			for _, expected := range children {
				key := deployment.ResourceKey("volume", expected.Begin.Scope.Tenant, expected.Begin.Scope.App, expected.Begin.Scope.ID)
				if resource.Key != key {
					continue
				}
				if resource.Volume == nil || *resource.Volume != expected.Begin.Target || resource.VolumeGeneration != 1 || resource.Node != expected.Begin.Target.Node || resource.Owner != expected.Begin.Target.NodeKey || resource.Source != (deployment.ObjectRef{}) {
					t.Fatal("input invented or substituted target native evidence", resource.Key)
				}
				seen[key] = true
			}
		}
		if len(seen) != len(children) || inputs.ReadSet == ([32]byte{}) {
			t.Fatal("group target omitted", seen)
		}
		sets[child.Begin.Scope.ID] = inputs.ReadSet
		if _, err = f.p.VolumeMovePermit(f.s, [32]byte(f.admin.Public().(ed25519.PublicKey)), VolumeMovePermitRequest{Selection: selection, Kind: "prepare-inputs"}, 10); err == nil {
			t.Fatal("foreign non-consumer acquired target inputs")
		}
		foreign := selection
		foreign.Scope.Tenant = "foreign"
		if _, err = f.p.VolumeMovePermit(f.s, job.Binding.Target.Key, VolumeMovePermitRequest{Selection: foreign, Kind: "prepare-inputs"}, 10); err == nil {
			t.Fatal("foreign tenant acquired group inputs")
		}
	}
	if sets["data"] == sets["logs"] {
		t.Fatal("different original child bindings shared an interchangeable read-set")
	}
	after, _ := state.Encode(f.s)
	if !bytes.Equal(before, after) {
		t.Fatal("input permit created native readiness/owner/closure")
	}
	raw, _ := state.Encode(f.s)
	restored, err := state.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, child := range children {
		permit, err := f.p.VolumeMovePermit(restored, child.Begin.Target.NodeKey, VolumeMovePermitRequest{Selection: VolumeMoveSelection{Scope: child.Begin.Scope, ID: child.Begin.ID}, Kind: "prepare-inputs"}, 10)
		if err != nil || permit.Inputs == nil || permit.Inputs.ReadSet != sets[child.Begin.Scope.ID] {
			t.Fatal("snapshot replaced original child read-set", err)
		}
	}
}

func TestDrainMoveInputsRejectMissingChildAndDifferentSignedGroup(t *testing.T) {
	f, children := drainInputsCore(t, false)
	first := children[0]
	job, _, found := f.view().Move(VolumeMoveSelection{Scope: first.Begin.Scope, ID: first.Begin.ID})
	if !found {
		t.Fatal("missing original first child")
	}
	if _, err := f.p.moveResourceReads(f.s, job); err == nil {
		t.Fatal("missing signed sibling treated as current ready native")
	}
	f, children = drainInputsCore(t, true)
	first = children[0]
	job, _, _ = f.view().Move(VolumeMoveSelection{Scope: first.Begin.Scope, ID: first.Begin.ID})
	for name, change := range map[string]func(*VolumeMove){
		"different-origin": func(j *VolumeMove) {
			j.Origin.RequestID = "other-parent"
			j.Origin.Signature = ed25519.Sign(f.admin, OperationBytes(j.Origin))
		},
		"foreign-scope": func(j *VolumeMove) { j.Binding.Scope.App = "other" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := ownMoveJob(job)
			change(&bad)
			if _, err := f.p.moveResourceReads(f.s, bad); err == nil {
				t.Fatal("foreign job borrowed signed group inputs")
			}
		})
	}
}

// No group is inferred from sharing a node, target, volume bytes or timestamp.
// The original non-drain adapter remains its own single-member group.
func TestDrainMoveInputsKeepLegacySingleMoveGroupAndOriginalTarget(t *testing.T) {
	f, begin := moveCore(t)
	f.apply("legacy-single-move", "begin-volume-move", f.core().Revision(), begin, state.Applied)
	job, _, _ := f.view().Move(VolumeMoveSelection{Scope: begin.Scope, ID: begin.ID})
	group, err := drainMoveGroup(f.view(), job)
	if err != nil || len(group) != 1 || group[0].Digest() != job.Digest() || group[0].Target != begin.Target {
		t.Fatal("legacy move selected an unrelated prepared target", err)
	}
	scope := deployment.AppScope{Cluster: begin.Scope.Cluster, Tenant: begin.Scope.Tenant, App: begin.Scope.App}
	targets, err := moveVolumeTargets(f.view(), job, scope)
	key := deployment.ResourceKey("volume", scope.Tenant, scope.App, begin.Scope.ID)
	if err != nil || len(targets) != 1 || targets[key] != begin.Target {
		t.Fatal("new input selector changed legacy single target", err)
	}
	for name, change := range map[string]func(*VolumeMove, *deployment.AppScope){
		"owner":           func(j *VolumeMove, _ *deployment.AppScope) { j.Target.NodeKey[0]++ },
		"node":            func(j *VolumeMove, _ *deployment.AppScope) { j.Target.Node = "node-c" },
		"target-scope":    func(j *VolumeMove, _ *deployment.AppScope) { j.Target.Scope.Tenant = "foreign" },
		"blueprint-scope": func(_ *VolumeMove, s *deployment.AppScope) { s.App = "foreign" },
	} {
		t.Run(name, func(t *testing.T) {
			bad, selected := ownMoveJob(job), scope
			change(&bad, &selected)
			if _, err := moveVolumeTargets(f.view(), bad, selected); err == nil {
				t.Fatal("different target owner/scope borrowed original input metadata")
			}
		})
	}
}
