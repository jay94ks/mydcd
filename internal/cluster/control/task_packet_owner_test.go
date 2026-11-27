// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
)

func rotateTaskPacketCoreOwner(t *testing.T, f *backupCoreFixture) ed25519.PrivateKey {
	t.Helper()
	_, configuration := cleanupControlIssuer(t, f)
	d, _ := f.p.Members(f.s)
	nodeCoreReport(t, f, MemberReport{Action: "configuration", Node: "node-a", Expected: d.Revision, Configuration: &configuration}, state.Applied)
	old := f.node
	next := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{193}, ed25519.SeedSize))
	d, _ = f.p.Members(f.s)
	entry, _ := d.Entry("node-a")
	f.apply("packet-owner-rotate", "rotate-node-identity", entry.Revision, NodeIdentityChange{ID: "node-a", Operation: "packet-owner-rotate"}, state.Applied)
	proof := lifecycle.IdentityProof{Schema: 1, Cluster: f.p.Cluster, Node: "node-a", Operation: "packet-owner-rotate", Old: [32]byte(old.Public().(ed25519.PublicKey)), New: [32]byte(next.Public().(ed25519.PublicKey)), Prepared: [32]byte{1}}
	proof.OldSignature = ed25519.Sign(old, lifecycle.IdentityProofBytes(proof))
	proof.NewSignature = ed25519.Sign(next, lifecycle.IdentityProofBytes(proof))
	for _, action := range []string{"identity-prepared", "identity-activate", "identity-installed"} {
		d, _ = f.p.Members(f.s)
		key := old
		if action == "identity-installed" {
			key = next
		}
		r := MemberReport{Schema: 1, Cluster: f.p.Cluster, Reporter: [32]byte(key.Public().(ed25519.PublicKey)), Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(MembersKey).Revision, RequestID: fmt.Sprintf("packet-owner-%s", action), Action: action, Node: "node-a", Operation: "packet-owner-rotate", Expected: d.Revision}
		if action == "identity-prepared" {
			r.Identity = &proof
		}
		r.Signature = ed25519.Sign(key, MemberReportBytes(r))
		command, err := r.Command()
		if err != nil {
			t.Fatal(err)
		}
		nextState, result, err := state.ApplyTransactional(f.s, f.s.Index()+1, command, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
		if err != nil || result.Code != state.Applied {
			t.Fatal(action, result, err)
		}
		f.s = nextState
	}
	f.node = next
	return old
}

func TestRotatedTaskPacketOwnerUsesExactOriginalNetworkAndDNS(t *testing.T) {
	f := managedDNSTaskCoreFixture(t)
	original := managedDNSTaskCoreBegin(t, f, "original-packet", "10.80.1.10", "original-packet")
	managedDNSTaskCoreSubmit(t, f, "original-packet", deployment.ResourceKey("network-ref", "tenant", "original-packet", "lan/node-a"), true, state.Applied)
	managedDNSTaskCoreSubmit(t, f, "original-packet", original, true, state.Applied)
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	before, err := f.p.ProjectResources(f.s)
	oldAllocation, found := before.Addresses.Allocation(original + "/lan/0")
	oldSource := f.s.Object("control/network-sources/bridge/tenant/services/node-a")
	if err != nil || !found {
		t.Fatal("original packet allocation", err)
	}
	old := rotateTaskPacketCoreOwner(t, f)
	oldOwner, current := [32]byte(old.Public().(ed25519.PublicKey)), [32]byte(f.node.Public().(ed25519.PublicKey))
	task := managedDNSTaskCoreBegin(t, f, "new-packet", "10.80.1.12", "new-packet")
	submitTaskPacketCoreRetainedStep(t, f, "new-packet", deployment.ResourceKey("network-ref", "tenant", "new-packet", "lan/node-a"), old)
	managedDNSTaskCoreSubmit(t, f, "new-packet", task, true, state.Applied)
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	projection, err := f.p.ProjectResources(f.s)
	allocation, found := projection.Addresses.Allocation(task + "/lan/0")
	goal := projection.Goals[task].Goal
	if err != nil || !found || goal.Owner != current || len(goal.ResourceKeys) == 0 || allocation.Owner != hex.EncodeToString(oldOwner[:]) || allocation.Generation != f.s.Object(task).Generation {
		t.Fatal("new Task signer and original packet owner were conflated", err)
	}
	retained, found := projection.Addresses.Allocation(original + "/lan/0")
	if !found || retained != oldAllocation || f.s.Object("control/network-sources/bridge/tenant/services/node-a") != oldSource {
		t.Fatal("new Task rewrote original endpoint or native source")
	}
	owner, err := f.p.taskPacketOwner(f.s, goal, "lan", f.s.Objects(""))
	if err != nil || owner != oldOwner {
		t.Fatal("exact borrowed packet owner", err)
	}
	required, err := f.p.ManagedTaskDNS(f.s, deployment.ObjectRef{Key: task, Generation: f.s.Object(task).Generation, Revision: f.s.Object(task).Revision})
	if err != nil || len(required) != 1 {
		t.Fatal("new Task lost original native DNS requirement", err)
	}
	permit, err := f.p.NativePermit(f.s, current, NativeRequest{Source: required[0].Source, DNS: required[0].Config.ID})
	if err != nil || permit.Owner != oldOwner || permit.Kind != "dns" {
		t.Fatal("current-key permit did not preserve native DNS owner", err)
	}
	for _, caller := range [][32]byte{oldOwner, {99}} {
		if _, err := f.p.NativePermit(f.s, caller, NativeRequest{Source: required[0].Source, DNS: required[0].Config.ID}); err == nil {
			t.Fatal("old/unrelated key obtained current DNS permission")
		}
	}
	objects := f.s.Objects("")
	for _, mutation := range []struct {
		name  string
		apply func(*deployment.GoalCommand)
	}{
		{"missing-lineage", func(g *deployment.GoalCommand) { g.ResourceKeys = nil }},
		{"uninstalled-proof-index", func(g *deployment.GoalCommand) { g.ResourceKeys[0].Index++ }},
		{"foreign-node", func(g *deployment.GoalCommand) { g.Node = "node-b" }},
		{"foreign-tenant", func(g *deployment.GoalCommand) { g.Tenant = "other" }},
		{"missing-read-set", func(g *deployment.GoalCommand) { g.Dependencies = nil }},
		{"stale-read-set", func(g *deployment.GoalCommand) { g.Dependencies[0].Revision++ }},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			g := goal
			g.ResourceKeys = lifecycle.OwnIdentityTransitions(goal.ResourceKeys)
			g.Dependencies = slices.Clone(goal.Dependencies)
			mutation.apply(&g)
			if _, err := f.p.taskPacketOwner(f.s, g, "lan", objects); err == nil {
				t.Fatal("invalid Task packet owner mapping admitted")
			}
		})
	}
	badObjects := maps.Clone(objects)
	refKey := deployment.ResourceKey("network-ref", goal.Tenant, goal.App, "lan/"+goal.Node)
	object := badObjects[refKey]
	var refGoal deployment.GoalCommand
	_ = json.Unmarshal([]byte(object.Value), &refGoal)
	var ref deployment.NetworkReference
	_ = json.Unmarshal(refGoal.Config, &ref)
	ref.Spec[0]++
	refGoal.Config, _ = json.Marshal(ref)
	value, _ := json.Marshal(refGoal)
	object.Value = string(value)
	badObjects[refKey] = object
	if _, err := f.p.taskPacketOwner(f.s, goal, "lan", badObjects); err == nil {
		t.Fatal("changed original native spec hash was accepted")
	}
	apps, _ := f.p.Apps(f.s)
	inventory, _ := apps.Inventory("tenant", "new-packet")
	var taskClaim deployment.Claim
	for _, claim := range inventory.Claims() {
		if claim.Step.Key == task {
			taskClaim = claim
		}
	}
	if !closedTaskPacketOwner(inventory, taskClaim, allocation, oldOwner) || closedTaskPacketOwner(inventory, taskClaim, allocation, current) || closedTaskPacketOwner(inventory, taskClaim, allocation, [32]byte{99}) {
		t.Fatal("positive address settlement lost exact original native network owner")
	}
	managedDNSChange(t, f, "down-new-packet", "down-app", inventory.Revision(), AppDown{Tenant: "tenant", App: "new-packet", Operation: "down-new-packet"}, state.Applied)
	apps, _ = f.p.Apps(f.s)
	refKey = deployment.ResourceKey("network-ref", "tenant", "new-packet", "lan/node-a")
	retainedAllocations, err := apps.NetworkRetirementAllocations("tenant", "new-packet", refKey)
	if err != nil || len(retainedAllocations) != 1 || retainedAllocations[0] != allocation {
		t.Fatal("current Task retirement did not preserve its exact original-native address", err, retainedAllocations)
	}
	closing, err := f.p.ProjectResources(f.s)
	stillHeld, found := closing.Addresses.Allocation(task + "/lan/0")
	if err != nil || !found || stillHeld != allocation {
		t.Fatal("accepted down returned an address before positive original closure", err)
	}
}

// Outer progress authenticates with the current node, while the borrowed
// native reference's positive fact remains signed by its original owner.
func submitTaskPacketCoreRetainedStep(t *testing.T, f *backupCoreFixture, app, key string, native ed25519.PrivateKey) {
	t.Helper()
	command := managedDNSTaskCoreSubmit(t, f, app, key, false, state.Applied)
	managedDNSTaskCoreProgress(t, f, app, "collect", key, nil)
	apps, _ := f.p.Apps(f.s)
	inventory, _ := apps.Inventory("tenant", app)
	execution, _ := apps.Execution("tenant", app)
	summary, _ := inventory.Active()
	stage, _ := execution.Stage(key)
	if stage.Result == nil || stage.Result.Code != state.Applied {
		t.Fatal("original retained reference result missing")
	}
	observation := deployment.Observation{Cluster: f.p.Cluster, Plan: summary.Plan, Operation: execution.ActiveOperation(), Key: key, Native: "mock-native-" + app, Owner: [32]byte(native.Public().(ed25519.PublicKey)), Command: state.Digest(command), Generation: stage.Result.Generation, Revision: stage.Result.Revision, Sequence: 1, At: 10, Applied: true, Healthy: true}
	observation.Signature = ed25519.Sign(native, deployment.ObservationBytes(observation))
	managedDNSTaskCoreProgress(t, f, app, "observe", key, &observation)
}

func TestRotatedReplicaDNSUsesCurrentWorkEligibility(t *testing.T) {
	f := managedDNSTaskCoreFixture(t)
	const app = "rotated-replicas"
	managedDNSTaskCoreBegin(t, f, app, "10.80.1.2", "replicas", func(c *deployment.Compose, _ *deployment.PlanningContext) {
		service := c.Services["web"]
		service.Sfc.Node, service.Sfc.Nodes, service.Sfc.PerNode = "", []string{"node-a"}, 2
		attachment := service.Networks["lan"]
		attachment.IPv4 = ""
		service.Networks["lan"] = attachment
		c.Services["web"] = service
	})
	managedDNSTaskCoreSubmit(t, f, app, deployment.ResourceKey("network-ref", "tenant", app, "lan/node-a"), true, state.Applied)
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	for _, id := range []string{"web/node-a/r1", "web/node-a/r2"} {
		managedDNSTaskCoreSubmit(t, f, app, deployment.ResourceKey("task", "tenant", app, id), true, state.Applied)
	}
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	oldOwner := [32]byte(f.node.Public().(ed25519.PublicKey))
	apps, _ := f.p.Apps(f.s)
	_, owners, known := apps.NetworkDNS(oldOwner)
	if !known || len(owners) != 1 {
		t.Fatal("original DNS owner missing")
	}
	before, _ := json.Marshal(apps.network.Groups)
	rotateTaskPacketCoreOwner(t, f)
	unavailable, err := f.p.AppDNSUnavailable(f.s, owners[0].Config, 10)
	if err != nil || len(unavailable) != 0 {
		t.Fatal("rotation suspended valid original replica facts", err, unavailable)
	}
	members, _ := f.p.Members(f.s)
	topology, _ := members.Topology()
	node, _ := topology.Node("node-a")
	f.apply("packet-dns-isolate", "isolate-node", node.Revision, NodeLifecycleChange{ID: "node-a", Operation: "packet-dns-isolate", Epoch: topology.Epoch()}, state.Applied)
	unavailable, err = f.p.AppDNSUnavailable(f.s, owners[0].Config, 10)
	if err != nil || len(unavailable) != 2 {
		t.Fatal("current work isolation retained old-key DNS serving", err, unavailable)
	}
	apps, _ = f.p.Apps(f.s)
	after, _ := json.Marshal(apps.network.Groups)
	if !bytes.Equal(before, after) {
		t.Fatal("current work gating rewrote original DNS ownership")
	}
}
