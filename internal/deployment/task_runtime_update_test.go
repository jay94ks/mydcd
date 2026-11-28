// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/workload"
)

// An alias-only redeploy keeps every Task's container: no retirement, the
// Task objects mutate under the same generation, and its inputs keep the
// reference they were made for.
func TestAliasOnlyRedeployUpdatesTasksInPlace(t *testing.T) {
	var before map[string]Claim
	x := redeployedFixture(t, nil, func(input *Compose) {
		web := input.Services["web"]
		attachment := web.Networks["app"]
		attachment.Aliases = append(attachment.Aliases, "www")
		web.Networks["app"] = attachment
		input.Services["web"] = web
	}, nil)
	before = map[string]Claim{}
	for _, c := range x.a.Claims() {
		before[c.Step.Key] = c
	}
	if _, retiring := x.a.Retirement(); retiring || x.e.d.Replacement != nil {
		t.Fatal("alias change stopped a container")
	}
	changes, err := x.a.Changes(x.b, false)
	if err != nil {
		t.Fatal(err)
	}
	updated := map[string]bool{}
	for _, c := range changes {
		switch {
		case c.Action == "RuntimeUpdate" && before[c.Key].Step.Kind == "task":
			updated[c.Key] = true
			if c.Interruption != "" {
				t.Fatal("in-place alias update reported an interruption", c)
			}
		case c.Action != "Keep" && c.Action != "RuntimeUpdate":
			t.Fatal("alias change replaced", c.Key, c.Action, c.Reason)
		}
	}
	if len(updated) != 2 {
		t.Fatalf("%d Tasks updated in place, want 2: %+v", len(updated), changes)
	}
	for round := 0; round < 32; round++ {
		pending := false
		for _, step := range x.b.Steps() {
			stage, _ := x.e.Stage(step.Key)
			if stage.Result != nil {
				continue
			}
			pending = true
			if x.e.dependencies(x.e.index(step.Key), x.now) {
				x.completeStep(step.Key)
			}
		}
		if !pending {
			break
		}
	}
	x.save(x.e.Finish(x.e.Revision(), x.now))
	x.sync()
	if x.e.Status() != "Succeeded" {
		t.Fatalf("status %s", x.e.Status())
	}
	for key, old := range before {
		if old.Step.Kind != "task" && old.Step.Kind != "inputs" {
			continue
		}
		stage, _ := x.e.Stage(key)
		if stage.Result == nil || stage.Result.Code != state.Applied || stage.Result.Generation != old.Result.Generation {
			t.Fatal("alias update made a new generation", key)
		}
		if updated[key] && stage.Result.Revision <= old.Result.Revision {
			t.Fatal("Task object did not take the new aliases", key)
		}
		if old.Step.Kind == "inputs" && (stage.Result.Revision != old.Result.Revision || !stage.Noop) {
			t.Fatal("inputs followed an alias change", key)
		}
	}
}

// attachFixture deploys the replica fixture with web as one Task and a
// second TUN network "extra" declared but unused, then redeploys it with web
// attached to it. (A replica's resolv.conf lists every managed network's
// DNS, so attaching one to replicas changes the recipe and replaces them.)
func attachFixture(t *testing.T) *inventoryFixture {
	t.Helper()
	return redeployedFixtureIn(t, func(f *fixture, input *Compose, ctx *PlanningContext) {
		quotas, _ := tenancy.NewQuotas(f.cluster)
		for _, scope := range []string{"", "tenant"} {
			for _, node := range []string{"node-a", "node-b"} {
				var err error
				quotas, err = quotas.Set(f.c, "admin", 0, tenancy.NodeLimit{Tenant: scope, Node: node, Owner: ctx.Nodes[node].Key, Networks: 4, Capacity: workload.Resources{CPU: 4e9, Memory: 4 << 30}, MaxConsumers: 8, PacketQueuePackets: 8, PacketQueueBytes: 16384}, ctx.Networks)
				if err != nil {
					t.Fatal(err)
				}
			}
		}
		d := tenancy.TUNDefinition{Tenant: "tenant", Name: "extra-services"}
		for i, node := range []string{"node-a", "node-b"} {
			prefix := netip.MustParsePrefix(fmt.Sprintf("10.99.%d.0/24", i+1))
			d.Members = append(d.Members, tenancy.TUNNode{Node: node, Owner: ctx.Nodes[node].Key, Pools: []tenancy.Subnet{{ID: "pool", Prefix: prefix, Gateway: prefix.Addr().Next(), MTU: 1400}}})
		}
		var err error
		ctx.Networks, err = ctx.Networks.CreateTUN(f.c, quotas, "alice", ctx.Networks.Revision(), d)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := ctx.Networks.TUNSources("tenant", d.Name)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			raw, _ := json.Marshal(row.Bridge)
			ctx.Current[row.BridgeKey] = state.Object{Present: true, Revision: 51, Generation: 47, Value: string(raw)}
			raw, _ = json.Marshal(row.Tunnel)
			ctx.Current[row.TunnelKey] = state.Object{Present: true, Revision: 52, Generation: 48, Value: string(raw)}
		}
		source := services.ManagedDNSSource{Schema: 1, Cluster: f.cluster, Principal: "alice", Definition: services.ManagedDNSDefinition{Schema: 1, Tenant: "tenant", Network: d.Name, Policy: services.ManagedDNSPolicy{Enabled: true, Zone: "extra.sfc.test."}}}
		raw, _ := json.Marshal(source)
		ctx.Current[services.ManagedDNSKey("tenant", d.Name)] = state.Object{Present: true, Generation: 61, Revision: 63, Value: string(raw)}
		input.Networks["extra"] = ComposeNetwork{External: true, Name: d.Name}
		web := input.Services["web"]
		web.Sfc.Node, web.Sfc.Nodes, web.Sfc.PerNode = "node-a", nil, 0
		input.Services["web"] = web
	}, func(input *Compose) {
		web := input.Services["web"]
		web.Networks["extra"] = Attachment{}
		input.Services["web"] = web
	}, nil)
}

// Attaching a network keeps the web container: its Tasks mutate under the
// same generation once the new network's steps are ready.
func TestNetworkAttachRedeployUpdatesTasksInPlace(t *testing.T) {
	x := attachFixture(t)
	before := map[string]Claim{}
	for _, c := range x.a.Claims() {
		before[c.Step.Key] = c
	}
	changes, err := x.a.Changes(x.b, false)
	if _, retiring := x.a.Retirement(); retiring || x.e.d.Replacement != nil {
		t.Fatalf("network attach stopped a container: %+v", changes)
	}
	if err != nil {
		t.Fatal(err)
	}
	updated := map[string]bool{}
	for _, c := range changes {
		switch {
		case c.Action == "RuntimeUpdate" && before[c.Key].Step.Kind == "task":
			updated[c.Key] = true
		case c.Action == "Replace" || c.Action == "Remove":
			t.Fatal("network attach replaced", c.Key, c.Action, c.Reason)
		}
	}
	if len(updated) != 1 {
		t.Fatalf("%d Tasks updated in place, want 1: %+v", len(updated), changes)
	}
	for round := 0; round < 32; round++ {
		pending := false
		for _, step := range x.b.Steps() {
			stage, _ := x.e.Stage(step.Key)
			if stage.Result != nil {
				continue
			}
			pending = true
			if x.e.dependencies(x.e.index(step.Key), x.now) {
				x.completeStep(step.Key)
			}
		}
		if !pending {
			break
		}
	}
	x.save(x.e.Finish(x.e.Revision(), x.now))
	x.sync()
	if x.e.Status() != "Succeeded" {
		t.Fatalf("status %s", x.e.Status())
	}
	for key := range updated {
		stage, _ := x.e.Stage(key)
		if stage.Result == nil || stage.Result.Generation != before[key].Result.Generation || stage.Result.Revision <= before[key].Result.Revision {
			t.Fatal("network attach made a new generation", key)
		}
		var service ComposeService
		var g GoalCommand
		_ = json.Unmarshal([]byte(stage.Command.Value), &g)
		_ = json.Unmarshal(g.Config, &service)
		if a, ok := service.Networks["extra"]; !ok || a.IPv4 == "" {
			t.Fatal("attached network has no address", key, service.Networks)
		}
	}
}
