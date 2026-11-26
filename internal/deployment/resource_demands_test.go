// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"strings"
	"testing"
)

func TestPlannedMoveDemandsCreditOnlyOriginalConfigAndCIDR(t *testing.T) {
	f := makeFixture(t)
	ctx := contextFor(t, f)
	input := smallCompose(t)
	plan, err := Compile(input, f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	demands, err := plan.ResourceDemands()
	if err != nil {
		t.Fatal(err)
	}
	for _, demand := range demands {
		if demand.Network != nil && (demand.Network.Generation != 0 || demand.Network.Revision != 0) {
			t.Fatal("planned network invented committed identity")
		}
		ctx.Planned = append(ctx.Planned, PlannedResource{Origin: [32]byte{1}, Scope: plan.Scope(), Demand: demand})
		n := ctx.Nodes[demand.Node]
		n.Used.CPU += demand.Need.CPU
		n.Used.Memory += demand.Need.Memory
		ctx.Nodes[demand.Node] = n
	}
	for id, n := range ctx.Nodes {
		n.Capacity = n.Used
		ctx.Nodes[id] = n
	}
	if _, err = Compile(input, f.c, ctx); err != nil {
		t.Fatal("exact held input lost its credit", err)
	}
	db := input.Services["db"]
	db.CPUs = "1.1"
	input.Services["db"] = db
	if _, err = Compile(input, f.c, ctx); err == nil {
		t.Fatal("different config borrowed pending budget")
	}
	db.CPUs = "1"
	input.Services["db"] = db
	wrongActor := ctx
	wrongActor.Actor = "admin"
	if _, err = Compile(input, f.c, wrongActor); err == nil {
		t.Fatal("different actor borrowed held CIDR/budget")
	}
	input.Name = "different-app"
	competing := ctx
	competing.Project = input.Name
	if _, err = Compile(input, f.c, competing); err == nil || !strings.Contains(err.Error(), "GLOBAL_CIDR_CONFLICT") {
		t.Fatal("different app borrowed held CIDR", err)
	}
}

func TestPlannedMoveStaticAddressesAreHeldWithoutAllocationGeneration(t *testing.T) {
	f := makeFixture(t)
	ctx := contextFor(t, f)
	input := smallCompose(t)
	plan, err := Compile(input, f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	demands, err := plan.ResourceDemands()
	if err != nil {
		t.Fatal(err)
	}
	for _, demand := range demands {
		// Isolate address protection from CIDR and CPU credit.
		if demand.Kind == "task" {
			if len(demand.Addresses) != 1 || demand.Addresses[0].Endpoint != demand.Key+"/app/0" || demand.Addresses[0].Network == "" {
				t.Fatal("original task attachment not held", demand)
			}
			ctx.Planned = append(ctx.Planned, PlannedResource{Origin: [32]byte{2}, Scope: plan.Scope(), Demand: demand})
			n := ctx.Nodes[demand.Node]
			n.Used.CPU += demand.Need.CPU
			n.Used.Memory += demand.Need.Memory
			ctx.Nodes[demand.Node] = n
		}
	}
	if _, err = Compile(input, f.c, ctx); err != nil {
		t.Fatal("original target lost its desired address", err)
	}
	web := input.Services["web"]
	command := Arguments{"changed"}
	if web.Command != nil {
		command = append(append(Arguments(nil), (*web.Command)...), "changed")
	}
	web.Command = &command
	input.Services["web"] = web
	if _, err = Compile(input, f.c, ctx); err == nil || !strings.Contains(err.Error(), "ADDRESS_CONFLICT") {
		t.Fatal("different task config borrowed desired address", err)
	}
	input = smallCompose(t)
	input.Name = "different-app"
	ctx.Project = input.Name
	if _, err = Compile(input, f.c, ctx); err == nil || !strings.Contains(err.Error(), "ADDRESS_CONFLICT") {
		t.Fatal("different app borrowed desired address without a native allocation", err)
	}
}
