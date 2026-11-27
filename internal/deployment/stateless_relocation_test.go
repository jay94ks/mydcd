// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"encoding/json"
	"testing"
)

func TestStatelessRelocationUsesOriginalClosureBeforeNewOwnerGeneration(t *testing.T) {
	x := newInventoryFixture(t)
	x.all()
	raw, _ := json.Marshal(x.b.d.Input)
	var input Compose
	if json.Unmarshal(raw, &input) != nil {
		t.Fatal("original input")
	}
	service := input.Services["web"]
	if len(service.Volumes) != 0 {
		t.Fatal("stateless fixture unexpectedly uses a Volume")
	}
	service.Sfc.Node = "node-b"
	for alias, attachment := range service.Networks {
		gateway := mustAddr(input.Networks[alias].Sfc.Pools["node-b"].Gateway)
		attachment.IPv4 = gateway.Next().Next().String()
		service.Networks[alias] = attachment
	}
	input.Services["web"] = service
	ctx := contextFor(t, x.f)
	ctx.Current = x.shared.Objects("")
	target, err := Compile(input, x.f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	key := ResourceKey("task", "tenant", "php-mysql", "web")
	old := x.a.d.Claims[x.a.claim(key)]
	plan, err := x.a.ReplacementPlan(target, false)
	if err != nil || plan == nil || plan.BlockedCode != "" || len(plan.Waves) != 1 || plan.Waves[0].Node != "node-b" {
		t.Fatal("singleton move did not use the original replacement closure", plan, err)
	}
	x.keep(x.a.Begin(x.a.Revision(), x.f.c, ctx, target, "relocation", "submitter", 1, false))
	x.b, x.e = target, Execution{*x.a.d.Active}
	stage, _ := x.e.Stage(key)
	if stage.Previous == nil || stage.Previous.Step.Node != "node-a" || stage.Command != nil {
		t.Fatal("new owner started before original owner closure")
	}
	closeReplacementWave(t, x)
	applyReplacementWave(t, x)
	stage, _ = x.e.Stage(key)
	if stage.Result == nil || stage.Result.Generation <= old.Result.Generation || stage.Observation == nil || stage.Observation.Owner != public(x.f.nb) || !stage.Observation.Healthy {
		t.Fatal("old owner observation was reused as the new owner generation")
	}
}
