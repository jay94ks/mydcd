// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"testing"

	contract "github.com/jay94ks/seafield/lifecycle/v1"
)

func TestActionPolicyDistinguishesUnknownAndActualContainerState(t *testing.T) {
	policy := ActionPolicy{OnAlive: StopContainer, OnDead: RestartContainer}
	for _, tc := range []struct {
		status  contract.Status
		running bool
		want    ContainerAction
	}{
		{contract.Pass, true, StopContainer}, {contract.Pass, false, KeepContainer},
		{contract.Fail, true, RestartContainer}, {contract.Fail, false, StartContainer},
		{contract.Unknown, true, KeepContainer}, {contract.Unknown, false, KeepContainer},
	} {
		got, err := policy.Decide(tc.status, tc.running)
		if err != nil || got != tc.want {
			t.Fatal("result/state selected wrong Docker action", tc, got, err)
		}
	}
	if got, err := (ActionPolicy{}).Decide(contract.Fail, true); err != nil || got != KeepContainer {
		t.Fatal("omission introduced an automatic restart", got, err)
	}
	if got, err := (ActionPolicy{OnAlive: StartContainer}).Decide(contract.Pass, true); err != nil || got != KeepContainer {
		t.Fatal("already running container started again", got, err)
	}
	if got, err := policy.Decide("invalid", true); err == nil || got != KeepContainer {
		t.Fatal("invalid observation authorized an effect", got, err)
	}
	if got, err := (ActionPolicy{OnDead: "remove-volume"}).Decide(contract.Fail, true); err == nil || got != KeepContainer {
		t.Fatal("unsupported control action accepted", got, err)
	}
}

func TestContainerActionsBelongToOneServiceLivenessCheck(t *testing.T) {
	policy := &ActionPolicy{OnDead: RestartContainer}
	check := Check{ID: "alive", Phase: contract.Liveness, Template: Template{Builtin: "docker_health"}, Actions: policy}
	p := Program{Services: map[string][]Check{"web": {check}}}
	resolved, err := ResolveProgram("tenant", p, nil, programDefaults(), 2000)
	if err != nil || resolved.Services["web"][0].Actions == nil {
		t.Fatal(resolved, err)
	}
	policy.OnDead = StopContainer
	if resolved.Services["web"][0].Actions.OnDead != RestartContainer {
		t.Fatal("input alias changed the accepted action")
	}
	duplicate := check
	duplicate.ID = "another"
	p.Services["web"] = []Check{check, duplicate}
	if _, err = CheckProgram(p, programDefaults(), 2000); err == nil {
		t.Fatal("two action owners for one service admitted")
	}
	check.Phase = contract.Readiness
	p.Services["web"] = []Check{check}
	if _, err = CheckProgram(p, programDefaults(), 2000); err == nil {
		t.Fatal("readiness check gained container control")
	}
	p.Services["web"] = nil
	p.Checks = []Check{{ID: "app", Phase: contract.Liveness, Template: Template{Builtin: "depends_on"}, Actions: policy}}
	if _, err = CheckProgram(p, programDefaults(), 2000); err == nil {
		t.Fatal("app aggregate could choose an implicit container target")
	}
}

func TestActionPolicySurvivesFrozenProgramAndTaskProjection(t *testing.T) {
	book, p, inline, _ := frozenProgramFixture(t)
	checks := p.Services["alpha"]
	checks[0].Phase = contract.Liveness
	checks[0].Actions = &ActionPolicy{OnDead: RestartContainer}
	p.Services["alpha"] = checks
	frozen, err := FreezeProgram("tenant", p, book, inline, programDefaults())
	if err != nil {
		t.Fatal(err)
	}
	task, err := frozen.Task("alpha")
	if err != nil || task.Validate(book.Cluster()) != nil || task.Checks[0].Actions == nil || task.Checks[0].Actions.OnDead != RestartContainer {
		t.Fatal("accepted policy lost at Task projection", task, err)
	}
	task.Checks[0].Actions.OnDead = StopContainer
	if frozen.Program.Services["alpha"][0].Actions.OnDead != RestartContainer {
		t.Fatal("Task view changed the frozen app policy")
	}
	task.Checks[0].Actions.OnDead = "invalid"
	if task.Validate(book.Cluster()) == nil {
		t.Fatal("stored Task accepted a modified invalid policy")
	}
}
