// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"reflect"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/workload"
)

func aliasClaim(t *testing.T, s ComposeService) (Claim, Step) {
	t.Helper()
	step := Step{Key: "workload/task/tenant/app/web", Kind: "task", Node: "node-a", Owner: [32]byte{1}, Goal: goal(s), Dependencies: []Dependency{{Key: "network/bridge/tenant/app/front/node-a", Condition: Applied}}}
	original := GoalCommand{Schema: 1, Kind: "task", Tenant: "tenant", App: "app", Node: step.Node, Owner: step.Owner, Config: step.Goal}
	return Claim{Step: step, Command: state.Command{Kind: state.Mutate, Key: step.Key, Value: string(goal(original))}, Result: state.Result{Code: state.Applied, Index: 10, Revision: 10, Generation: 8}, Native: "container/original"}, step
}

func TestTaskAliasRuntimeUpdateAcceptsOnlyAliasChanges(t *testing.T) {
	base := ComposeService{Image: "img@sha256:" + strings.Repeat("a", 64), Networks: map[string]Attachment{"front": {IPv4: "10.1.0.5", Aliases: []string{"web"}}}}
	claim, step := aliasClaim(t, base)
	if TaskAliasRuntimeUpdate(claim, step) {
		t.Fatal("unchanged Task reported as an update instead of Keep")
	}
	for name, aliases := range map[string][]string{"renamed": {"www"}, "added": {"web", "www"}, "cleared": nil} {
		next := base
		next.Networks = map[string]Attachment{"front": {IPv4: "10.1.0.5", Aliases: aliases}}
		target := step
		target.Goal = goal(next)
		if !TaskAliasRuntimeUpdate(claim, target) {
			t.Fatal("alias-only change requires replacement", name)
		}
	}
	for name, mutate := range map[string]func(*ComposeService){
		"address": func(s *ComposeService) {
			s.Networks = map[string]Attachment{"front": {IPv4: "10.1.0.6", Aliases: []string{"www"}}}
		},
		"attach": func(s *ComposeService) { s.Networks = map[string]Attachment{"front": {IPv4: "10.1.0.5"}, "back": {}} },
		"switch network": func(s *ComposeService) {
			s.Networks = map[string]Attachment{"back": {IPv4: "10.1.0.5", Aliases: []string{"web"}}}
		},
		"image": func(s *ComposeService) {
			s.Image = "img@sha256:" + strings.Repeat("b", 64)
			s.Networks = map[string]Attachment{"front": {IPv4: "10.1.0.5"}}
		},
	} {
		next := base
		mutate(&next)
		target := step
		target.Goal = goal(next)
		if TaskAliasRuntimeUpdate(claim, target) {
			t.Fatal("non-alias change treated as alias-only", name)
		}
	}
	renamed := base
	renamed.Networks = map[string]Attachment{"front": {IPv4: "10.1.0.5", Aliases: []string{"www"}}}
	target := step
	target.Goal = goal(renamed)
	for name, change := range map[string]func(*Claim, *Step){
		"removed":   func(c *Claim, _ *Step) { c.Removed = true },
		"retained":  func(c *Claim, _ *Step) { c.Retained = true },
		"unapplied": func(c *Claim, _ *Step) { c.Result.Code = state.Forbidden },
		"kind":      func(_ *Claim, s *Step) { s.Kind = "ingress" },
		"node":      func(_ *Claim, s *Step) { s.Node = "node-b" },
		"owner":     func(_ *Claim, s *Step) { s.Owner = [32]byte{2} },
		"dependency": func(_ *Claim, s *Step) {
			s.Dependencies = []Dependency{{Key: "network/bridge/tenant/app/back/node-a", Condition: Applied}}
		},
		"activation": func(_ *Claim, s *Step) { s.Activation = []Dependency{{Key: "dns/x", Condition: Applied}} },
		"command":    func(c *Claim, _ *Step) { c.Command.Value = "{" },
	} {
		c, s := claim, target
		change(&c, &s)
		if TaskAliasRuntimeUpdate(c, s) {
			t.Fatal("alias update accepted without the exact original Task", name)
		}
	}
}

// Aliases are managed DNS names only. If the container recipe ever gains an
// alias field, an alias change would need the engine and this judgment breaks.
func TestContainerSpecCarriesNoNetworkAliases(t *testing.T) {
	var walk func(reflect.Type, string)
	seen := map[reflect.Type]bool{}
	walk = func(ty reflect.Type, path string) {
		for ty.Kind() == reflect.Pointer || ty.Kind() == reflect.Slice || ty.Kind() == reflect.Map {
			ty = ty.Elem()
		}
		if ty.Kind() != reflect.Struct || seen[ty] {
			return
		}
		seen[ty] = true
		for i := 0; i < ty.NumField(); i++ {
			f := ty.Field(i)
			if strings.Contains(strings.ToLower(f.Name), "alias") {
				t.Fatal("container recipe carries aliases", path+"."+f.Name)
			}
			walk(f.Type, path+"."+f.Name)
		}
	}
	walk(reflect.TypeOf(workload.ContainerSpec{}), "ContainerSpec")
}
