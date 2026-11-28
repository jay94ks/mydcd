// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
)

func networkDeps(names ...string) []Dependency {
	var out []Dependency
	for _, name := range names {
		out = append(out, Dependency{Key: ResourceKey("bridge", "tenant", "app", name+"/node-a"), Condition: Applied})
	}
	return out
}

func TestTaskNetworkRuntimeUpdateAcceptsOnlyExtraNetworkAttachAndDetach(t *testing.T) {
	image := "img@sha256:" + strings.Repeat("a", 64)
	base := ComposeService{Image: image, Networks: map[string]Attachment{"a-front": {IPv4: "10.1.0.5", Aliases: []string{"web"}}}}
	claim, step := aliasClaim(t, base)
	claim.Step.Dependencies = networkDeps("a-front")
	step.Dependencies = networkDeps("a-front")
	if TaskNetworkRuntimeUpdate(claim, step) {
		t.Fatal("unchanged Task reported as a network update")
	}
	attach := func(s ComposeService, deps []Dependency) Step {
		target := step
		target.Goal, target.Dependencies = goal(s), deps
		return target
	}
	two := base
	two.Networks = map[string]Attachment{"a-front": base.Networks["a-front"], "b-back": {IPv4: "10.2.0.5"}}
	if !TaskNetworkRuntimeUpdate(claim, attach(two, networkDeps("a-front", "b-back"))) {
		t.Fatal("attaching an extra network requires replacement")
	}
	withDNS := networkDeps("a-front", "b-back")
	withDNS = append(withDNS, Dependency{Key: ResourceKey("dns", "tenant", "app", "b-back/node-a"), Condition: Committed})
	target := attach(two, withDNS)
	target.Activation = []Dependency{{Key: ResourceKey("dns", "tenant", "app", "b-back/node-a"), Condition: Applied}}
	if !TaskNetworkRuntimeUpdate(claim, target) {
		t.Fatal("the attached network's DNS step blocked an in-place attach")
	}
	// Detaching the extra network again, from a two-network original.
	twoClaim, _ := aliasClaim(t, two)
	twoClaim.Step.Dependencies = networkDeps("a-front", "b-back")
	if !TaskNetworkRuntimeUpdate(twoClaim, attach(base, networkDeps("a-front"))) {
		t.Fatal("detaching an extra network requires replacement")
	}
	for name, next := range map[string]struct {
		s    ComposeService
		deps []Dependency
	}{
		"alias only":           {ComposeService{Image: image, Networks: map[string]Attachment{"a-front": {IPv4: "10.1.0.5", Aliases: []string{"www"}}}}, networkDeps("a-front")},
		"kept address":         {ComposeService{Image: image, Networks: map[string]Attachment{"a-front": {IPv4: "10.1.0.6"}, "b-back": {}}}, networkDeps("a-front", "b-back")},
		"new primary":          {ComposeService{Image: image, Networks: map[string]Attachment{"0-first": {}, "a-front": base.Networks["a-front"]}}, networkDeps("0-first", "a-front")},
		"switch primary":       {ComposeService{Image: image, Networks: map[string]Attachment{"b-back": {}}}, networkDeps("b-back")},
		"image":                {ComposeService{Image: "img@sha256:" + strings.Repeat("b", 64), Networks: two.Networks}, networkDeps("a-front", "b-back")},
		"volume":               {ComposeService{Image: image, Networks: two.Networks, Volumes: Mounts{{Type: "volume", Source: "data", Target: "/data"}}}, networkDeps("a-front", "b-back")},
		"other dependency":     {two, append(networkDeps("a-front", "b-back"), Dependency{Key: ResourceKey("volume", "tenant", "app", "data"), Condition: Applied})},
		"foreign network step": {two, append(networkDeps("a-front", "b-back"), Dependency{Key: ResourceKey("bridge", "tenant", "app", "c-other/node-a"), Condition: Applied})},
	} {
		if TaskNetworkRuntimeUpdate(claim, attach(next.s, next.deps)) {
			t.Fatal("change treated as an in-place network update", name)
		}
	}
	for name, change := range map[string]func(*Claim, *Step){
		"removed":   func(c *Claim, _ *Step) { c.Removed = true },
		"unapplied": func(c *Claim, _ *Step) { c.Result.Code = state.Forbidden },
		"node":      func(_ *Claim, s *Step) { s.Node = "node-b" },
		"identity":  func(_ *Claim, s *Step) { s.Identity = []string{"x"} },
		"command":   func(c *Claim, _ *Step) { c.Command.Value = "{" },
	} {
		c, s := claim, attach(two, networkDeps("a-front", "b-back"))
		change(&c, &s)
		if TaskNetworkRuntimeUpdate(c, s) {
			t.Fatal("network update accepted without the exact original Task", name)
		}
	}
}
