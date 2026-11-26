// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"slices"
	"testing"
)

func TestRetirementImpactPreviewUsesTheActualClosureAndOwnsItsClaims(t *testing.T) {
	x := newInventoryFixture(t)
	x.all()
	key := ResourceKey("task", "tenant", "php-mysql", "db")
	before, err := x.a.Encode()
	if err != nil {
		t.Fatal(err)
	}
	preview, err := x.a.PreviewRetirement([]string{key, key}, false)
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, claim := range preview {
		keys = append(keys, claim.Step.Key)
		if claim.Step.Kind == "volume" || claim.Step.Kind == "bridge" {
			t.Fatal("task recreation selected retained data or unrelated network")
		}
	}
	if !slices.IsSorted(keys) || len(slices.Compact(slices.Clone(keys))) != len(keys) {
		t.Fatal("preview was nondeterministic or duplicated a dependent")
	}
	for _, kind := range []string{"task", "inputs"} {
		for _, service := range []string{"db", "web"} {
			if !slices.Contains(keys, ResourceKey(kind, "tenant", "php-mysql", service)) {
				t.Fatal("preview hid affected service/input", kind, service)
			}
		}
	}
	if len(preview) == 0 {
		t.Fatal("empty impact")
	}
	preview[0].Command.Value = "foreign-command"
	preview[0].Step.Key = "foreign-key"
	after, err := x.a.Encode()
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("preview changed original inventory", err)
	}
	x.keep(x.a.Retire(x.a.Revision(), x.f.c, "alice", "recreate", "submitter", 1, []string{key}, false))
	actual, ok := x.a.Retirement()
	if !ok || len(actual.Targets) != len(keys) {
		t.Fatal("actual retirement differs from advertised impact")
	}
	for _, target := range actual.Targets {
		if !slices.Contains(keys, target.Original.Step.Key) {
			t.Fatal("actual retirement expanded beyond its preview")
		}
	}
	if _, err := x.a.PreviewRetirement([]string{key}, false); err == nil {
		t.Fatal("in-progress retirement accepted a second impact plan")
	}
}

func TestRetirementImpactPreviewRejectsUnsettledAndMissingTargets(t *testing.T) {
	x := newInventoryFixture(t)
	key := ResourceKey("task", "tenant", "php-mysql", "db")
	x.before(key)
	x.completeStep(key)
	x.sync()
	if _, err := x.a.PreviewRetirement([]string{key}, false); err == nil {
		t.Fatal("unsettled initial operation claimed a stable recreation target")
	}
	for _, step := range x.b.Steps() {
		stage, _ := x.e.Stage(step.Key)
		if stage.Result == nil {
			x.completeStep(step.Key)
		}
	}
	x.save(x.e.Finish(x.e.Revision(), x.now))
	x.sync()
	for _, keys := range [][]string{nil, {}, {"foreign"}, {key, "foreign"}} {
		if _, err := x.a.PreviewRetirement(keys, false); err == nil {
			t.Fatal("missing or empty recreation target accepted", keys)
		}
	}
	all, err := x.a.PreviewRetirement(nil, true)
	if err != nil || len(all) != len(x.a.Claims()) {
		t.Fatal("full stop impact omitted current claims", err)
	}
}
