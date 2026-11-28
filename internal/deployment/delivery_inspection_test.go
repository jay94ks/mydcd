// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestCDInspectionSeparatesGitCandidateFromAppliedValueAndSingleImageDiff(t *testing.T) {
	f := newDeliveryFixture(t, "manual")
	first := f.receive(f.body)
	f.approve()
	f.start("inspection-first")
	f.completeDelivery()
	input, err := ParseApp(f.body)
	if err != nil {
		t.Fatal(err)
	}
	previous := input.Services["web"].Image
	service := input.Services["web"]
	service.Image = strings.Split(previous, "@sha256:")[0] + "@sha256:" + strings.Repeat("c", 64)
	if service.Image == previous {
		t.Fatal("fixture image did not change")
	}
	input.Services["web"] = service
	raw, err := yaml.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	second := f.receive(raw)
	view, err := f.d.FieldValues([]string{"services", "web", "image"})
	if err != nil || view.SourceCommit != second || view.CurrentCommit != first || !view.Source.Present || !view.Current.Present || !bytes.Equal(view.Source.Value, goal(service.Image)) || !bytes.Equal(view.Current.Value, goal(previous)) {
		t.Fatal("candidate was reported as already applied", view, err)
	}
	changes, err := f.d.ServiceChanges()
	if err != nil || len(changes) != 1 || changes[0].Service != "web" || changes[0].Action != "changed" || !slices.Equal(changes[0].Path, []string{"services", "web", "image"}) || !bytes.Equal(changes[0].Before.Value, goal(previous)) || !bytes.Equal(changes[0].After.Value, goal(service.Image)) {
		t.Fatal("one image line became resource/CAS changes", changes, err)
	}
	// Owned public output cannot modify accepted input or the next read.
	changes[0].After.Value[0] = '!'
	again, err := f.d.ServiceChanges()
	if err != nil || !json.Valid(again[0].After.Value) {
		t.Fatal("diff retained caller bytes", err)
	}
}

func TestCDFieldInspectionShowsOverrideAndDistinguishesAbsentNull(t *testing.T) {
	f, ctx, d, _ := completedRegisteredApp(t)
	key := ResourceKey("task", "tenant", d.Inventory().Scope().App, "web")
	current := ctx.Current[key]
	path := []string{"services", "web", "environment", "APP_MODE"}
	prior, err := d.FieldValues(path)
	if err != nil {
		t.Fatal(err)
	}
	updated, err := d.PutOverride(d.Revision(), 0, f.c, ctx, "alice", path, goal("debug"), []ObjectRef{{key, current.Revision, current.Generation}})
	if err != nil {
		t.Fatal(err)
	}
	view, err := updated.FieldValues(path)
	if err != nil || !bytes.Equal(view.Source.Value, prior.Source.Value) || view.Source.Present != prior.Source.Present || !bytes.Equal(view.Current.Value, goal("debug")) {
		t.Fatal("override changed Git field value", view, err)
	}
	if _, err = updated.FieldValues([]string{"services", "web", "x-sfc", "secrets"}); err == nil {
		t.Fatal("nonwhitelisted secret selector read")
	}
	tree := map[string]any{"present": nil}
	if !publicField(tree, []string{"present"}).Present || string(publicField(tree, []string{"present"}).Value) != "null" || publicField(tree, []string{"absent"}).Present {
		t.Fatal("absent and null conflated")
	}
}

func TestCDServiceDiffUsesDeterministicStructuralAddRemoveRows(t *testing.T) {
	a := Compose{Services: map[string]ComposeService{"old": {Image: "old"}, "web": {Environment: Environment{"KEY": "old"}}}}
	b := Compose{Services: map[string]ComposeService{"new": {Image: "new"}, "web": {Environment: Environment{"KEY": "new"}}}}
	rows, err := serviceChanges(a, b)
	if err != nil || len(rows) != 3 || rows[0].Action != "added" || rows[0].Service != "new" || rows[1].Action != "removed" || rows[1].Service != "old" || !slices.Equal(rows[2].Path, []string{"services", "web", "environment", "KEY"}) {
		t.Fatal(rows, err)
	}
}
