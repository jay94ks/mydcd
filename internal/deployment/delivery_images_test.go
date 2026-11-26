// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestDeliveryImagePlansKeepQueuedAndLastSuccessfulImagesOwned(t *testing.T) {
	f := newTransitionFixture(t, false, false)
	f.receive(f.imageChange("b"))
	var candidate, success bool
	for _, selected := range f.d.ImagePlans() {
		for _, step := range selected.Plan.Steps() {
			if step.Kind != "task" {
				continue
			}
			var service ComposeService
			if json.Unmarshal(step.Goal, &service) != nil {
				t.Fatal("frozen task config")
			}
			if selected.Kind == "cd-candidate" && strings.Contains(service.Image, strings.Repeat("b", 64)) {
				candidate = true
			}
			if selected.Kind == "cd-last-success" && strings.Contains(service.Image, strings.Repeat("a", 64)) {
				success = true
			}
			clear(step.Goal)
		}
	}
	if !candidate || !success {
		t.Fatal("queued candidate or continuity image omitted")
	}
	encoded, err := f.d.Encode()
	if err != nil {
		t.Fatal("view mutated authoritative plan", err)
	}
	restored, err := DecodeDelivery(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(restored.ImagePlans()) != len(f.d.ImagePlans()) {
		t.Fatal("retained references lost across checkpoint")
	}
}

func TestHistoricalAppFieldsReuseOverlayCoreWithoutForgingCurrentOwnerAnchors(t *testing.T) {
	f := newDeliveryFixture(t, "manual")
	scope := f.d.Inventory().Scope()
	value, _ := json.Marshal("docker.io/library/mysql@sha256:" + strings.Repeat("b", 64))
	field := AppFieldOverlay{Path: []string{"services", "db", "image"}, Value: value, Revision: 1, Actor: "alice"}
	before := bytes.Clone(f.body)
	input, err := RestoreAppInput(f.body, nil, scope, []AppFieldOverlay{field})
	if err != nil || input.Services["db"].Image != "docker.io/library/mysql@sha256:"+strings.Repeat("b", 64) {
		t.Fatal("historical effective value", err)
	}
	if !bytes.Equal(before, f.body) {
		t.Fatal("historical read rewrote original bytes")
	}
	// Public historical values do not become current edit authority.
	document := AppDocument{Body: f.body, Overrides: []DeliveryOverride{{Path: field.Path, Value: field.Value, Revision: field.Revision, Actor: field.Actor}}}
	if _, err = document.EffectiveInput(scope); err == nil {
		t.Fatal("missing current owner anchors accepted by compile path")
	}
	bad := field
	bad.Path = []string{"x-mydc", "tenant"}
	if _, err = RestoreAppInput(f.body, nil, scope, []AppFieldOverlay{bad}); err == nil {
		t.Fatal("historical field reader expanded to cluster scope")
	}
}
