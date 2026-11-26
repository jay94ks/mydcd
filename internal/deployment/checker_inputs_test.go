// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"encoding/json"
	"testing"

	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
)

func TestCheckerAcceptedSelectionBindsTaskRecipeAndPreservesLegacyNilBytes(t *testing.T) {
	f := makeFixture(t)
	n := f.web()
	raw, err := json.Marshal(n)
	if err != nil {
		t.Fatal(err)
	}
	var old map[string]json.RawMessage
	if err := json.Unmarshal(raw, &old); err != nil {
		t.Fatal(err)
	}
	if _, present := old["Lifecycle"]; present {
		t.Fatal("legacy recipe acquired lifecycle bytes")
	}
	selection := checker.Selection{PolicyRevision: 1, Scripts: []checker.NamedReference{{Name: "ready", Revision: 1}}}
	n.Lifecycle = &selection
	owned := ownNeeds(n)
	selection.Scripts[0].Name = "changed"
	if owned.Lifecycle.Scripts[0].Name != "ready" || !validNeeds(owned) {
		t.Fatal("mutable or invalid accepted selection")
	}
	svc := ComposeService{LifecycleSources: owned.Lifecycle}
	if svc.CheckLifecycleNeeds(owned) == nil {
		t.Fatal("selection without its frozen Task program accepted")
	}
	changed := ownNeeds(owned)
	changed.Lifecycle.PolicyRevision++
	if svc.CheckLifecycleNeeds(changed) == nil || svc.CheckLifecycleNeeds(f.web()) == nil {
		t.Fatal("Task accepted different/missing input selection")
	}
}
