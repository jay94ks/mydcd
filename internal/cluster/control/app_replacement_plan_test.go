// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/deployment"
)

func TestAppDiffReplacementPlanKeepsExactScopeAndSourceCoordinates(t *testing.T) {
	key := deployment.ResourceKey("task", "tenant", "shop", "web/node-a/r1")
	diff := AppDiff{Schema: 1, Tenant: "tenant", App: "shop", Deployment: "deploy", Plan: [32]byte{1},
		Replacement: &deployment.ReplacementPlan{Required: true, Waves: []deployment.ReplacementWave{{Node: "node-a", Tasks: []string{key}, Targets: []deployment.ObjectRef{{Key: key, Generation: 7, Revision: 11}}}}}}
	raw, _ := json.Marshal(diff)
	decoded, err := DecodeAppDiff(raw)
	if err != nil || decoded.Replacement == nil || decoded.Replacement.Waves[0].Targets[0].Generation != 7 {
		t.Fatal("valid immutable stop-set preview rejected", err)
	}
	for _, mutate := range []func(*AppDiff){
		func(d *AppDiff) {
			d.Replacement.Waves[0].Targets[0].Key = deployment.ResourceKey("task", "foreign", "shop", "web/node-a/r1")
		},
		func(d *AppDiff) { d.Replacement.Waves[0].Targets[0].Revision = 6 },
		func(d *AppDiff) { d.Replacement.Waves[0].Targets[0].Generation = 0 },
		func(d *AppDiff) {
			d.Replacement.Waves[0].Tasks = []string{deployment.ResourceKey("task", "tenant", "shop", "other")}
		},
		func(d *AppDiff) { d.Replacement.Waves = append(d.Replacement.Waves, d.Replacement.Waves[0]) },
		func(d *AppDiff) { d.Replacement.Waves[0].Node = "../other" },
		func(d *AppDiff) {
			d.Replacement.BlockedCode = "ROLLING_DEPENDENCY_CONFLICT"
			d.Replacement.Blocker = key
		},
		func(d *AppDiff) { d.Replacement.Required = false },
	} {
		var changed AppDiff
		_ = json.Unmarshal(raw, &changed)
		mutate(&changed)
		bad, _ := json.Marshal(changed)
		if _, err := DecodeAppDiff(bad); err == nil {
			t.Fatal("foreign, invalid, or contradictory replacement preview accepted")
		}
	}
	diff.Replacement = nil
	legacy, _ := json.Marshal(diff)
	if _, err := DecodeAppDiff(legacy); err != nil {
		t.Fatal("singleton/legacy diff now requires replica metadata", err)
	}
}
