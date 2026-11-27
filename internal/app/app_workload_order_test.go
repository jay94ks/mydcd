// SPDX-License-Identifier: Apache-2.0

package app

import (
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
)

func TestAppWorkloadObservationOrder(t *testing.T) {
	work := []appWorkload{
		{step: deployment.Step{Key: "fresh"}, stage: deployment.StageRecord{Observation: &deployment.Observation{Applied: true, At: 20}}},
		{step: deployment.Step{Key: "missing"}},
		{step: deployment.Step{Key: "released"}, stage: deployment.StageRecord{Observation: &deployment.Observation{Applied: true, Released: true, At: 30}}},
		{step: deployment.Step{Key: "failed"}, stage: deployment.StageRecord{Observation: &deployment.Observation{At: 40}}},
		{step: deployment.Step{Key: "old"}, stage: deployment.StageRecord{Observation: &deployment.Observation{Applied: true, At: 10}}},
		{step: deployment.Step{Key: "same"}, stage: deployment.StageRecord{Observation: &deployment.Observation{Applied: true, At: 20}}},
		{step: deployment.Step{Key: "future"}, stage: deployment.StageRecord{Observation: &deployment.Observation{Applied: true, At: 1000}}},
	}
	before := map[string]string{}
	for _, w := range work {
		b, _ := json.Marshal(w.stage)
		before[w.step.Key] = string(b)
	}
	orderAppWorkloads(work)
	want := []string{"missing", "released", "failed", "old", "fresh", "same", "future"}
	for i, w := range work {
		b, _ := json.Marshal(w.stage)
		if w.step.Key != want[i] || string(b) != before[w.step.Key] {
			t.Fatal("polling order changed evidence or tie order", i, w.step.Key)
		}
	}
}

func TestAppWorkloadObservationOrderDoesNotStarveLaterApp(t *testing.T) {
	var work []appWorkload
	for _, app := range []string{"first", "last"} {
		for _, key := range []string{"volume", "task", "inputs"} {
			work = append(work, appWorkload{app: control.AppView{App: app}, step: deployment.Step{Key: app + "/" + key}, stage: deployment.StageRecord{Observation: &deployment.Observation{Applied: true, At: 1}}})
		}
	}
	seen := map[string]bool{}
	// Each report takes longer than the normal refresh interval. A fixed
	// prefix would always refresh its first stage and never reach the suffix.
	for i := range len(work) * 3 {
		orderAppWorkloads(work)
		if i%len(work) == 0 {
			seen = map[string]bool{}
		}
		key := work[0].step.Key
		if seen[key] {
			t.Fatal("successful prefix starved another stage", key)
		}
		seen[key] = true
		work[0].stage.Observation.At = uint64(2 + i*20)
		if i%len(work) == len(work)-1 && len(seen) != len(work) {
			t.Fatal("not every app/stage was observed", seen)
		}
	}
}
