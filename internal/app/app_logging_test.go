// SPDX-License-Identifier: Apache-2.0

package app

import (
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/workload"
)

func TestFreshTaskEvidenceRequiresTheActualDriverFact(t *testing.T) {
	status := workload.ContainerStatus{NativeID: "original", Running: true, Ready: true, LogDriver: "json-file"}
	stage := deployment.StageRecord{Observation: &deployment.Observation{Native: "original", Applied: true, Healthy: true, At: uint64(time.Now().Unix())}}
	if (&Runtime{}).freshAppTaskObservation(stage, status) {
		t.Fatal("legacy healthy evidence suppressed the new driver observation")
	}
	stage.Observation.LogDriver = "json-file"
	if !(&Runtime{}).freshAppTaskObservation(stage, status) {
		t.Fatal("same current native/driver observation was needlessly refreshed")
	}
	status.LogDriver = "local"
	if (&Runtime{}).freshAppTaskObservation(stage, status) {
		t.Fatal("changed native driver was treated as unchanged evidence")
	}
}
