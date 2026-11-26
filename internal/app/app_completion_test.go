// SPDX-License-Identifier: Apache-2.0

package app

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/workload"
)

func TestAppTaskReportsActualRunningOrExitAndSignsOwnedCompletion(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	id := &identity.Identity{Private: key, Public: [32]byte(key.Public().(ed25519.PublicKey))}
	r := &Runtime{Identity: id, controlPolicy: control.Policy{Cluster: [32]byte{1}}}
	app := control.AppView{Operation: deployment.OperationSummary{ID: "operation", Plan: [32]byte{2}}}
	stage := deployment.StageRecord{Key: "workload/task/tenant/app/job", Command: &state.Command{}, Result: &state.Result{Generation: 3, Revision: 7}}
	finished := time.Now().Add(-time.Second).UnixNano()
	exit := engine.ContainerExit{StartedAt: finished - int64(time.Second), FinishedAt: finished}
	for _, status := range []workload.ContainerStatus{
		{NativeID: "original", Running: true},
		{NativeID: "original", Running: true, Ready: true},
		{NativeID: "original"}, // Missing terminal evidence is not Applied.
		{NativeID: "original", Exit: &exit},
	} {
		o, err := r.appTaskObservation(app, stage, status)
		if err != nil || o.Applied != (status.Running || status.Exit != nil) || o.Healthy != status.Ready || !ed25519.Verify(ed25519.PublicKey(id.Public[:]), deployment.ObservationBytes(o), o.Signature) {
			t.Fatal("actual status/signature were not preserved", err)
		}
		stage.Observation = &o
		if !(&Runtime{}).freshAppTaskObservation(stage, status) {
			t.Fatal("same current original observation not reusable")
		}
		if status.Exit != nil {
			status.Exit.Code = 1
			if o.Exit.Code != 0 || (&Runtime{}).freshAppTaskObservation(stage, status) {
				t.Fatal("borrowed native pointer rewrote signed original or hid change")
			}
			status.Exit.Code = 0
		}
	}
	for _, invalid := range []workload.ContainerStatus{
		{NativeID: "original", Running: true, Exit: &exit},
		{NativeID: "original", Ready: true},
		{NativeID: "original", Exit: &engine.ContainerExit{}},
	} {
		if _, err := r.appTaskObservation(app, stage, invalid); err == nil {
			t.Fatal("inconsistent task status accepted")
		}
	}
}
