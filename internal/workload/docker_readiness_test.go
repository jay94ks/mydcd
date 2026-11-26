// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"testing"

	"github.com/moby/moby/api/types/container"
)

func TestContainerProcessReadinessRejectsUnavailableRunningStates(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state *container.State
		ready bool
	}{
		{"missing", nil, false},
		{"exited", &container.State{}, false},
		{"running", &container.State{Running: true}, true},
		{"paused-stale-healthy", &container.State{Running: true, Paused: true}, false},
		{"restarting", &container.State{Running: true, Restarting: true}, false},
		{"dead", &container.State{Running: true, Dead: true}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := containerProcessReady(tc.state); got != tc.ready {
				t.Fatalf("process readiness=%v want %v", got, tc.ready)
			}
		})
	}
}
