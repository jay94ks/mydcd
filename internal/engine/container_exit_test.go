// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"testing"

	"github.com/moby/moby/api/types/container"
)

func TestStartableIsOnlyNeverStartedCreatedAndNotAClosureWitness(t *testing.T) {
	created := container.State{Status: container.StateCreated, StartedAt: "0001-01-01T00:00:00Z", FinishedAt: "0001-01-01T00:00:00Z"}
	if !ContainerStartable(&created) || ObserveContainerExit(&created) != nil {
		t.Fatal("never-started state confused with terminal execution")
	}
	for _, change := range []func(*container.State){
		func(s *container.State) { s.Status = container.StateExited },
		func(s *container.State) { s.Status = container.StateDead },
		func(s *container.State) { s.Status = "" },
		func(s *container.State) { s.StartedAt = "2026-11-14T01:00:00Z" },
		func(s *container.State) { s.FinishedAt = "2026-11-14T01:00:00Z" },
		func(s *container.State) { s.StartedAt = "bad timestamp" },
		func(s *container.State) { s.Error = "start error" },
		func(s *container.State) { s.Running = true },
		func(s *container.State) { s.Paused = true },
		func(s *container.State) { s.Restarting = true },
		func(s *container.State) { s.OOMKilled = true },
		func(s *container.State) { s.Pid = 1 },
		func(s *container.State) { s.ExitCode = 1 },
	} {
		changed := created
		change(&changed)
		if ContainerStartable(&changed) {
			t.Fatal("ambiguous/terminal native became a new Start precondition")
		}
	}
	if ContainerStartable(nil) {
		t.Fatal("missing state is not created")
	}
}
