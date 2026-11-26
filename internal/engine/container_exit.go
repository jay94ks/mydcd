// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"time"

	"github.com/moby/moby/api/types/container"
)

// ContainerExit is a positive process observation, not a writer fence or a
// proof that separately launched execs and all descendants have terminated.
type ContainerExit struct {
	Code                  int
	StartedAt, FinishedAt int64 // Unix nanoseconds of the inspected original
}

func (e ContainerExit) Valid() bool {
	return e.Code >= 0 && e.Code <= 255 && e.StartedAt > 0 && e.FinishedAt >= e.StartedAt
}

// ContainerStartable is a native precondition only, never proof that a prior
// dispatched Start was not executed. Owners still need their original journal.
func ContainerStartable(state *container.State) bool {
	if state == nil || state.Status != container.StateCreated || state.Running || state.Paused || state.Restarting || state.Dead || state.OOMKilled || state.Pid != 0 || state.Error != "" || state.ExitCode != 0 {
		return false
	}
	for _, value := range []string{state.StartedAt, state.FinishedAt} {
		if value == "" {
			continue
		}
		when, err := time.Parse(time.RFC3339Nano, value)
		if err != nil || !when.IsZero() {
			return false
		}
	}
	return true
}

// ObserveContainerExit never turns Running=false or a default exit code into
// an execution receipt. Both Engine timestamps and the exited state are needed.
func ObserveContainerExit(state *container.State) *ContainerExit {
	if state == nil || state.Status != container.StateExited || state.Running || state.Paused || state.Restarting || state.Dead || state.OOMKilled || state.Pid != 0 || state.Error != "" || state.ExitCode < 0 || state.ExitCode > 255 {
		return nil
	}
	started, err := time.Parse(time.RFC3339Nano, state.StartedAt)
	if err != nil || started.IsZero() {
		return nil
	}
	finished, err := time.Parse(time.RFC3339Nano, state.FinishedAt)
	if err != nil || finished.IsZero() || finished.Before(started) {
		return nil
	}
	e := ContainerExit{Code: state.ExitCode, StartedAt: started.UnixNano(), FinishedAt: finished.UnixNano()}
	if !e.Valid() || !time.Unix(0, e.StartedAt).Equal(started) || !time.Unix(0, e.FinishedAt).Equal(finished) {
		return nil
	}
	return &e
}
