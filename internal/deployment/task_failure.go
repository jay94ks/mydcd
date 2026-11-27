// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"errors"
	"fmt"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/workload"
)

// A Task whose committed recipe can never run on its digest-pinned image
// ends its deployment as Failed. Its owner says so with one signed
// observation that carries a Failure code and no native container. Retrying
// cannot help: the goal and the image are both fixed for this operation, and
// each retry would read the image source again.
const (
	FailureProcessUser    = "PROCESS_USER"
	FailureProcessInvalid = "PROCESS_INVALID"
)

// PreparationFailure names a permanent Task preparation error, or "" for an
// error that a later pass may not meet (an unreachable source, a missing
// permit, a cancelled context).
func PreparationFailure(err error) string {
	switch {
	case errors.Is(err, workload.ErrProcessUser):
		return FailureProcessUser
	case errors.Is(err, workload.ErrProcess):
		return FailureProcessInvalid
	}
	return ""
}

func failureText(code string) string {
	switch code {
	case FailureProcessUser:
		return "the image runs as root or a named user; set the service's user: to a non-zero UID:GID"
	case FailureProcessInvalid:
		return "the image's execution configuration is invalid or unsupported"
	}
	return ""
}

// validFailureObservation is the only shape a Failure fact takes: a Task
// stage of this operation, no container, nothing applied or held.
func (e Execution) validFailureObservation(i int, o Observation) bool {
	if o.Failure == "" {
		return true
	}
	s := e.d.Stages[i]
	return failureText(o.Failure) != "" && e.d.Plan.Steps[i].Kind == "task" && !s.Held() && o.Native == NeverObservedNative && !o.Applied && !o.Healthy && !o.Released && !o.Stopped && !o.Gone && !o.Retained && o.Pins == 0 && o.Exit == nil && o.TaskFact == nil && o.LogDriver == "" && o.AppChecks == nil && o.Restart == nil && o.StartedAt == 0 && len(o.IngressBackends) == 0 && len(o.IngressDrained) == 0
}

// validFailureTransition keeps a Failure final: after it the owner may only
// repeat it or, on stop, report the Task released.
func validFailureTransition(old, o Observation) bool {
	if old.Failure != "" {
		return o.Released || o.Failure == old.Failure
	}
	return o.Failure == ""
}

func stageFailed(s StageRecord) bool {
	return s.Result != nil && s.Result.Code != state.Applied || s.Observation != nil && s.Observation.Failure != ""
}

func (e Execution) failed() bool {
	for _, s := range e.d.Stages {
		if stageFailed(s) {
			return true
		}
	}
	return false
}

// Failures says, for status only, which Tasks could not start and why.
func (e Execution) Failures(limit int) []string {
	var out []string
	for i, s := range e.d.Stages {
		if s.Observation == nil || s.Observation.Failure == "" {
			continue
		}
		if len(out) == limit {
			return append(out, "...")
		}
		step := e.d.Plan.Steps[i]
		out = append(out, fmt.Sprintf("%s on %s cannot start: %s", step.Key, step.Node, failureText(s.Observation.Failure)))
	}
	return out
}
