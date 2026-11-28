// SPDX-License-Identifier: Apache-2.0

package deployment

import "strings"

// HealthReason says, for status only, why an app is not Healthy: the first
// cause Health met, the step and server it is on, and the Task's exit code or
// failure code. It never carries native output or secret text.
type HealthReason struct {
	Code    string
	Key     string `json:",omitempty"`
	Kind    string `json:",omitempty"` // the step kind: task, ingress, volume, ...
	Name    string `json:",omitempty"` // the service or resource name in app.yaml
	Node    string `json:",omitempty"`
	Exit    *int   `json:",omitempty"`
	Failure string `json:",omitempty"` // a Task failure code (task_failure.go)
}

const (
	HealthReplicasPartial  = "REPLICAS_PARTIAL"   // some replicas of a service serve, some do not
	HealthIngressNotReady  = "INGRESS_NOT_READY"  // a listener serves but some backends are not ready
	HealthTaskFailed       = "TASK_FAILED"        // a Task can never start (Failure)
	HealthTaskExited       = "TASK_EXITED"        // a Task exited with a non-zero code (Exit)
	HealthNotRunning       = "NOT_RUNNING"        // the step's native is not applied
	HealthTaskUnhealthy    = "TASK_UNHEALTHY"     // a Task that must be healthy is not
	HealthTaskNotCompleted = "TASK_NOT_COMPLETED" // a Task that must complete has not
	HealthStepPending      = "STEP_PENDING"       // the step has not been applied yet
	HealthStepRejected     = "STEP_REJECTED"      // the step's send was refused
	HealthNotObserved      = "NOT_OBSERVED"       // no live report from the step's server
	HealthAppCheckFailed   = "APP_CHECK_FAILED"
	HealthAppCheckPending  = "APP_CHECK_PENDING"
)

// HealthReasonCodes lists every HealthReason.Code.
var HealthReasonCodes = []string{HealthReplicasPartial, HealthIngressNotReady, HealthTaskFailed, HealthTaskExited, HealthNotRunning, HealthTaskUnhealthy, HealthTaskNotCompleted, HealthStepPending, HealthStepRejected, HealthNotObserved, HealthAppCheckFailed, HealthAppCheckPending}

// observationProblem is the Degraded cause in o, or "". completion also
// checks a Completed step's success (not judged for held replacement facts).
func observationProblem(step Step, o Observation, completion bool) string {
	switch {
	case o.Failure != "":
		return HealthTaskFailed
	case o.Exit != nil && o.Exit.Code != 0:
		return HealthTaskExited
	case !o.Applied:
		return HealthNotRunning
	case step.Completion == Healthy && !o.Healthy:
		return HealthTaskUnhealthy
	case completion && step.Completion == Completed && !successfulCompletion(o):
		return HealthTaskNotCompleted
	}
	return ""
}

func (e Execution) stageReason(code string, i int) *HealthReason {
	step := e.observationStep(i)
	r := &HealthReason{Code: code, Key: step.Key, Kind: step.Kind, Node: step.Node}
	if id, err := ResourceIDFromKey(step.Kind, e.d.Plan.Tenant, e.d.Plan.App, step.Key); err == nil {
		r.Name, _, _ = strings.Cut(id, "/")
	}
	return r
}

func (e Execution) observationReason(code string, i int, o Observation) *HealthReason {
	r := e.stageReason(code, i)
	switch code {
	case HealthTaskFailed:
		r.Failure = o.Failure
	case HealthTaskExited:
		exit := o.Exit.Code
		r.Exit = &exit
	}
	return r
}
