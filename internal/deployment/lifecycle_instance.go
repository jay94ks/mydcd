// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/jay94ks/seafield/internal/engine"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
	contract "github.com/jay94ks/seafield/lifecycle/v1"
)

// TaskRestart carries the node's completed original control receipt. The
// surrounding Observation signature binds it to the same plan/Task/native.
// It authorizes neither arbitrary external restarts nor a new container ID.
type UserRestart struct {
	Operation string
	Request   [32]byte
}

type TaskRestart struct {
	User         *UserRestart `json:",omitempty"`
	Program      [32]byte
	Checker      string
	Status       contract.Status
	Control      checker.ContainerControl
	PreviousExit *engine.ContainerExit `json:",omitempty"`
}

func (p TaskRestart) Clone() TaskRestart {
	if p.User != nil {
		user := *p.User
		p.User = &user
	}
	if p.PreviousExit != nil {
		exit := *p.PreviousExit
		p.PreviousExit = &exit
	}
	return p
}

func instanceStarted(stamp string) (int64, bool) {
	t, err := time.Parse(time.RFC3339Nano, stamp)
	if err != nil || t.IsZero() || t.UnixNano() <= 0 || !time.Unix(0, t.UnixNano()).Equal(t) {
		return 0, false
	}
	return t.UnixNano(), true
}

func restartDigest(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == value && !bytes.Equal(raw, make([]byte, 32))
}

func (e Execution) validTaskInstance(i int, o Observation) bool {
	if o.OwnerBoot != "" && (e.observationStep(i).Kind != "task" || !restartDigest(o.OwnerBoot)) {
		return false
	}
	if o.StartedAt == 0 {
		return o.Restart == nil
	}
	step := e.observationStep(i)
	if step.Kind != "task" || o.StartedAt < 0 || uint64(o.StartedAt/1_000_000_000) > o.At || o.Exit != nil && o.Exit.StartedAt != o.StartedAt {
		return false
	}
	if o.Restart == nil {
		return true
	}
	p := o.Restart
	c := p.Control
	if c.Validate() != nil || c.Phase != checker.ControlCompleted || c.Action != checker.StartContainer && c.Action != checker.RestartContainer {
		return false
	}
	if !restartDigest(c.RunID) || !restartDigest(c.Target.OwnerBoot) {
		return false
	}
	target := c.Target
	var taskService ComposeService
	if json.Unmarshal(step.Goal, &taskService) != nil {
		return false
	}
	instance, identityErr := TaskInstanceForKey(e.d.Plan.Tenant, e.d.Plan.App, o.Key, taskService)
	before, ok := instanceStarted(target.StartedAt)
	if identityErr != nil || instance.Service != target.Service || !ok || before >= o.StartedAt || target.TaskKey != o.Key || target.NativeID != o.Native || target.Generation != o.Generation || target.Revision != o.Revision || target.Owner != hex.EncodeToString(o.Owner[:]) {
		return false
	}
	if p.PreviousExit != nil && (!p.PreviousExit.Valid() || p.PreviousExit.StartedAt != before || p.PreviousExit.FinishedAt > o.StartedAt) {
		return false
	}
	if p.User != nil {
		return p.User.Operation != "" && p.User.Request == c.RequestDigest && p.Program == ([32]byte{}) && p.Checker == "" && p.Status == "" && (c.Action == checker.RestartContainer || taskService.Standalone && c.Action == checker.StartContainer)
	}
	var checks []checker.ResolvedCheck
	var program [32]byte
	if e.d.Stages[i].Held() && taskService.LifecycleProgram != nil {
		program, checks = taskService.LifecycleProgram.Program, taskService.LifecycleProgram.Checks
	} else if e.d.Plan.Checkers != nil {
		program, checks = e.d.Plan.Checkers.Digest(), e.d.Plan.Checkers.Program.Services[target.Service]
	}
	if program == ([32]byte{}) || p.Program != program || p.Status != contract.Pass && p.Status != contract.Fail {
		return false
	}
	for _, check := range checks {
		if check.ID != p.Checker || check.Phase != contract.Liveness || check.Actions == nil {
			continue
		}
		action := check.Actions.OnAlive
		if p.Status == contract.Fail {
			action = check.Actions.OnDead
		}
		return action == c.Action || action == checker.RestartContainer && c.Action == checker.StartContainer
	}
	return false
}

func validInstanceTransition(old, o Observation) bool {
	if old.StartedAt == 0 && o.StartedAt == 0 {
		return old.Restart == nil && o.Restart == nil
	}
	before := old.StartedAt
	if before == 0 && old.Exit != nil {
		before = old.Exit.StartedAt
	}
	if before == 0 {
		return true
	} // first instance metadata for a legacy observation
	if o.StartedAt == before {
		return bytes.Equal(goal(old.Restart), goal(o.Restart))
	}
	if o.Restart == nil || o.StartedAt <= before {
		return false
	}
	stamp, ok := instanceStarted(o.Restart.Control.Target.StartedAt)
	if !ok || stamp != before {
		return false
	}
	previous := o.Restart.PreviousExit
	return old.Exit == nil && previous == nil || old.Exit != nil && previous != nil && *old.Exit == *previous
}

// An exit belongs to one instance. It remains immutable until an authorized
// completed control bridges it to a strictly newer instance of the same native.
// Execution and Inventory consume this same rule, including a new instance
// that has already stopped before its first shared observation is published.
func validExitTransition(old, next Observation) bool {
	if old.Exit == nil || next.Released || next.Exit != nil && *next.Exit == *old.Exit {
		return true
	}
	return next.Restart != nil && next.StartedAt > old.StartedAt && next.Restart.PreviousExit != nil && *next.Restart.PreviousExit == *old.Exit
}
