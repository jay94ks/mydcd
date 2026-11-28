// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/json"

	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/eventlog"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
)

// DiagnosticTask joins an owner-verified Docker identity to a retained
// committed claim. Its public target is not a container permit or Binding.
func (p Policy) DiagnosticTask(s state.State, key string, generation uint64, owner [32]byte, native string) (eventlog.Target, error) {
	a, err := p.readOnlyApps(s)
	if err != nil {
		return eventlog.Target{}, err
	}
	for _, entry := range a.entries {
		for _, claim := range entry.Inventory.Claims() {
			if claim.Command.Key != key || claim.Result.Generation != generation || claim.Result.Code != state.Applied {
				continue
			}
			var goal deployment.GoalCommand
			if json.Unmarshal([]byte(claim.Command.Value), &goal) != nil || goal.Cluster != p.Cluster || goal.Owner != owner || goal.Kind != "task" {
				continue
			}
			service, err := managedTaskService(claim.Command.Key, goal.Tenant, goal.App)
			if err != nil {
				return eventlog.Target{}, err
			}
			return eventlog.Target{Tenant: goal.Tenant, App: goal.App, Service: service, Deployment: goal.Deployment, Task: key, Native: native, Node: goal.Node, Generation: generation, Revision: claim.Result.Revision}, nil
		}
	}
	return eventlog.Target{}, ErrCatalog
}

func managedTaskService(key, tenant, app string) (string, error) {
	prefix := "workload/task/" + tenant + "/" + app + "/"
	if len(key) <= len(prefix) || key[:len(prefix)] != prefix {
		return "", ErrCatalog
	}
	service := key[len(prefix):]
	if !lifecycle.ValidID(service) {
		return "", ErrCatalog
	}
	return service, nil
}

func (p Policy) DiagnosticTaskReason(s state.State, target eventlog.Target, detail *eventlog.Detail) {
	a, err := p.readOnlyApps(s)
	if err != nil {
		return
	}
	entry, ok := a.entries[appKey(target.Tenant, target.App)]
	if !ok {
		return
	}
	for _, restart := range entry.TaskRestarts {
		t := restart.Plan.Container
		c := restart.Control
		phase := checker.ControlStartSent
		if detail.Reason == "exit" {
			phase = checker.ControlStopSent
		}
		dispatched := c != nil && c.Phase == phase
		if t.NativeID == target.Native && t.Instance == target.Task && t.Generation == target.Generation && dispatched {
			detail.Reason = "user"
			detail.Operation = restart.Origin.RequestID
			detail.Actor = restart.Origin.Session.User
			if restart.Origin.Reason != nil {
				detail.OperatorReason = restart.Origin.Reason.Text
				detail.IncidentID = restart.Origin.Reason.IncidentID
				detail.ApprovedBy = restart.Origin.Reason.ApprovedBy
			}
			return
		}
	}
}
