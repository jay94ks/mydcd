// SPDX-License-Identifier: Apache-2.0

package control

import (
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

// Interpret the signed target operation without synthesizing a begin-app op.
func appOriginBegin(op UserOperation, scope deployment.AppScope) (AppBegin, error) {
	var begin AppBegin
	switch op.Change.Action {
	case "drain-node":
		return drainAppBegin(op, scope)
	case "begin-app", "standalone-up":
		if canonical(op.Change.Payload, &begin) != nil {
			return begin, ErrCatalog
		}
	case "begin-volume-move":
		var move VolumeMoveBegin
		if canonical(op.Change.Payload, &move) != nil || move.App == nil || move.App.Target == nil || move.Scope.Cluster != scope.Cluster {
			return begin, ErrCatalog
		}
		begin = AppBegin{Tenant: move.Scope.Tenant, App: move.Scope.App, Deployment: scope.Deployment, Upload: move.App.Target.Upload, Operation: move.App.Target.Operation}
	default:
		return begin, ErrCatalog
	}
	if begin.Tenant != scope.Tenant || begin.App != scope.App || begin.Deployment != scope.Deployment {
		return begin, ErrCatalog
	}
	return begin, nil
}

func (p Policy) advanceAppInventory(s state.State, i deployment.Inventory, e deployment.Execution) (deployment.Inventory, error) {
	v, err := p.Volumes(s)
	if err != nil {
		return i, err
	}
	current := map[string]volumes.State{}
	for key, entry := range v.entries {
		current[key] = entry.State
	}
	return i.AdvanceWithVolumes(i.Revision(), e, s, current)
}
