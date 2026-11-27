// SPDX-License-Identifier: Apache-2.0

package app

import (
	"errors"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/reconcile"
)

// Requires latest work's committed withdrawal/no-grant barrier AND the same
// current catalog/Authority in the reusable core. It performs no native I/O.
func (r *Runtime) prepareNeverDispatchedRoute(view cluster.View, projection control.ResourceProjection, work control.RouteWork, record routeOwnerRecord, known bool) (routeOwnerRecord, error) {
	if !work.Retiring || work.Reference.Dispatch != nil || work.Reference.Closed != nil || projection.NetworkAuthority == nil {
		return record, errors.New("never-dispatched retirement has no committed withdrawal barrier")
	}
	catalog, err := r.controlPolicy.Catalog(view.State)
	if err != nil {
		return record, err
	}
	var core services.RouteRuntime
	if known {
		if record.NativeStarted || record.Bridge != (reconcile.Lease{}) || record.Retirement != nil {
			return record, errors.New("original route may already have native work or references")
		}
		core, err = services.DecodeRouteRuntime(record.Core)
		if err != nil {
			return record, err
		}
		core, err = core.RetireNeverDispatched(catalog, projection.Resources.Networks, *projection.NetworkAuthority)
	} else {
		boot, bootErr := services.NativeBootID()
		if bootErr != nil {
			return record, bootErr
		}
		core, err = services.NewUnstartedRouteRetirement(catalog, projection.Resources.Networks, *projection.NetworkAuthority, work.Reference.ID, boot)
		record.Schema = 1
	}
	if err != nil {
		return record, err
	}
	record.Core, err = core.Encode()
	if err != nil {
		return record, err
	}
	// Keep any old private proposal/nonce/unknown metadata submission. The
	// committed barrier prevents that submission from ever granting native work.
	record.NeverDispatched, record.BridgeReturned = true, true
	if err := r.saveRouteOwner(record, work.Reference); err != nil {
		return record, err
	}
	return record, nil
}
