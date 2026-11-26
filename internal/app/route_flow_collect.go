// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/network/services"
	"github.com/jay94ks/mydcd/internal/reconcile"
)

func routeTransportTuple(tuple services.RouteTuple) network.TransportPacket {
	return tuple.Transport()
}

func originalRouteResource(ref services.ReferenceConsumer, record routeOwnerRecord) (reconcile.Resource, error) {
	spec, err := services.RouteTunnelDefinition(ref)
	if err != nil {
		return reconcile.Resource{}, err
	}
	raw, err := json.Marshal(spec)
	if err != nil || sha256.Sum256(raw) != record.Dispatch.NativeSpec {
		return reconcile.Resource{}, errors.New("route flow changed its original native target")
	}
	return reconcile.Resource{Generation: ref.Generation, Present: true, Spec: string(raw)}, nil
}

func (r *Runtime) routeFlowCensus(ctx context.Context, ref services.ReferenceConsumer, record routeOwnerRecord) (map[network.TransportPacket]bool, error) {
	if !record.NativeStarted || record.BridgeReturned || record.NeverDispatched {
		return nil, errors.New("route flow has no original native owner")
	}
	resource, err := originalRouteResource(ref, record)
	if err != nil {
		return nil, err
	}
	return r.nativeRouteDriver().RouteConntrackCensus(ctx, ref.RouteNativeKey(), resource)
}

// Called under routeMu after exact native recovery. A successful COMPLETE
// census is an observation, not a peer closure or permission to return pins.
func (r *Runtime) observeActiveRouteFlows(ctx context.Context, work control.RouteWork, record *routeOwnerRecord, core services.RouteRuntime) (services.RouteRuntime, error) {
	ref := work.Reference
	if !work.PrepareAllowed || ref.Route == nil || ref.Route.Side != ref.Route.Policy.Source.Tenant || core.FlowCount() == 0 {
		return core, nil
	}
	census, err := r.routeFlowCensus(ctx, ref, *record)
	if err != nil {
		return core, err
	}
	candidate, changed, err := core.ObserveConntrack(census)
	if err != nil {
		return core, err
	}
	if changed {
		if err := r.saveRouteCore(record, ref, candidate); err != nil {
			return core, err
		}
	}
	return candidate, nil
}
